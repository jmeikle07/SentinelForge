"""PIT + search_after paging in lab.es (Elastic behaviour simulated with `responses`)."""
import json
import logging

import pytest
import requests
import responses

from lab import es, http

BASE = "https://es.example.test:9200"


class FakeES:
    """Dataset with heavy duplicate @timestamp; honours pit/search_after on the sort tuple."""

    def __init__(self, total=1250, fail_page=None, rotate_pit=True, drop_sort_on=None):
        self.total = total
        self.events = []  # call log: (method, path, body)
        self.fail_page = fail_page
        self.rotate = rotate_pit
        self.drop_sort_on = drop_sort_on
        self.searches = 0
        self.pit_n = 0

    def _rows(self):
        # ts shared by 10 consecutive docs; unique shard_doc tiebreaker = i
        return [(i // 10, i) for i in range(self.total)]

    def install(self, pit_status=200, delete_status=200, delete_exc=None):
        def pit(request):
            self.events.append(("POST", request.path_url, None))
            if pit_status != 200:
                return pit_status, {}, "{}"
            self.pit_n += 1
            return 200, {}, json.dumps({"id": "pit0"})

        def search(request):
            body = json.loads(request.body)
            self.events.append(("POST", request.path_url, body))
            self.searches += 1
            if self.fail_page == self.searches:
                return 500, {}, "{}"
            after = body.get("search_after")
            rows = [r for r in self._rows() if after is None or list(r) > list(after)]
            page = rows[: body["size"]]
            hits = [{"_id": str(i), "_source": {"n": i}, "sort": [ts, i]} for ts, i in page]
            if self.drop_sort_on == self.searches:
                hits[-1].pop("sort")
            out = {"hits": {"hits": hits}}
            if self.rotate:
                out["pit_id"] = f"pit{self.searches}"
            return 200, {}, json.dumps(out)

        def delete(request):
            self.events.append(("DELETE", request.path_url, json.loads(request.body)))
            if delete_exc:
                raise delete_exc
            return delete_status, {}, "{}"

        responses.add_callback(responses.POST, f"{BASE}/idx/_pit", callback=pit)
        responses.add_callback(responses.POST, f"{BASE}/_search", callback=search)
        responses.add_callback(responses.POST, f"{BASE}/idx/_search", callback=search)
        responses.add_callback(responses.DELETE, f"{BASE}/_pit", callback=delete)
        return self


def _run(**kw):
    return list(es.search_all(http.session(retries=0), "idx", {"query": {"match_all": {}}},
                              page_size=500, base_url=BASE, **kw))


@responses.activate
def test_pit_call_order_bodies_and_close():
    fake = FakeES(total=600).install()
    got = _run()
    assert len(got) == 600
    kinds = [(m, p.split("?")[0]) for m, p, _ in fake.events]
    assert kinds == [("POST", "/idx/_pit"), ("POST", "/_search"), ("POST", "/_search"), ("DELETE", "/_pit")]
    assert fake.events[0][1].endswith("keep_alive=1m")
    first, second = fake.events[1][2], fake.events[2][2]
    assert first["sort"] == [{"@timestamp": "asc"}, {"_shard_doc": "asc"}]
    assert first["pit"] == {"id": "pit0", "keep_alive": "1m"} and "search_after" not in first
    # pit id refreshed from page 1's response
    assert second["pit"]["id"] == "pit1" and second["search_after"] == [49, 499]
    assert fake.events[-1][2] == {"id": "pit2"}  # latest id is the one closed


@responses.activate
def test_duplicate_timestamps_exactly_once():
    FakeES(total=1250).install()
    ids = [h["_source"]["n"] for h in _run()]
    assert ids == list(range(1250))


@responses.activate
def test_hit_without_sort_raises_search_error_and_closes_pit():
    fake = FakeES(total=1250, drop_sort_on=1).install()
    with pytest.raises(es.SearchError, match="sort"):
        _run()
    assert fake.events[-1][0] == "DELETE"


@responses.activate
def test_http_error_on_page_two_raises_and_closes_pit():
    fake = FakeES(total=1250, fail_page=2).install()
    got = []
    with pytest.raises(es.SearchError):
        for h in es.search_all(http.session(retries=0), "idx", {}, page_size=500, base_url=BASE):
            got.append(h)
    assert len(got) == 500  # the first page was delivered, but the end was an error, not a clean stop
    assert fake.events[-1][0] == "DELETE"


@responses.activate
def test_pit_open_403_falls_back_with_warning(caplog):
    fake = FakeES(total=700).install(pit_status=403)
    with caplog.at_level(logging.WARNING, logger="lab.es"):
        got = _run()
    assert [h["_source"]["n"] for h in got] == list(range(700))
    assert any("NOT guaranteed" in r.message for r in caplog.records)
    searches = [b for m, p, b in fake.events if p.endswith("/idx/_search")]
    assert searches and "pit" not in searches[0]
    assert searches[0]["sort"] == [{"@timestamp": "asc"}, {"_doc": "asc"}]
    assert not any(m == "DELETE" for m, _, _ in fake.events)


@responses.activate
def test_close_failure_is_swallowed():
    FakeES(total=10).install(delete_exc=requests.ConnectionError("boom"))
    assert len(_run()) == 10
    responses.reset()
    FakeES(total=10).install(delete_status=500)
    assert len(_run()) == 10


@responses.activate
def test_close_failure_does_not_mask_search_error():
    FakeES(total=1250, fail_page=1).install(delete_exc=requests.ConnectionError("boom"))
    with pytest.raises(es.SearchError, match="search on idx failed"):
        _run()


@responses.activate
def test_caller_sort_gets_shard_doc_tiebreaker():
    fake = FakeES(total=5).install()
    list(es.search_all(http.session(retries=0), "idx",
                       {"sort": [{"@timestamp": {"order": "desc"}}, {"_doc": "asc"}]}, base_url=BASE))
    assert fake.events[1][2]["sort"] == [{"@timestamp": {"order": "desc"}}, {"_shard_doc": "asc"}]


@responses.activate
def test_capped_reports_truncation():
    fake = FakeES(total=1250).install()
    got, truncated = es.search_all_capped(http.session(retries=0), "idx", {}, 1000, base_url=BASE)
    assert len(got) == 1000 and truncated is True
    assert fake.events[-1][0] == "DELETE"
    responses.reset()
    FakeES(total=1000).install()
    got, truncated = es.search_all_capped(http.session(retries=0), "idx", {}, 1000, base_url=BASE)
    assert len(got) == 1000 and truncated is False
    responses.reset()
    FakeES(total=3).install()
    got, truncated = es.search_all_capped(http.session(retries=0), "idx", {}, 1000, base_url=BASE)
    assert len(got) == 3 and truncated is False
