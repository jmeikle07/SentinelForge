import json

import pytest
import responses

from lab import es, http

BASE = "https://es.example.test:9200"


@responses.activate
def test_search_all_pages_past_one_page():
    total = 1250
    calls = []

    def cb(request):
        body = json.loads(request.body)
        calls.append(body)
        size = body["size"]
        after = body.get("search_after")
        start = after[0] + 1 if after else 0
        ids = range(start, min(start + size, total))
        hits = [{"_id": str(i), "_source": {"n": i}, "sort": [i]} for i in ids]
        return 200, {}, json.dumps({"hits": {"hits": hits}})

    responses.add_callback(responses.POST, f"{BASE}/idx/_search", callback=cb,
                           content_type="application/json")
    got = list(es.search_all(http.session(), "idx", {"query": {"match_all": {}}},
                             page_size=500, base_url=BASE))
    assert len(got) == total
    assert [h["_source"]["n"] for h in got] == list(range(total))
    assert len(calls) == 3  # 500 + 500 + 250
    assert all("sort" in c for c in calls)


@responses.activate
def test_search_all_raises_on_server_error():
    responses.add(responses.POST, f"{BASE}/idx/_search", status=500)
    with pytest.raises(es.SearchError):
        list(es.search_all(http.session(retries=0), "idx", {"query": {}}, base_url=BASE))
