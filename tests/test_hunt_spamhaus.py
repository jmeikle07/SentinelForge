"""W3: Spamhaus DROP refresh is atomic, validated, locked, and never turns a bad list into
a cached 'not in DROP'."""
import ipaddress
import os
import threading
import time

import pytest
import responses

import sf_hunt


def drop_text(n=60, start=20):
    lines = ["; Spamhaus DROP List 2026/01/01 - (c) 2026 The Spamhaus Project SLU",
             "; https://www.spamhaus.org/drop/drop.txt"]
    lines += [f"{start + i // 250}.{i % 250}.0.0/16 ; SBL{100000 + i}" for i in range(n)]
    return "\n".join(lines) + "\n"


@pytest.fixture
def drop(tmp_path, monkeypatch):
    f = tmp_path / "spamhaus_drop.txt"
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "SPAMHAUS_DROP_CACHE", f)
    monkeypatch.setattr(sf_hunt, "_spamhaus_parsed_ranges", None)
    monkeypatch.setattr(sf_hunt, "_spamhaus_loaded_from", None)
    monkeypatch.setattr(sf_hunt, "_spamhaus_next_attempt", 0.0, raising=False)
    return f


def _age(path, seconds):
    t = time.time() - seconds
    os.utime(path, (t, t))


DAY = 24 * 3600


# ── parser ───────────────────────────────────────────────────────────────────
def test_parser_accepts_a_real_looking_list():
    ranges = sf_hunt.parse_drop_list(drop_text(60))
    assert len(ranges) == 60
    assert ranges[0] == (ipaddress.ip_network("20.0.0.0/16"), "SBL100000")


@pytest.mark.parametrize("body", [
    "", "   \n", "; only comments\n; nothing else\n",
    "<html><body>Rate limited</body></html>",
    "Too Many Requests\n",
    drop_text(5),                                                  # too few ranges to be the real list
    drop_text(60) + "this is not a drop line\n",                   # garbage mixed in
    drop_text(60) + "1.2.3.0/99 ; SBL1\n",                         # impossible prefix
    drop_text(60) + "1.2.3.0/16 ; nonsense\n",                     # no SBL id
])
def test_parser_rejects_empty_garbage_and_implausible_bodies(body):
    assert sf_hunt.parse_drop_list(body) is None


# ── refresh ──────────────────────────────────────────────────────────────────
@responses.activate
def test_refresh_downloads_validates_and_writes_atomically(drop, monkeypatch):
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=drop_text(60))
    replaced = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (replaced.append((str(a), str(b))), real(a, b))[1])
    assert sf_hunt._spamhaus_drop_refresh_if_stale() is True
    assert drop.read_text(encoding="utf-8") == drop_text(60)
    assert len(replaced) == 1 and replaced[0][1] == str(drop) and replaced[0][0] != str(drop)
    assert [p.name for p in drop.parent.iterdir()] == [drop.name]        # no temp file left behind


@responses.activate
def test_failed_write_leaves_the_previous_good_list_untouched(drop, monkeypatch):
    drop.write_text(drop_text(60), encoding="utf-8")
    _age(drop, 2 * DAY)
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=drop_text(80))

    def broken(a, b):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken)
    sf_hunt._spamhaus_drop_refresh_if_stale()
    assert drop.read_text(encoding="utf-8") == drop_text(60)
    assert [p.name for p in drop.parent.iterdir()] == [drop.name]        # temp cleaned up


@responses.activate
@pytest.mark.parametrize("bad", ["", "<html>captcha</html>", "garbage\n" * 100, drop_text(3)])
def test_bad_200_body_never_replaces_a_good_list(drop, bad):
    drop.write_text(drop_text(60), encoding="utf-8")
    _age(drop, 2 * DAY)
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=bad)
    sf_hunt._spamhaus_drop_refresh_if_stale()
    assert drop.read_text(encoding="utf-8") == drop_text(60)


@responses.activate
def test_bad_body_with_no_existing_list_writes_nothing(drop):
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body="<html>nope</html>")
    assert sf_hunt._spamhaus_drop_refresh_if_stale() is False
    assert not drop.exists()


@responses.activate
def test_a_list_that_shrinks_drastically_is_treated_as_truncated(drop):
    drop.write_text(drop_text(200), encoding="utf-8")
    _age(drop, 2 * DAY)
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=drop_text(30))          # valid shape, but 15% of before
    sf_hunt._spamhaus_drop_refresh_if_stale()
    assert drop.read_text(encoding="utf-8") == drop_text(200)


@responses.activate
def test_content_length_mismatch_is_rejected(drop):
    body = drop_text(60)
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=body,
                  headers={"Content-Length": str(len(body) + 500)})
    sf_hunt._spamhaus_drop_refresh_if_stale()
    assert not drop.exists()


@responses.activate
def test_concurrent_callers_trigger_exactly_one_download(drop):
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=drop_text(60))
    results, barrier = [], threading.Barrier(8)

    def work():
        barrier.wait()
        results.append(sf_hunt._spamhaus_drop_refresh_if_stale())

    ts = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results == [True] * 8
    assert len(responses.calls) == 1


@responses.activate
def test_failed_refresh_is_not_retried_on_every_call(drop):
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, status=503)
    sf_hunt._spamhaus_drop_refresh_if_stale()
    sf_hunt._spamhaus_drop_refresh_if_stale()
    assert len(responses.calls) == 1                     # Spamhaus asks for at most one fetch a day


@responses.activate
def test_recent_but_corrupt_file_is_redownloaded_not_trusted_for_24h(drop, conn):
    drop.write_text(drop_text(60)[:-9], encoding="utf-8")                     # fresh mtime, cut-off content
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=drop_text(60))
    res = sf_hunt.spamhaus_drop_check_ip(conn, "20.5.1.1")
    assert res["available"] is True and res["in_drop"] is True
    assert drop.read_text(encoding="utf-8") == drop_text(60)


# ── lookup ───────────────────────────────────────────────────────────────────
@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "m.db")
    c = sf_hunt.memory_init()
    yield c
    c.close()


@responses.activate
def test_hit_and_miss_with_a_fresh_list(drop, conn):
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, body=drop_text(60))
    hit = sf_hunt.spamhaus_drop_check_ip(conn, "20.5.1.1")
    assert hit["in_drop"] is True and hit["sbl"] == "SBL100005" and hit["range"] == "20.5.0.0/16"
    miss = sf_hunt.spamhaus_drop_check_ip(conn, "8.8.8.8")
    assert miss["available"] is True and miss["in_drop"] is False
    assert sf_hunt.cache_get(conn, "8.8.8.8", "spamhaus_drop") is not None   # fresh list: miss is cached


@responses.activate
def test_truncated_list_on_disk_is_unavailable_and_nothing_is_cached(drop, conn):
    """A crash under the old non-atomic writer left a cut-off file: it must not answer 'not in DROP'."""
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, status=503)
    drop.write_text(drop_text(60)[:-9], encoding="utf-8")                     # last line cut mid-way
    res = sf_hunt.spamhaus_drop_check_ip(conn, "8.8.8.8")
    assert res["available"] is False
    assert sf_hunt.cache_get(conn, "8.8.8.8", "spamhaus_drop") is None


@responses.activate
def test_garbage_file_on_disk_is_unavailable(drop, conn):
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, status=503)
    drop.write_text("<html>oops</html>", encoding="utf-8")
    assert sf_hunt.spamhaus_drop_check_ip(conn, "8.8.8.8")["available"] is False


@responses.activate
def test_stale_list_after_failed_refresh_answers_but_does_not_cache_a_miss(drop, conn):
    drop.write_text(drop_text(60), encoding="utf-8")
    _age(drop, 3 * DAY)
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, status=503)
    miss = sf_hunt.spamhaus_drop_check_ip(conn, "8.8.8.8")
    assert miss["available"] is True and miss["in_drop"] is False
    assert sf_hunt.cache_get(conn, "8.8.8.8", "spamhaus_drop") is None       # not pinned for 24h
    hit = sf_hunt.spamhaus_drop_check_ip(conn, "20.5.1.1")
    assert hit["in_drop"] is True
    assert sf_hunt.cache_get(conn, "20.5.1.1", "spamhaus_drop") is not None   # a hit is still a hit


@responses.activate
def test_list_older_than_the_max_stale_age_is_not_trusted(drop, conn):
    drop.write_text(drop_text(60), encoding="utf-8")
    _age(drop, 30 * DAY)
    responses.get(sf_hunt.SPAMHAUS_DROP_URL, status=503)
    assert sf_hunt.spamhaus_drop_check_ip(conn, "8.8.8.8")["available"] is False


def test_reparse_when_file_is_replaced_even_within_same_mtime(drop):
    drop.write_text(drop_text(60), encoding="utf-8")
    first = sf_hunt._spamhaus_drop_load()
    st = drop.stat()
    drop.write_text(drop_text(70), encoding="utf-8")
    os.utime(drop, ns=(st.st_atime_ns, st.st_mtime_ns))                       # identical mtime
    assert len(sf_hunt._spamhaus_drop_load()) == 70 and len(first) == 60
