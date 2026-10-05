"""W2: --fresh bypasses cache reads. W6: web lookups are cached in memory only, never on disk."""
import sqlite3

import pytest
import responses

import sf_hunt

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"


@pytest.fixture
def paths(tmp_path, monkeypatch):
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "m.db")
    monkeypatch.setattr(sf_hunt, "elk_index_doc", lambda *a, **k: False)
    monkeypatch.setattr(sf_hunt, "OTX_API_KEY", "k")
    monkeypatch.setattr(sf_hunt, "_EPHEMERAL_CONN", None)   # each test gets its own in-memory cache
    return tmp_path


def _seed_cached_otx():
    conn = sf_hunt.memory_init()
    sf_hunt.cache_put(conn, "example.com", "otx",
                      {"available": True, "pulse_count": 1, "top_pulses": ["cached"], "_cached": False})
    conn.close()


def _otx_live():
    responses.get(OTX_URL, json={"pulse_info": {"count": 7, "pulses": [{"name": "live"}]}})


@responses.activate
def test_default_hunt_serves_enrichment_from_cache(paths):
    _seed_cached_otx()
    _otx_live()
    assert sf_hunt.hunt("example.com") == 0
    assert len(responses.calls) == 0


@responses.activate
def test_fresh_hunt_bypasses_cache_reads_and_refreshes_the_entry(paths):
    _seed_cached_otx()
    _otx_live()
    assert sf_hunt.hunt("example.com", fresh=True) == 0
    assert len(responses.calls) == 1                      # went to the network despite a warm cache
    conn = sf_hunt.memory_init()
    assert sf_hunt.cache_get(conn, "example.com", "otx")["pulse_count"] == 7   # cache refreshed
    conn.close()


def test_fresh_connection_never_reads_cache_but_still_writes(paths):
    conn = sf_hunt.memory_init(bypass_cache_reads=True)
    sf_hunt.cache_put(conn, "1.1.1.1", "otx", {"x": 1})
    assert sf_hunt.cache_get(conn, "1.1.1.1", "otx") is None
    plain = sf_hunt.memory_init()
    assert sf_hunt.cache_get(plain, "1.1.1.1", "otx") == {"x": 1}
    conn.close()
    plain.close()


def test_cache_get_is_the_only_cache_reader():
    """--fresh works by cache_get returning None, so nothing may read the cache another way."""
    import inspect
    src = inspect.getsource(sf_hunt)
    assert src.count("SELECT timestamp_utc, response_json FROM enrichment_cache") == 1


def test_fresh_help_text_matches_behaviour():
    import io
    import contextlib
    import sys
    parser_help = io.StringIO()
    old = sys.argv
    sys.argv = ["sf_hunt", "--help"]
    try:
        with contextlib.redirect_stdout(parser_help), pytest.raises(SystemExit):
            sf_hunt.main()
    finally:
        sys.argv = old
    assert "cache" in parser_help.getvalue().lower()


# ── W6 ───────────────────────────────────────────────────────────────────────
def test_ephemeral_memory_cache_roundtrips_and_touches_no_disk(paths):
    conn = sf_hunt.memory_init_ephemeral()
    sf_hunt.cache_put(conn, "8.8.8.8", "otx", {"available": True})
    assert sf_hunt.cache_get(conn, "8.8.8.8", "otx") == {"available": True}
    assert not (paths / "m.db").exists()
    assert list(paths.iterdir()) == []


def test_ephemeral_cache_is_shared_so_repeat_lookups_hit_it(paths):
    a = sf_hunt.memory_init_ephemeral()
    sf_hunt.cache_put(a, "8.8.8.8", "otx", {"n": 1})
    assert sf_hunt.cache_get(sf_hunt.memory_init_ephemeral(), "8.8.8.8", "otx") == {"n": 1}


def test_ephemeral_cache_is_bounded_and_drops_expired_rows(paths, monkeypatch):
    monkeypatch.setattr(sf_hunt, "EPHEMERAL_CACHE_MAX_ROWS", 5)
    conn = sf_hunt.memory_init_ephemeral()
    conn.execute("DELETE FROM enrichment_cache")
    conn.execute("INSERT INTO enrichment_cache VALUES ('old','otx','2000-01-01T00:00:00+00:00','{}',200)")
    conn.commit()
    for i in range(12):
        sf_hunt.cache_put(conn, f"9.9.9.{i}", "otx", {"i": i})
    sf_hunt.cache_prune(conn)
    rows = conn.execute("SELECT ioc FROM enrichment_cache").fetchall()
    assert len(rows) <= 5
    assert ("old",) not in [tuple(r) for r in rows]
    assert "9.9.9.11" in [r[0] for r in rows]             # newest survive


def test_memory_init_ephemeral_is_not_the_disk_db(paths):
    conn = sf_hunt.memory_init_ephemeral()
    assert isinstance(conn, sqlite3.Connection)
    assert conn.execute("PRAGMA database_list").fetchall()[0][2] in ("", None)   # in-memory: no file
