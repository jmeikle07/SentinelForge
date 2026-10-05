"""Elasticsearch helpers."""
from __future__ import annotations

import logging
from typing import Iterator, Optional

import requests

from lab import config


class SearchError(RuntimeError):
    """Elasticsearch was unreachable or returned an error."""


_log = logging.getLogger(__name__)

PIT_KEEP_ALIVE = "1m"
_TIEBREAKERS = ("_doc", "_shard_doc")


def _sort_field(entry) -> Optional[str]:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and entry:
        return next(iter(entry))
    return None


def _build_sort(sort, tiebreaker: str) -> list:
    """Caller's sort (default @timestamp asc) with any _doc/_shard_doc replaced by `tiebreaker` at the end."""
    base = list(sort) if sort else [{"@timestamp": "asc"}]
    base = [e for e in base if _sort_field(e) not in _TIEBREAKERS]
    return base + [{tiebreaker: "asc"}]


def _open_pit(session, base: str, index: str, headers: dict) -> Optional[str]:
    """Open a point in time; None (never an exception) when it is unavailable."""
    try:
        resp = session.post(f"{base}/{index}/_pit", params={"keep_alive": PIT_KEEP_ALIVE}, headers=headers)
        resp.raise_for_status()
        pit_id = resp.json()["id"]
        return pit_id if isinstance(pit_id, str) and pit_id else None
    except (requests.RequestException, KeyError, ValueError, TypeError) as exc:
        _log.warning("could not open a point in time on %s (%s); falling back to plain search_after "
                     "paging: completeness is NOT guaranteed if the index changes or events share a timestamp",
                     index, exc)
        return None


def _close_pit(session, base: str, pit_id: str, headers: dict) -> None:
    """Best-effort DELETE /_pit. Never raises."""
    try:
        session.delete(f"{base}/_pit", json={"id": pit_id}, headers=headers)
    except Exception as exc:  # noqa: BLE001 - cleanup must never mask the real outcome
        _log.warning("could not close point in time: %s", exc)


def search_all(session: requests.Session, index: str, body: dict, page_size: int = 500,
               *, base_url: Optional[str] = None, api_key: Optional[str] = None) -> Iterator[dict]:
    """Yield every hit for `body`, paging with search_after (no truncation).

    Preferred mode: open a point in time (POST /<index>/_pit), page with
    ``pit`` + ``search_after`` and the explicit unique tiebreaker ``_shard_doc``
    (the caller's sort is honoured; ``_shard_doc`` is appended), refresh the pit id
    from every response, and always DELETE /_pit when finished (close failures are
    swallowed). This gives a consistent snapshot: each event is returned exactly once.

    Fallback: if the PIT cannot be opened (missing privilege, old/unsupported
    version, ...) a warning is logged and paging uses plain search_after with a
    ``_doc`` tiebreaker. ``_doc`` is a per-shard order, so in this mode completeness is
    NOT guaranteed (events may be skipped/repeated across shards or concurrent writes).

    Raises SearchError on any HTTP/parse error, including mid-pagination and a page
    whose last hit has no ``sort``; a partial result is never returned as complete
    (the iterator ends normally only when the result set is exhausted).

    Assumed from Elastic docs (not verifiable offline): PIT needs ES >= 7.10 and the
    ``read`` index privilege; ``_shard_doc`` sort needs ES >= 7.12 and a PIT; a search
    with ``pit`` must not name an index in the URL.
    """
    base, headers = _auth(base_url, api_key)
    pit_id = _open_pit(session, base, index, headers)
    try:
        query = dict(body)
        query["size"] = page_size
        if pit_id is not None:
            query["sort"] = _build_sort(query.get("sort"), "_shard_doc")
            url = f"{base}/_search"
        else:
            query["sort"] = _build_sort(query.get("sort"), "_doc")
            url = f"{base}/{index}/_search"

        while True:
            if pit_id is not None:
                query["pit"] = {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE}
            try:
                resp = session.post(url, json=query, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                hits = data["hits"]["hits"]
                if not isinstance(hits, list):
                    raise TypeError("hits is not a list")
                if pit_id is not None and data.get("pit_id"):
                    pit_id = data["pit_id"]
            except (requests.RequestException, KeyError, ValueError, TypeError, AttributeError) as exc:
                raise SearchError(f"search on {index} failed: {exc}") from exc
            yield from hits
            if not hits or len(hits) < page_size:
                return
            last_sort = hits[-1].get("sort") if isinstance(hits[-1], dict) else None
            if not isinstance(last_sort, list) or not last_sort:
                raise SearchError(f"search on {index} failed: page ended with a hit lacking 'sort'; "
                                  "cannot continue paging")
            query["search_after"] = last_sort
    finally:
        if pit_id is not None:
            _close_pit(session, base, pit_id, headers)


def search_all_capped(session: requests.Session, index: str, body: dict, max_events: int,
                      page_size: int = 500, *, base_url: Optional[str] = None,
                      api_key: Optional[str] = None) -> tuple[list, bool]:
    """Collect at most `max_events` hits. Returns (hits, truncated); truncated is True when
    more hits existed than were returned. Raises SearchError like search_all."""
    gen = search_all(session, index, body, min(page_size, max(1, max_events + 1)),
                     base_url=base_url, api_key=api_key)
    out: list = []
    try:
        for hit in gen:
            if len(out) >= max_events:
                return out, True
            out.append(hit)
        return out, False
    finally:
        gen.close()  # runs the PIT close immediately


def _auth(base_url: Optional[str], api_key: Optional[str]) -> tuple[str, dict]:
    if base_url is None:
        settings = config.load()
        base_url = settings.elastic_url
        if api_key is None:
            api_key = settings.elastic_api_key
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return base_url.rstrip("/"), headers


def backtest_body(lucene: str, days: int = 7) -> dict:
    """Count body for a Lucene query restricted to the last `days` days."""
    return {"query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": f"now-{int(days)}d"}}},
        {"query_string": {"query": lucene, "analyze_wildcard": True}},
    ]}}}


def backtest_count(session: requests.Session, lucene: str, days: int = 7, index: str = "logs-*",
                   *, base_url: Optional[str] = None, api_key: Optional[str] = None) -> int:
    """Number of events in the last `days` days matching `lucene`. Raises SearchError on any failure."""
    base, headers = _auth(base_url, api_key)
    try:
        resp = session.post(f"{base}/{index}/_count", json=backtest_body(lucene, days), headers=headers)
        resp.raise_for_status()
        return int(resp.json()["count"])
    except (requests.RequestException, KeyError, ValueError, TypeError) as exc:
        raise SearchError(f"backtest count on {index} failed: {exc}") from exc


def search(session: requests.Session, index: str, body: dict,
           *, base_url: Optional[str] = None, api_key: Optional[str] = None) -> dict:
    """Single _search call returning the parsed response. Raises SearchError on any failure."""
    base, headers = _auth(base_url, api_key)
    try:
        resp = session.post(f"{base}/{index}/_search", json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        raise SearchError(f"search on {index} failed: {exc}") from exc
