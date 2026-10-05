"""Elasticsearch helpers."""
from __future__ import annotations

from typing import Iterator, Optional

import requests

from lab import config


class SearchError(RuntimeError):
    """Elasticsearch was unreachable or returned an error."""


def search_all(session: requests.Session, index: str, body: dict, page_size: int = 500,
               *, base_url: Optional[str] = None, api_key: Optional[str] = None) -> Iterator[dict]:
    """Yield every hit for `body`, paging with search_after (no truncation)."""
    if base_url is None:
        settings = config.load()
        base_url = settings.elastic_url
        if api_key is None:
            api_key = settings.elastic_api_key
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    query = dict(body)
    query["size"] = page_size
    query.setdefault("sort", [{"@timestamp": "asc"}, {"_doc": "asc"}])
    url = f"{base_url.rstrip('/')}/{index}/_search"

    while True:
        try:
            resp = session.post(url, json=query, headers=headers)
            resp.raise_for_status()
            hits = resp.json()["hits"]["hits"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise SearchError(f"search on {index} failed: {exc}") from exc
        yield from hits
        if len(hits) < page_size:
            return
        query["search_after"] = hits[-1]["sort"]
