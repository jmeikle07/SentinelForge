"""The one place HTTP sessions are built: default timeout, retries, TLS on by default."""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lab.config import insecure_tls_requested

RETRY_STATUSES = (429, 502, 503, 504)


class _TimeoutSession(requests.Session):
    def __init__(self, timeout: float):
        super().__init__()
        self._default_timeout = timeout

    def request(self, method, url, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self._default_timeout
        return super().request(method, url, **kwargs)


def session(retries: int = 3, timeout: float = 10.0, *, backoff_factor: float = 0.5) -> requests.Session:
    s = _TimeoutSession(timeout)
    retry = Retry(
        total=retries,
        status_forcelist=RETRY_STATUSES,
        backoff_factor=backoff_factor,
        allowed_methods=None,  # retry all verbs (ES _search POSTs are idempotent)
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.verify = not insecure_tls_requested()
    return s
