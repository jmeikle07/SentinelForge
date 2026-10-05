"""The one place HTTP sessions are built: default timeout, retries, TLS on by default."""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lab.config import insecure_tls_requested

RETRY_STATUSES = (429, 502, 503, 504)
# Methods safe to re-send after a read timeout / 5xx. POST is excluded unless the caller opts in
# with session(retry_post=True): a retried LLM POST is generated and billed twice. (Connect
# errors, where no request was sent, are retried for every method.)
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
MAX_RETRY_AFTER = 30  # seconds; urllib3 would otherwise honour up to 6 h


class _CappedRetry(Retry):
    def parse_retry_after(self, retry_after):
        return min(super().parse_retry_after(retry_after), MAX_RETRY_AFTER)


class _TimeoutSession(requests.Session):
    def __init__(self, timeout: float):
        super().__init__()
        self._default_timeout = timeout

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        settings = super().merge_environment_settings(url, proxies, stream, verify, cert)
        # requests lets REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE override session.verify=False;
        # an explicit opt-out must win. (A per-call verify argument still wins over it.)
        if self.verify is False and verify is None:
            settings["verify"] = False
        return settings

    def request(self, method, url, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self._default_timeout
        return super().request(method, url, **kwargs)


def session(retries: int = 3, timeout: float = 10.0, *, backoff_factor: float = 0.5,
            verify: bool | None = None, retry_post: bool = False) -> requests.Session:
    s = _TimeoutSession(timeout)
    retry = _CappedRetry(
        total=retries,
        status_forcelist=RETRY_STATUSES,
        backoff_factor=backoff_factor,
        allowed_methods=None if retry_post else IDEMPOTENT_METHODS,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    # verify comes from Settings.verify_tls when the caller has it, else from the env opt-in
    s.verify = (not insecure_tls_requested()) if verify is None else bool(verify)
    return s
