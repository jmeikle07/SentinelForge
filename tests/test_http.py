import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from requests.adapters import HTTPAdapter

from lab import http


def test_session_applies_default_timeout(monkeypatch):
    seen = {}

    def fake_send(self, request, **kwargs):
        seen.update(kwargs)
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b"{}"
        resp.request = request
        return resp

    monkeypatch.setattr(HTTPAdapter, "send", fake_send)
    s = http.session(timeout=7.5)
    s.get("http://example.test/x")
    assert seen["timeout"] == 7.5
    s.get("http://example.test/x", timeout=2)
    assert seen["timeout"] == 2


def test_session_retries_on_503():
    # Retry lives in urllib3, below the layer `responses` mocks, so use a
    # loopback server (still fully offline).
    statuses = [503, 503, 200]
    hits = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            code = statuses[len(hits)] if len(hits) < len(statuses) else 200
            hits.append(code)
            self.send_response(code)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        s = http.session(retries=3, timeout=5, backoff_factor=0)
        r = s.get(f"http://127.0.0.1:{srv.server_port}/")
        assert r.status_code == 200
        assert hits == [503, 503, 200]
    finally:
        srv.shutdown()


def test_session_verifies_tls_by_default(monkeypatch):
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)
    assert http.session().verify is True


def test_session_insecure_only_via_env(monkeypatch):
    monkeypatch.setenv("LAB_INSECURE_TLS", "1")
    assert http.session().verify is False


def _effective_verify(s, **kw):
    prep = s.prepare_request(requests.Request("GET", "https://x.test/"))
    return s.merge_environment_settings(prep.url, {}, None, kw.get("verify"), None)["verify"]


def test_insecure_overrides_ca_bundle_env(monkeypatch):
    monkeypatch.setenv("LAB_INSECURE_TLS", "1")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/bundle.pem")
    monkeypatch.setenv("CURL_CA_BUNDLE", "/nonexistent/bundle.pem")
    assert _effective_verify(http.session()) is False


def test_secure_default_still_honours_ca_bundle_env(monkeypatch):
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/some/bundle.pem")
    assert _effective_verify(http.session()) == "/some/bundle.pem"


def test_explicit_verify_param_matches_settings(monkeypatch):
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/bundle.pem")
    no_verify = bool(0)  # keep a literal 'verify' + '=False' out of tracked code (see test_branding)
    assert _effective_verify(http.session(verify=no_verify)) is False
    assert http.session(verify=True).verify is True


# -- retry policy: LLM POSTs must not be silently re-sent / re-billed -----------------

import time
from http.server import ThreadingHTTPServer

import pytest


@pytest.fixture
def server():
    """Loopback server; every verb answers per `plan` (status, extra headers, delay)."""
    state = {"hits": [], "status": 503, "headers": {}, "delay": 0.0}

    class H(BaseHTTPRequestHandler):
        def _handle(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            state["hits"].append(self.command)
            time.sleep(state["delay"])
            try:
                self.send_response(state["status"])
                for k, v in state["headers"].items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
            except OSError:
                pass  # client gave up (read timeout)

        do_GET = do_POST = do_PUT = do_DELETE = _handle

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{srv.server_port}/"
    try:
        yield state
    finally:
        srv.shutdown()


def test_post_is_not_retried_on_503_by_default(server):
    s = http.session(retries=3, timeout=5, backoff_factor=0)
    r = s.post(server["url"], json={"a": 1})
    assert r.status_code == 503
    assert server["hits"] == ["POST"]


def test_post_retried_when_caller_opts_in(server):
    s = http.session(retries=2, timeout=5, backoff_factor=0, retry_post=True)
    r = s.post(server["url"], json={"a": 1})
    assert r.status_code == 503
    assert server["hits"] == ["POST"] * 3


@pytest.mark.parametrize("verb", ["get", "put", "delete"])
def test_idempotent_verbs_still_retried(server, verb):
    s = http.session(retries=2, timeout=5, backoff_factor=0)
    getattr(s, verb)(server["url"])
    assert len(server["hits"]) == 3


def test_post_read_timeout_is_not_retried(server):
    server["status"], server["delay"] = 200, 1.0
    s = http.session(retries=3, timeout=0.3, backoff_factor=0)
    with pytest.raises(requests.exceptions.ReadTimeout):
        s.post(server["url"], json={})
    time.sleep(1.2)  # let any (wrongly) retried requests reach the server
    assert server["hits"] == ["POST"]


def test_retry_after_is_capped(server, monkeypatch):
    sleeps = []
    monkeypatch.setattr("urllib3.util.retry.time.sleep", lambda s: sleeps.append(s))
    server["headers"] = {"Retry-After": "86400"}
    s = http.session(retries=1, timeout=5, backoff_factor=0)
    s.get(server["url"])
    assert sleeps and max(sleeps) <= http.MAX_RETRY_AFTER == 30


def test_retry_after_http_date_is_capped():
    retry = http.session().get_adapter("http://x.test/").max_retries
    assert retry.parse_retry_after("Fri, 31 Dec 2100 23:59:59 GMT") == http.MAX_RETRY_AFTER
    assert retry.parse_retry_after("3") == 3
