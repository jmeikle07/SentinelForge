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
