"""W4: IOC validation happens before any third-party call; cache keys are canonical."""
import pytest

import sf_hunt


@pytest.mark.parametrize("ioc,expected", [
    ("1.1.1.1", "ipv4"),
    ("8.8.8.8", "ipv4"),
    ("a" * 32, "md5"),
    ("b" * 40, "sha1"),
    ("c" * 64, "sha256"),
    ("example.com", "domain"),
    ("sub.example.co.uk", "domain"),
])
def test_valid_public_iocs(ioc, expected):
    assert sf_hunt.detect_ioc_type(ioc) == expected


@pytest.mark.parametrize("ioc", [
    "١.٢.٣.٤",     # Arabic-Indic digits: \d matched these
    "8.8.8.８",                    # fullwidth 8
    "08.8.8.8", "8.08.8.8", "001.2.3.4", "8.8.8.00",          # leading zeros
    "256.1.1.1", "1.2.3", "1.2.3.4.5", " 8.8.8.8", "8.8.8.8\n", "",
    "2001:db8::1", "http://example.com/x", "exa mple.com", "-bad.example.com",
])
def test_malformed_iocs_are_unknown(ioc):
    assert sf_hunt.detect_ioc_type(ioc) == "unknown"


def test_non_string_is_unknown():
    assert sf_hunt.detect_ioc_type(None) == "unknown"
    assert sf_hunt.detect_ioc_type(8) == "unknown"


@pytest.mark.parametrize("ioc", [
    "10.0.0.1", "192.168.1.5", "172.16.0.9", "127.0.0.1", "169.254.1.1", "0.0.0.0",
    "224.0.0.1", "255.255.255.255", "100.64.0.1", "203.0.113.9",
    "dc01.corp.local", "printer.lan", "host.internal", "a.localhost", "x.home.arpa", "svc.test",
    "dc01", "localhost",
])
def test_non_global_ips_and_internal_hostnames_are_non_public(ioc):
    assert sf_hunt.detect_ioc_type(ioc) == "non_public"


@pytest.mark.parametrize("raw,canon", [
    ("  8.8.8.8  ", "8.8.8.8"),
    ("EXAMPLE.Com", "example.com"),
    ("A" * 64, "a" * 64),
])
def test_normalize_canonicalises_cache_keys(raw, canon):
    ioc, ioc_type, reason = sf_hunt.normalize_ioc(raw)
    assert ioc == canon and reason is None and ioc_type != "unknown"


@pytest.mark.parametrize("raw,fragment", [
    ("10.0.0.1", "non-public"),
    ("dc01.corp.local", "non-public"),
    ("not an ioc", "valid"),
    ("", "empty"),
])
def test_normalize_gives_a_reason_for_rejections(raw, fragment):
    ioc, ioc_type, reason = sf_hunt.normalize_ioc(raw)
    assert reason and fragment in reason.lower()
    assert ioc_type in ("non_public", "unknown")


def test_cli_rejects_non_public_before_any_network_or_cache(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "m.db")

    def boom(*a, **k):
        raise AssertionError("third-party/ES call attempted for a rejected IOC")

    for fn in ("bucket_external_ip", "bucket_identity_ip", "bucket_observed_ip",
               "bucket_external_domain", "bucket_external_hash", "elk_search"):
        monkeypatch.setattr(sf_hunt, fn, boom)
    assert sf_hunt.hunt("10.1.2.3") == 2
    out = capsys.readouterr().out.lower()
    assert "non-public" in out
    assert not (tmp_path / "m.db").exists()          # nothing recorded for a rejected IOC


def test_cli_canonicalises_ioc_before_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "m.db")
    seen = []
    monkeypatch.setattr(sf_hunt, "bucket_external_domain",
                        lambda conn, d: seen.append(d) or {})
    monkeypatch.setattr(sf_hunt, "elk_index_doc", lambda *a, **k: False)
    assert sf_hunt.hunt("EXAMPLE.com") == 0
    assert seen == ["example.com"]
