"""Verdict maths (B1/B2/W5) and IOC validation (W4). Pure functions, no network."""
import pytest

import sf_hunt

DOWN = {"available": False, "reason": "down"}


def _all_down_ip():
    return {k: dict(DOWN) for k in
            ("abuseipdb", "greynoise", "virustotal", "otx", "threatfox", "internetdb", "spamhaus_drop")}


def _all_malicious_ip(in_drop=False):
    return {
        "virustotal": {"available": True, "malicious": 60, "suspicious": 0, "total_engines": 90},
        "abuseipdb": {"available": True, "abuse_score": 100, "is_whitelisted": False},
        "greynoise": {"available": True, "classification": "malicious"},
        "threatfox": {"available": True, "match_count": 9},
        "otx": {"available": True, "pulse_count": 50},
        "spamhaus_drop": {"available": True, "in_drop": in_drop},
    }


# ── B1: zero data must not read as benign ────────────────────────────────────
@pytest.mark.parametrize("observed", [{}, {"error": "es down"}])
def test_all_sources_failed_is_unknown_insufficient_not_benign(observed):
    v = sf_hunt.bucket_verdict(observed, _all_down_ip(), "ipv4")
    assert v["verdict"] == "unknown"
    assert v["action"] == "INSUFFICIENT DATA"
    assert v["insufficient_data"] is True
    assert v["sources_answered"] == []


def test_empty_inputs_are_insufficient_for_every_ioc_type():
    for t in ("ipv4", "md5", "sha1", "sha256", "domain"):
        v = sf_hunt.bucket_verdict({}, {}, t)
        assert (v["verdict"], v["action"]) == ("unknown", "INSUFFICIENT DATA"), t


def test_clean_answers_from_real_sources_are_still_benign():
    ext = {
        "virustotal": {"available": True, "malicious": 0, "suspicious": 0, "total_engines": 90},
        "abuseipdb": {"available": True, "abuse_score": 0},
        "greynoise": {"available": True, "classification": "unknown"},
        "spamhaus_drop": {"available": True, "in_drop": False},
    }
    v = sf_hunt.bucket_verdict({}, ext, "ipv4")
    assert v["verdict"] == "benign" and not v["insufficient_data"]


def test_single_weak_clean_source_is_not_called_benign():
    v = sf_hunt.bucket_verdict({}, {"otx": {"available": True, "pulse_count": 0}}, "ipv4")
    assert v["verdict"] == "unknown" and v["insufficient_data"] is True


def test_not_in_drop_alone_is_not_evidence():
    v = sf_hunt.bucket_verdict({}, {"spamhaus_drop": {"available": True, "in_drop": False}}, "ipv4")
    assert v["insufficient_data"] is True


# ── B2: renormalise over the sources that actually answered ──────────────────
def test_every_external_source_malicious_is_malicious_without_tpot():
    v = sf_hunt.bucket_verdict({}, _all_malicious_ip(), "ipv4")
    assert v["verdict"] == "malicious" and v["action"] == "BLOCK"
    assert v["score"] >= 80


def test_drop_member_with_other_malicious_sources_is_not_capped_at_suspicious():
    v = sf_hunt.bucket_verdict({}, _all_malicious_ip(in_drop=True), "ipv4")
    assert v["verdict"] == "malicious" and v["score"] >= 80


def test_drop_alone_is_suspicious_via_floor():
    v = sf_hunt.bucket_verdict({}, {"spamhaus_drop": {"available": True, "in_drop": True}}, "ipv4")
    assert v["verdict"] == "suspicious" and v["score"] == 65.0


def test_one_weak_source_cannot_inflate_to_malicious():
    v = sf_hunt.bucket_verdict({}, {"otx": {"available": True, "pulse_count": 50}}, "ipv4")
    assert v["verdict"] != "malicious" and v["score"] < 40


def test_failed_source_does_not_dilute_the_others():
    ext = _all_malicious_ip()
    ext["otx"] = dict(DOWN)
    ext["abuseipdb"] = dict(DOWN)
    assert sf_hunt.bucket_verdict({}, ext, "ipv4")["verdict"] == "malicious"


def test_cli_and_web_inputs_agree_when_tpot_is_unavailable():
    ext = _all_malicious_ip()
    web = sf_hunt.bucket_verdict({}, ext, "ipv4")
    cli = sf_hunt.bucket_verdict({"error": "tpot unreachable"}, ext, "ipv4")
    assert web == cli


def test_observed_honeypot_data_still_counts_when_present():
    ext = _all_malicious_ip()
    v = sf_hunt.bucket_verdict({"event_count": 50000}, ext, "ipv4")
    assert v["verdict"] == "malicious" and "tpot" in v["sources_answered"]


def test_hash_and_domain_renormalise_too():
    h = sf_hunt.bucket_verdict({}, {"virustotal": {"available": True, "malicious": 60, "suspicious": 0,
                                                    "total_engines": 70, "in_corpus": True},
                                    "malwarebazaar": dict(DOWN)}, "sha256")
    assert h["verdict"] == "malicious"
    d = sf_hunt.bucket_verdict({}, {"urlhaus": {"available": True, "listed": True, "urls_online": 2}},
                               "domain")
    assert d["verdict"] == "malicious"


# ── W5: untrusted API fields are coerced, never raise ────────────────────────
@pytest.mark.parametrize("bad", ["100", "abc", None, [], {}, True, float("nan"), 10 ** 400])
def test_wrongly_typed_api_fields_never_raise(bad):
    ext = {
        "abuseipdb": {"available": True, "abuse_score": bad, "is_whitelisted": bad, "total_reports": bad},
        "virustotal": {"available": True, "malicious": bad, "suspicious": bad, "total_engines": bad,
                       "in_corpus": True},
        "greynoise": {"available": True, "classification": bad, "riot": bad, "name": bad},
        "threatfox": {"available": True, "match_count": bad},
        "otx": {"available": True, "pulse_count": bad},
        "spamhaus_drop": {"available": True, "in_drop": bad},
    }
    v = sf_hunt.bucket_verdict({"event_count": bad}, ext, "ipv4")
    assert 0 <= v["score"] <= 100


def test_numeric_string_score_is_coerced_not_a_typeerror():
    v = sf_hunt.bucket_verdict({}, {"abuseipdb": {"available": True, "abuse_score": "100"}}, "ipv4")
    assert v["signals"]["abuseipdb"] == 1.0


def test_non_dict_source_payloads_are_ignored():
    v = sf_hunt.bucket_verdict({}, {"virustotal": "oops", "otx": ["x"], "abuseipdb": 5}, "ipv4")
    assert v["insufficient_data"] is True
