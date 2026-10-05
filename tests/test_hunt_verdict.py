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


# ── bands, floors and overrides (previously untested) ────────────────────────
@pytest.mark.parametrize("score,expected", [
    (100, "malicious"), (80, "malicious"), (79.9, "suspicious"), (60, "suspicious"),
    (59.9, "unknown"), (40, "unknown"), (39.9, "benign"), (0, "benign"),
])
def test_band_boundaries(score, expected):
    assert sf_hunt._band_for_score(score)[0] == expected


def test_drop_plus_heavy_honeypot_floors_at_85():
    v = sf_hunt.bucket_verdict({"event_count": 20000},
                               {"spamhaus_drop": {"available": True, "in_drop": True}}, "ipv4")
    assert v["score"] >= 85 and v["verdict"] == "malicious"
    assert any("IN DROP + T-Pot" in f for f in v["floors_applied"])


def test_heavy_honeypot_alone_applies_the_75_floor():
    v = sf_hunt.bucket_verdict({"event_count": 20000},
                               {"otx": {"available": True, "pulse_count": 0}}, "ipv4")
    assert v["score"] >= 75 and v["verdict"] in ("suspicious", "malicious")
    assert any("T-Pot" in f and "floor 75" in f for f in v["floors_applied"])


def test_riot_safety_brake_caps_at_unknown_unless_in_drop():
    ext = {"greynoise": {"available": True, "classification": "benign", "riot": True, "name": "Cloudflare"},
           "virustotal": {"available": True, "malicious": 60, "suspicious": 0, "total_engines": 90}}
    v = sf_hunt.bucket_verdict({"event_count": 20000}, ext, "ipv4")
    assert v["safety_brake"] is True and v["verdict"] == "unknown" and v["score"] == 59.0
    ext["spamhaus_drop"] = {"available": True, "in_drop": True}
    assert sf_hunt.bucket_verdict({"event_count": 20000}, ext, "ipv4")["safety_brake"] is False


def test_greynoise_benign_is_an_anti_signal_that_lowers_the_score():
    base = {"abuseipdb": {"available": True, "abuse_score": 80},
            "virustotal": {"available": True, "malicious": 60, "suspicious": 0, "total_engines": 90},
            "threatfox": {"available": True, "match_count": 5}}
    plain = sf_hunt.bucket_verdict({}, base, "ipv4")
    benign = sf_hunt.bucket_verdict(
        {}, dict(base, greynoise={"available": True, "classification": "benign"}), "ipv4")
    assert benign["contributions"]["greynoise"] < 0
    assert benign["raw_score"] < plain["raw_score"]


def test_hash_floors_malwarebazaar_signature_and_vt_consensus():
    mb = sf_hunt.bucket_verdict({}, {"malwarebazaar": {"available": True, "in_corpus": True,
                                                        "signature": "Emotet"}}, "sha256")
    assert mb["score"] >= 85 and mb["verdict"] == "malicious"
    vt = sf_hunt.bucket_verdict({}, {"virustotal": {"available": True, "in_corpus": True, "malicious": 30,
                                                     "suspicious": 0, "total_engines": 70}}, "sha256")
    assert vt["verdict"] == "malicious"
    quiet = {"malwarebazaar": {"available": True, "in_corpus": False},
             "threatfox": {"available": True, "match_count": 0},
             "otx": {"available": True, "pulse_count": 0}}
    weak = sf_hunt.bucket_verdict({}, dict(quiet, virustotal={"available": True, "in_corpus": True,
                                                              "malicious": 6, "suspicious": 0,
                                                              "total_engines": 60}), "sha256")
    assert weak["verdict"] == "suspicious" and weak["score"] == 65.0
    assert any("floor 65" in f for f in weak["floors_applied"])


def test_domain_urlhaus_live_floor_and_offline_floor():
    live = sf_hunt.bucket_verdict({}, {"urlhaus": {"available": True, "listed": True, "urls_online": 3}},
                                  "domain")
    off = sf_hunt.bucket_verdict({}, {"urlhaus": {"available": True, "listed": True, "urls_online": 0}},
                                 "domain")
    assert live["verdict"] == "malicious" and off["verdict"] == "suspicious"


def test_conflicts_are_reported_for_benign_vs_malicious_signals():
    ext = {"greynoise": {"available": True, "classification": "benign"},
           "abuseipdb": {"available": True, "abuse_score": 90}}
    v = sf_hunt.bucket_verdict({}, ext, "ipv4")
    assert any("AbuseIPDB scores 90" in c for c in v["conflicts"])
