import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
EA = Path(__file__).resolve().parent.parent / "elastalert"
FILES = [EA / "config.yaml", EA / "rules" / "siem_alerts.yaml"]


def test_elastalert_config_has_no_secrets_or_personal_paths():
    cfg = yaml.safe_load((EA / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["verify_certs"] is True
    key = cfg.get("es_api_key")
    assert not key or str(key).startswith("${"), "es_api_key must be an env reference"
    for f in FILES:
        text = f.read_text(encoding="utf-8")
        assert "/Us" + "ers/" not in text
        assert not re.search(r"[\w.+-]+@gmail\.com", text, re.I)
        assert "10.0" + ".0.1" not in text
        assert not re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text), f"key-like string in {f.name}"
        low = text.lower()
        for legacy in ("1x" + "lozec", "tall " + "kitchen", "tall" + "kitchen"):
            assert legacy not in low


def test_elastalert_uses_env_for_connection():
    cfg = yaml.safe_load((EA / "config.yaml").read_text(encoding="utf-8"))
    assert "${ELASTIC_HOST}" in str(cfg["es_host"])
    assert "${ELASTIC_API_KEY}" in str(cfg["es_api_key"])
    assert (EA / "run.sh").exists()


def test_rule_targets_alerts_alias_and_branding():
    rule = yaml.safe_load((EA / "rules" / "siem_alerts.yaml").read_text(encoding="utf-8"))
    assert rule["index"] == ".alerts-security.alerts-default"
    assert "SentinelForge" in rule["alert_text"]
    assert rule["email"] == ["${ALERT_EMAIL_TO}"]


def test_realert_is_scoped_per_query_key():
    rule = yaml.safe_load((EA / "rules" / "siem_alerts.yaml").read_text(encoding="utf-8"))
    assert rule["realert"] == {"minutes": 60}
    qk = rule.get("query_key")
    keys = qk if isinstance(qk, list) else [qk]
    assert "kibana.alert.rule.uuid" in keys and "host.name" in keys
    assert "kibana.alert.rule.uuid" in rule["include"] and "host.name" in rule["include"]
