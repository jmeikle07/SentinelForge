import dataclasses

import pytest

from lab import config


def test_load_requires_elastic_url(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    with pytest.raises(config.ConfigError):
        config.load()


def test_load_reads_env_and_defaults_tls_on(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.test:9200")
    monkeypatch.setenv("KIBANA_URL", "https://kb.example.test:5601")
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)
    s = config.load()
    assert s.elastic_url == "https://es.example.test:9200"
    assert s.kibana_url == "https://kb.example.test:5601"
    assert s.verify_tls is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.elastic_url = "x"


def test_insecure_tls_opt_in_warns(monkeypatch, caplog):
    config._reset_insecure_warning()
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.test:9200")
    monkeypatch.setenv("LAB_INSECURE_TLS", "1")
    with caplog.at_level("WARNING"):
        s = config.load()
    assert s.verify_tls is False
    assert "insecure" in caplog.text.lower()


def test_kibana_url_derived_when_unset_preserves_scheme(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.test:9200")
    monkeypatch.delenv("KIBANA_URL", raising=False)
    assert config.load().kibana_url == "https://es.example.test:5601"


def test_api_key_is_stripped(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.test:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "  abc123==\r\n")
    assert config.load().elastic_api_key == "abc123=="


@pytest.mark.parametrize("bad", ["es.example.test:9200", "//es.example.test", "elastic", "localhost:9200"])
def test_derive_kibana_rejects_url_without_scheme(monkeypatch, bad):
    monkeypatch.setenv("ELASTIC_URL", bad)
    monkeypatch.delenv("KIBANA_URL", raising=False)
    with pytest.raises(config.ConfigError):
        config.load()


def test_explicit_kibana_url_without_scheme_rejected(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.test:9200")
    monkeypatch.setenv("KIBANA_URL", "kb.example.test:5601")
    with pytest.raises(config.ConfigError):
        config.load()


def test_elastic_url_without_scheme_rejected_even_with_kibana_set(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "es.example.test:9200")
    monkeypatch.setenv("KIBANA_URL", "https://kb.example.test:5601")
    with pytest.raises(config.ConfigError):
        config.load()


def test_insecure_warning_logged_once_per_process(monkeypatch, caplog):
    config._reset_insecure_warning()
    monkeypatch.setenv("LAB_INSECURE_TLS", "1")
    with caplog.at_level("WARNING"):
        for _ in range(3):
            assert config.insecure_tls_requested() is True
    assert len([r for r in caplog.records if r.levelname == "WARNING" and "INSECURE_TLS" in r.getMessage()]) == 1
