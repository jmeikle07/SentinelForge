"""Environment-driven settings. No hardcoded hosts or secrets."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

log = logging.getLogger(__name__)


class ConfigError(RuntimeError):
    """Required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    elastic_url: str
    kibana_url: str
    verify_tls: bool
    elastic_api_key: str = field(default="", repr=False)


def insecure_tls_requested() -> bool:
    """True only when LAB_INSECURE_TLS=1 is set. Logs a warning each time."""
    if os.environ.get("LAB_INSECURE_TLS", "").strip() == "1":
        log.warning("LAB_INSECURE_TLS=1: TLS certificate verification is DISABLED (insecure)")
        return True
    return False


def _derive_kibana(elastic_url: str) -> str:
    p = urlparse(elastic_url)
    host = p.hostname or ""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return urlunparse((p.scheme, f"{host}:5601", "", "", "", ""))


def load() -> Settings:
    elastic_url = os.environ.get("ELASTIC_URL", "").strip().rstrip("/")
    if not elastic_url:
        raise ConfigError("ELASTIC_URL is not set (see .env.example)")
    kibana_url = os.environ.get("KIBANA_URL", "").strip().rstrip("/") or _derive_kibana(elastic_url)
    return Settings(
        elastic_url=elastic_url,
        kibana_url=kibana_url,
        verify_tls=not insecure_tls_requested(),
        elastic_api_key=os.environ.get("ELASTIC_API_KEY", ""),
    )
