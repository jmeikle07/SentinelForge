"""Branding, hygiene and README guard rails (offline; reads git-tracked files only)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THIS_FILE = Path(__file__).resolve()

# Built by concatenation so this file does not trip its own scan.
LEGACY = [
    "1x" + "lozec",
    "tall" + "kitchen",
    "tall" + " kitchen",
    "al" + "bundy",
    "10.0" + ".0.1",
]


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode("utf-8", "replace")
    paths = []
    for rel in filter(None, out.split("\0")):
        p = ROOT / rel
        if p.is_file() and ".git/" not in rel.replace("\\", "/") + "/":
            paths.append(p)
    return paths


def _text(p: Path) -> str | None:
    data = p.read_bytes()
    if b"\0" in data:
        return None  # binary
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def test_no_legacy_branding_strings():
    hits = []
    for p in _tracked_files():
        if p.resolve() == THIS_FILE:
            continue
        text = _text(p)
        if text is None:
            continue
        low = text.lower()
        for needle in LEGACY:
            if needle in low:
                hits.append(f"{p.relative_to(ROOT).as_posix()}: {needle}")
    assert not hits, "legacy strings remain:\n" + "\n".join(hits)


def test_no_verify_false_outside_documented_opt_in():
    """verify=False must never appear in tracked Python. TLS verification is
    controlled in one place (lab.http.session -> lab.config.insecure_tls_requested,
    the LAB_INSECURE_TLS opt-in), which assigns ``s.verify = not ...`` rather than
    a literal ``verify=False``. lab/http.py is the only file allowed to mention it."""
    needle = "verify" + "=False"
    hits = []
    for p in _tracked_files():
        rel = p.relative_to(ROOT).as_posix()
        if p.suffix != ".py" or rel == "lab/http.py" or p.resolve() == THIS_FILE:
            continue
        text = _text(p) or ""
        if needle in text:
            hits.append(rel)
    assert not hits, hits


README = (ROOT / "README.md").read_text(encoding="utf-8")


def _headings() -> list[str]:
    return [l for l in README.splitlines() if l.startswith("#")]


def test_readme_has_certification_mapping_section():
    heads = " ".join(_headings()).lower()
    assert "security+" in heads
    assert "isc2 cc" in heads
    assert "docs/compliance/COVERAGE.md" in README


def test_readme_states_mappings_are_authors_own():
    low = README.lower()
    assert "not official" in low or "not an official" in low


def test_readme_has_no_credentials():
    low = README.lower()
    assert "password:" not in low
    assert "**password" not in low
    assert "username:" not in low
    assert not re.search(r"(api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9+/_\-]{16,}", README)


def test_readme_has_honest_testing_section():
    heads = " ".join(_headings()).lower()
    assert "not verified" in heads


@pytest.mark.parametrize(
    "path",
    ["run_efficacy.sh", "run_engine.sh", "scripts/sfhunt", "scripts/sfengine"],
)
def test_scripts_are_portable_and_lf(path):
    p = ROOT / path
    assert p.exists(), path
    data = p.read_bytes()
    assert b"\r\n" not in data
    text = data.decode("utf-8")
    assert text.startswith("#!")
    assert "/Users/" not in text
    assert "scutil" not in text


@pytest.mark.parametrize("path", ["scheduler/com.sf.efficacy.plist", "scheduler/com.sf.engine.plist"])
def test_plists_have_no_hardcoded_paths(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    assert "/Users/" not in text
    assert "com.sf." in text
    assert "__SF_LAB_DIR__" in text  # documented placeholder substituted at install time


def test_docs_exist():
    for rel in ("docs/ARCHITECTURE.md", "docs/SETUP.md"):
        assert (ROOT / rel).read_text(encoding="utf-8").strip(), rel


def test_setup_documents_required_configuration():
    setup = (ROOT / "docs" / "SETUP.md").read_text(encoding="utf-8")
    for token in ("ELASTIC_URL", "ELASTIC_API_KEY", "KIBANA_URL", "envsubst",
                  "MODEL_NAME", "SMTP_HOST", "LAB_ADMIN_TOKEN", "rotate"):
        assert token in setup, token
