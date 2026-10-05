"""Branding, hygiene and README guard rails (offline; scans tracked and untracked-but-not-ignored files)."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THIS_FILE = Path(__file__).resolve()

# Built by concatenation so this file does not trip its own scan.
LEGACY = [
    ("1x" + "lozec"),
    ("tall" + "kitchen"),
    ("tall" + " kitchen"),
    ("al" + "bundy"),
    ("tk" + "-hunt"),
]
# Test modules legitimately spell the legacy names inside their own "must not appear" patterns.
LEGACY_NOT_IN_TESTS = {"tk" + "-hunt"}
# A personal LAN address: matched as a whole address ("110.0.0.10" and "10.0.0.15" are fine).
LEGACY_ADDR = re.compile(r"(?<![\d.])10\.0\.0\.1(?![\d.])")
VERIFY_FALSE = re.compile(r"\bverify\s*=\s*False\b")
SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache", "state", "build"}


def _candidate_files(root: Path = ROOT) -> list[Path]:
    """Every file that is (or would be) part of the repository: tracked files AND untracked files
    that are not git-ignored, so a new file cannot dodge the scan until it is committed. Outside a
    git checkout (source tarball, CI artefact) fall back to walking the tree."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, capture_output=True, check=True,
        ).stdout.decode("utf-8", "replace")
        rels = sorted(set(filter(None, out.split("\0"))))
    except (OSError, subprocess.CalledProcessError):
        rels = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                rels.append(Path(dirpath, name).relative_to(root).as_posix())
    return [root / rel for rel in rels if (root / rel).is_file()]


def _tracked_files() -> list[Path]:
    return _candidate_files(ROOT)


def _text(p: Path) -> str | None:
    data = p.read_bytes()
    if b"\0" in data:
        return None  # binary
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _legacy_hits(text: str, is_test: bool = False) -> list[str]:
    low = text.lower()
    hits = [needle for needle in LEGACY
            if needle in low and not (is_test and needle in LEGACY_NOT_IN_TESTS)]
    if LEGACY_ADDR.search(text):
        hits.append("10.0.0.1")
    return hits


def test_no_legacy_branding_strings():
    hits = []
    for p in _candidate_files():
        if p.resolve() == THIS_FILE:
            continue
        text = _text(p)
        if text is None:
            continue
        for needle in _legacy_hits(text, is_test=p.relative_to(ROOT).parts[:1] == ("tests",)):
            hits.append(f"{p.relative_to(ROOT).as_posix()}: {needle}")
    assert not hits, "legacy strings remain:\n" + "\n".join(hits)


@pytest.mark.parametrize("text,expected", [
    ("host = 10.0.0.1", True), ("10.0.0.1:9200", True), ("(10.0.0.1)", True),
    ("110.0.0.10", False), ("10.0.0.15", False), ("v10.0.0.1.2", False), ("10.0.0.2", False),
    ("TK-Hunt", True), ("sf-hunt", False),
])
def test_legacy_scan_matches_whole_addresses_and_the_old_hunt_name(text, expected):
    assert bool(_legacy_hits(text)) is expected


@pytest.mark.parametrize("text,expected", [
    ("requests.get(u, verify=False)", True), ("requests.get(u, verify = False)", True),
    ("s.verify  =\tFalse", True), ("verify=True", False), ("s.verify = not insecure", False),
    ("self_verify=False_positive", False),
])
def test_verify_false_pattern_tolerates_whitespace(text, expected):
    assert bool(VERIFY_FALSE.search(text)) is expected


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=cwd, check=True, capture_output=True)


def test_scan_includes_untracked_but_not_ignored_files(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (tmp_path / "tracked.txt").write_text("a", encoding="utf-8")
    _git(tmp_path, "add", ".gitignore", "tracked.txt")
    _git(tmp_path, "commit", "-q", "-m", "x")
    (tmp_path / "new_untracked.py").write_text("print(1)", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("secret", encoding="utf-8")
    names = {p.name for p in _candidate_files(tmp_path)}
    assert {"tracked.txt", "new_untracked.py", ".gitignore"} <= names
    assert "ignored.txt" not in names


def test_scan_does_not_crash_outside_a_git_checkout(tmp_path):
    (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "skip.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "b.py").write_text("x = 2", encoding="utf-8")
    names = {p.name for p in _candidate_files(tmp_path)}
    assert names == {"a.py", "b.py"}


def test_no_verify_false_outside_documented_opt_in():
    """verify=False must never appear in tracked Python. TLS verification is
    controlled in one place (lab.http.session -> lab.config.insecure_tls_requested,
    the LAB_INSECURE_TLS opt-in), which assigns ``s.verify = not ...`` rather than
    a literal ``verify=False``. lab/http.py is the only file allowed to mention it."""
    hits = []
    for p in _candidate_files():
        rel = p.relative_to(ROOT).as_posix()
        if p.suffix != ".py" or rel == "lab/http.py" or p.resolve() == THIS_FILE:
            continue
        text = _text(p) or ""
        if VERIFY_FALSE.search(text):
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
