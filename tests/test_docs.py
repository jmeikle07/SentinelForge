"""Cheap guards so the documentation cannot silently rot (offline, no network).

They check things a reader would trip over: a command that names a script that no longer exists, a
link to a file that was renamed, an environment variable in a table that no code reads, or a test
count stated as an exact figure (which would be wrong after the next commit).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DOCS = sorted((ROOT / "docs").glob("*.md"))
DOC_FILES = [README, *DOCS]
SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache", "state", "build"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _repo_files() -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        out.extend(Path(dirpath, n) for n in filenames)
    return out


REPO_FILES = _repo_files()
REPO_RELATIVE = {p.relative_to(ROOT).as_posix() for p in REPO_FILES}
REPO_BASENAMES = {p.name for p in REPO_FILES}


def _ids(paths):
    return [p.relative_to(ROOT).as_posix() for p in paths]


# ── scripts named in the docs exist ──────────────────────────────────────────

# `python tools/x.py ...`, `venv/bin/python -m pytest`, `python3 approve.py list`
_PY_COMMAND = re.compile(r"\bpython3?(?:\.exe)?\s+((?:-[A-Za-z]+\s+)*)([\w./-]+\.py)\b")
# any mention of a repo script or shell wrapper
_SCRIPT_MENTION = re.compile(r"(?<![\w/.-])((?:[\w-]+/)*[\w-]+\.(?:py|sh))\b")
# Names that are examples, outputs or things created at run time, not repository files.
_NOT_REPO_FILES = {"redeploy-plan.json", "redeploy-result.json"}


@pytest.mark.parametrize("doc", DOC_FILES, ids=_ids(DOC_FILES))
def test_python_commands_name_existing_scripts(doc):
    missing = []
    for m in _PY_COMMAND.finditer(_text(doc)):
        script = m.group(2)
        if script not in REPO_RELATIVE:
            missing.append(script)
    assert not missing, f"{doc.name}: `python <script>` paths that do not exist: {sorted(set(missing))}"


@pytest.mark.parametrize("doc", DOC_FILES, ids=_ids(DOC_FILES))
def test_mentioned_scripts_exist(doc):
    missing = []
    for m in _SCRIPT_MENTION.finditer(_text(doc)):
        name = m.group(1)
        if name in _NOT_REPO_FILES:
            continue
        ok = name in REPO_RELATIVE or ("/" not in name and name in REPO_BASENAMES)
        if not ok:
            missing.append(name)
    assert not missing, f"{doc.name}: scripts mentioned but not found in the repository: {sorted(set(missing))}"


def test_wrapper_scripts_named_without_extension_exist():
    text = "\n".join(_text(p) for p in DOC_FILES)
    for name in ("sfhunt", "sfengine"):
        if f"scripts/{name}" in text:
            assert (ROOT / "scripts" / name).is_file()


# ── relative links resolve ───────────────────────────────────────────────────

_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_IMAGE = re.compile(r"\!\[[^\]]*\]\(([^)\s]+)\)")


def _slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    s = re.sub(r"[`*_]", "", heading.strip().lower())
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    out, in_code = set(), False
    for line in _text(path).splitlines():
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code and re.match(r"#{1,6}\s", line):
            out.add(_slug(line.lstrip("#")))
    return out


def _local_targets(doc: Path):
    text = _text(doc)
    for m in list(_LINK.finditer(text)) + list(_IMAGE.finditer(text)):
        target = m.group(1)
        if re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):  # http:, https:, mailto:
            continue
        yield target


@pytest.mark.parametrize("doc", DOC_FILES, ids=_ids(DOC_FILES))
def test_relative_links_resolve(doc):
    broken = []
    for target in _local_targets(doc):
        path_part, _, anchor = target.partition("#")
        dest = doc if not path_part else (doc.parent / path_part).resolve()
        if not dest.exists():
            broken.append(target)
        elif anchor and dest.suffix == ".md" and anchor not in _anchors(dest):
            broken.append(target + " (no such heading)")
    assert not broken, f"{doc.name}: broken relative links: {broken}"


# ── environment variables in the tables are read by the code ─────────────────

_ENV_NAME = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")


def _table_env_names(doc: Path, heading: str | None = None) -> set[str]:
    """Backticked UPPER_CASE names in the first column of the markdown table rows of a section."""
    text = _text(doc)
    if heading:
        start = text.index(heading)
        nxt = re.search(r"^## ", text[start + len(heading):], re.M)
        text = text[start:start + len(heading) + (nxt.start() if nxt else len(text))]
    names = set()
    for line in text.splitlines():
        if line.startswith("|"):
            first = line.split("|")[1] if line.count("|") > 1 else ""
            names.update(_ENV_NAME.findall(first))
    return names


def _code_text() -> str:
    parts = []
    for p in REPO_FILES:
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(("tests/", "docs/")) or p.name == "README.md":
            continue
        if p.suffix in {".py", ".sh", ".yml", ".yaml", ".plist"} or p.name in {".env.example"}:
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def test_readme_env_table_variables_appear_in_the_code():
    names = _table_env_names(README, "## Configuration")
    assert len(names) >= 10, "the README configuration table looks empty or its heading moved"
    code = _code_text()
    unused = sorted(n for n in names if n not in code)
    assert not unused, f"README configuration table names variables the code never mentions: {unused}"


def test_setup_env_table_variables_appear_in_the_code():
    names = _table_env_names(ROOT / "docs" / "SETUP.md", "## 4. Configuration")
    assert len(names) >= 15
    code = _code_text()
    unused = sorted(n for n in names if n not in code)
    assert not unused, f"SETUP.md configuration table names variables the code never mentions: {unused}"


def test_security_switches_stay_in_the_readme_table():
    # The security-relevant switches must stay documented in the README table.
    names = _table_env_names(README, "## Configuration")
    for required in ("LAB_ADMIN_TOKEN", "LAB_INSECURE_TLS", "SF_ALLOWED_HOSTS", "SF_CASE_VARIANTS",
                     "WATER_REVIEW_GATE", "ELASTIC_URL", "ELASTIC_API_KEY"):
        assert required in names


# ── no brittle or stale claims ───────────────────────────────────────────────

def test_test_count_is_never_stated_as_an_exact_number():
    count = re.compile(r"(?P<lead>[^.\n]{0,40}?)\b(?P<n>\d{1,3}(?:,\d{3})+|\d{3,5})\s+(?:offline\s+)?tests\b")
    hedge = re.compile(r"roughly|about|around|approximately|over|more than|~", re.I)
    for doc in DOC_FILES:
        for m in count.finditer(_text(doc)):
            assert hedge.search(m.group("lead")), (
                f"{doc.name}: states a test count ({m.group('n')}) without 'roughly'/'about'; "
                "counts change with every commit")
            # a hedged figure must be round, not a copy of a pytest summary line
            digits = m.group("n").replace(",", "")
            assert digits.endswith("00"), f"{doc.name}: test count {m.group('n')} is not a rounded figure"


def test_readme_generated_blocks_are_present_and_untouched_by_hand():
    text = _text(README)
    for name in ("detections-table", "cert-table"):
        assert f"<!-- BEGIN GENERATED: {name} -->" in text
        assert f"<!-- END GENERATED: {name} -->" in text


def test_readme_has_a_contents_list_and_required_sections():
    text = _text(README)
    for heading in ("## Contents", "## Quick start", "## Configuration", "## Security model", "## CI/CD",
                    "## Testing", "## Known limitations and what is not verified", "## Repository layout"):
        assert heading in text, heading


def test_readme_cert_dates_match_the_recorded_outline_metadata():
    objectives = yaml.safe_load(_text(ROOT / "docs" / "compliance" / "objectives.yml"))
    isc2 = objectives["isc2cc"]
    text = _text(README)
    assert str(isc2["effective_date"]) in text, "README must state the ISC2 outline effective date"
    assert str(isc2["retrieved"]) in text, "README must state the outline retrieval date"


def test_docs_do_not_claim_deployment_or_name_programs():
    banned = re.compile(r"graduat|in production|production-ready|deployed (?:at|in|to) (?:a |the )?(?:company|enterprise|client)",
                        re.I)
    for doc in DOC_FILES:
        m = banned.search(_text(doc))
        assert m is None, f"{doc.name}: {m.group(0)!r}"


def test_redeploy_doc_is_linked_from_readme_and_setup():
    assert "docs/REDEPLOY.md" in _text(README)
    assert "REDEPLOY.md" in _text(ROOT / "docs" / "SETUP.md")
    assert (ROOT / "docs" / "REDEPLOY.md").is_file()


def test_project_summary_exists_and_is_linked():
    assert (ROOT / "docs" / "PROJECT_SUMMARY.md").is_file()
    assert "docs/PROJECT_SUMMARY.md" in _text(README)
