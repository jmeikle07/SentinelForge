"""Case-variant expansion in lab.ecs.convert.

Sigma matches strings case-insensitively; the rendered Lucene query_string does
not on keyword / wildcard typed fields. lab.ecs therefore expands string literals
on Windows case-insensitive fields into a small bounded set of case variants at
conversion time (rule YAML is untouched). These tests pin the expansion for each
Sigma value form, its bounds, the exclusions and the debugging switch.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lab import ecs
from tests.test_rule_events import RULE_FILES, RULES_DIR, _parse

BUDGET = ecs.QUERY_CLAUSE_BUDGET


def _rule(detection: str, product: str = "windows", category: str = "process_creation",
          title: str = "case probe") -> str:
    body = "\n".join("    " + line for line in detection.strip("\n").splitlines())
    return (f"title: {title}\nid: 22222222-3333-4444-8555-666666666666\nstatus: test\n"
            f"logsource:\n    category: {category}\n    product: {product}\n"
            f"detection:\n{body}\nlevel: low\n")


def _q(detection: str, **kw) -> str:
    out = ecs.convert(_rule(detection, **kw))
    assert len(out) == 1
    return out[0]


def _terms(query: str) -> set[str]:
    """Flat set of 'field:pattern' leaves of a converted query (evaluator AST)."""
    found: set[str] = set()

    def walk(t):
        if t[0] == "term":
            found.add(t[1] + ":" + "".join(p[1] if p[0] == "lit" else "*" if p[0] == "any" else "?"
                                           for p in t[2]))
        elif t[0] == "not":
            walk(t[1])
        else:
            for c in t[1]:
                walk(c)
    walk(_parse(query))
    return found


# ---------------------------------------------------------------- variant generator
def test_case_variants_order_and_dedupe():
    assert ecs.case_variants("hostname.exe") == ["hostname.exe", "HOSTNAME.EXE", "Hostname.exe"]
    assert ecs.case_variants("HOSTNAME.EXE") == ["HOSTNAME.EXE", "hostname.exe", "Hostname.exe"]
    assert ecs.case_variants("Domain Admins") == [
        "Domain Admins", "domain admins", "DOMAIN ADMINS"]  # Title == as written
    assert ecs.case_variants("reg save") == ["reg save", "REG SAVE", "Reg Save"]


def test_case_variants_never_exceed_the_cap_and_keep_as_written_first():
    for text in ("a", "aB", "C:\\Windows\\System32\\cmd.exe", "mIxEd CaSe -Flag /Create"):
        for cap in (1, 2, 3, 4):
            v = ecs.case_variants(text, cap)
            assert v[0] == text and len(v) <= cap and len(set(v)) == len(v)
    assert len(ecs.case_variants("mIxEd CaSe", 4)) == 4


def test_case_variants_without_letters_is_a_single_value():
    assert ecs.case_variants("1234 /-") == ["1234 /-"]
    assert ecs.case_variants("") == [""]


# ---------------------------------------------------------------- Sigma value forms
def test_equals_form_expanded():
    q = _q("sel:\n  process.name: hostname.exe\ncondition: sel")
    assert _terms(q) >= {"process.name:hostname.exe", "process.name:HOSTNAME.EXE",
                         "process.name:Hostname.exe"}


def test_endswith_startswith_contains_forms_keep_wildcards():
    q = _q("sel:\n  process.executable|endswith: '\\hostname.exe'\n"
           "  process.command_line|contains: '/Create'\n"
           "  process.working_directory|startswith: 'C:\\Windows'\ncondition: sel")
    t = _terms(q)
    assert {"process.executable:*\\hostname.exe", "process.executable:*\\HOSTNAME.EXE",
            "process.executable:*\\Hostname.exe"} <= t
    assert {"process.command_line:*/Create*", "process.command_line:*/create*",
            "process.command_line:*/CREATE*"} <= t
    assert {"process.working_directory:C:\\Windows*", "process.working_directory:c:\\windows*",
            "process.working_directory:C:\\WINDOWS*"} <= t
    assert not any(x.endswith("hostname.exe") and not x.startswith("process.executable:*")
                   for x in t if x.startswith("process.executable:"))


def test_contains_all_expands_each_value_independently_and_keeps_the_and():
    q = _q("sel:\n  process.command_line|contains|all:\n    - reg\n    - Save\ncondition: sel")
    leaves = _terms(q)
    assert {"process.command_line:*reg*", "process.command_line:*REG*",
            "process.command_line:*Reg*"} <= leaves
    assert {"process.command_line:*Save*", "process.command_line:*save*",
            "process.command_line:*SAVE*"} <= leaves
    # AND between the two values is preserved: one without the other must not match
    from tests.test_rule_events import rule_matches
    qs = [q]
    assert rule_matches(qs, {"event.code": "1", "process.command_line": "x REG SAVE y"})
    assert rule_matches(qs, {"event.code": "1", "process.command_line": "x reg save y"})
    assert not rule_matches(qs, {"event.code": "1", "process.command_line": "x REG only"})


def test_value_list_is_deduplicated_against_manual_variants():
    q = _q("sel:\n  process.command_line|contains:\n    - 'Domain Admins'\n    - 'domain admins'\n"
           "condition: sel")
    leaves = sorted(x for x in _terms(q) if x.startswith("process.command_line:"))
    assert leaves == ["process.command_line:*DOMAIN ADMINS*", "process.command_line:*Domain Admins*",
                      "process.command_line:*domain admins*"]
    assert q.count("ADMINS") == 1 and q.count("Admins") == 1  # no duplicate clauses


def test_interior_wildcards_and_question_marks_survive():
    q = _q("sel:\n  process.name|contains: 'sv?host*x'\ncondition: sel")
    t = _terms(q)
    assert "process.name:*sv?host*x*" in t and "process.name:*SV?HOST*X*" in t


# ---------------------------------------------------------------- exclusions
def test_cased_values_are_never_expanded():
    # pySigma's Lucene backend cannot render |cased at all (NotImplementedError), so such a
    # rule fails loudly at conversion instead of being silently case-folded ...
    with pytest.raises(NotImplementedError):
        _q("sel:\n  process.name|cased: Hostname.exe\ncondition: sel")
    # ... and the expansion itself refuses SigmaCasedString should a future backend allow it.
    from sigma.types import SigmaCasedString, SigmaString
    assert ecs._expandable(SigmaString("Foo*"))
    assert not ecs._expandable(SigmaCasedString("Foo*"))


@pytest.mark.parametrize("field,value", [
    ("process.hash.sha256", "ABCDEF0123456789abcdef"),
    ("winlog.event_data.IntegrityLevel", "System"),
    ("registry.data.strings", "Secret Value"),
    ("event.action", "Process Create"),
    ("winlog.event_data.GrantedAccess", "0x1FFFFF"),
    ("destination.port", "4444"),
])
def test_case_meaningful_fields_are_untouched(field, value):
    q = _q(f"sel:\n  {field}: '{value}'\ncondition: sel")
    assert not ecs.is_case_insensitive_field(field)
    leaves = [x for x in _terms(q) if x.startswith(field + ":")]
    assert len(leaves) == 1, leaves
    assert value.lower() == value or value.lower() not in q   # no lower-cased copy emitted
    assert value.upper() == value or value.upper() not in q   # no UPPER-cased copy emitted


def test_sysmon_name_mapped_fields_are_covered():
    # Image / CommandLine are mapped to ECS by the pipeline, then expanded
    q = _q("sel:\n  Image|endswith: '\\reg.exe'\n  CommandLine|contains: 'SAVE'\ncondition: sel")
    t = _terms(q)
    assert "process.executable:*\\Reg.exe" in t and "process.command_line:*save*" in t


def test_non_windows_logsource_is_not_expanded():
    q = _q("sel:\n  process.name: Foo\ncondition: sel", product="linux")
    assert "FOO" not in q and "foo" not in q and "Foo" in q


def test_regex_cidr_and_numbers_are_not_expanded():
    q = _q("sel:\n  process.command_line|re: 'Foo.*Bar'\n  destination.ip|cidr: 10.0.0.0/8\n"
           "  destination.port: 443\ncondition: sel")
    assert q.count("Foo") == 1 and "foo" not in q and "FOO" not in q


def test_base64_modified_values_are_not_expanded():
    # base64 text is case significant: the three base64offset encodings must stay exactly three
    q = _q("sel:\n  process.command_line|base64offset|contains: 'IEX'\ncondition: sel")
    assert len([x for x in _terms(q) if x.startswith("process.command_line:")]) == 3


# ---------------------------------------------------------------- switch
def test_env_switch_disables_expansion(monkeypatch):
    det = "sel:\n  process.name: hostname.exe\ncondition: sel"
    monkeypatch.setenv("SF_CASE_VARIANTS", "0")
    assert not ecs.case_variants_enabled()
    assert _q(det) == "event.code:1 AND process.name:hostname.exe"
    monkeypatch.setenv("SF_CASE_VARIANTS", "1")
    assert ecs.case_variants_enabled()
    assert "HOSTNAME.EXE" in _q(det)
    monkeypatch.delenv("SF_CASE_VARIANTS")
    assert ecs.case_variants_enabled()  # default ON


# ---------------------------------------------------------------- bounds
def _long_contains_all(n: int) -> str:
    items = "\n".join(f"    - 'FlagNumber{i}x'" for i in range(n))
    return f"sel:\n  process.command_line|contains|all:\n{items}\ncondition: sel"


def test_per_value_cap_is_four():
    q = _q("sel:\n  process.command_line|contains: 'aBcDeF'\ncondition: sel")
    assert len([x for x in _terms(q) if x.startswith("process.command_line:")]) == 4


def test_long_contains_all_stays_under_the_clause_budget():
    for n in (10, 40, 60, 90, 150, 250):
        q = _q(_long_contains_all(n))
        if n < BUDGET:
            assert ecs.clause_count(q) <= BUDGET, (n, ecs.clause_count(q))
        else:  # the literal count alone exceeds the budget: nothing may be ADDED to it
            assert ecs.clause_count(q) == n + 1, (n, ecs.clause_count(q))


def test_budget_degrades_tier_by_tier_and_names_the_rule(caplog):
    # 40 values x 4 variants = 160 fits
    ecs._WARNED.clear()
    with caplog.at_level(logging.WARNING, logger="lab.ecs"):
        q = _q(_long_contains_all(40), title="Budget Probe Forty")
    assert "Flagnumber0x" in q and not caplog.records
    # 60: 4 variants = 240 > 200, as written + lower + UPPER = 180 fits
    with caplog.at_level(logging.WARNING, logger="lab.ecs"):
        q = _q(_long_contains_all(60), title="Budget Probe Sixty")
    assert "FLAGNUMBER0X" in q and "flagnumber0x" in q and "Flagnumber0x" not in q
    assert any("Budget Probe Sixty" in r.getMessage() for r in caplog.records)
    # 90: even 3 variants (270) do not fit; the list is longer than SMALL_LIST_MAX, so as written
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="lab.ecs"):
        q = _q(_long_contains_all(90), title="Budget Probe Ninety")
    assert "FLAGNUMBER0X" not in q and "FlagNumber0x" in q
    assert any("Budget Probe Ninety" in r.getMessage() for r in caplog.records)
    # 250: the unexpanded rule is over budget itself -> as written, still warned
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="lab.ecs"):
        q = _q(_long_contains_all(250), title="Budget Probe Huge")
    assert "FLAGNUMBER0X" not in q and ecs.clause_count(q) == 251
    assert any("Budget Probe Huge" in r.getMessage() for r in caplog.records)


def test_warning_is_logged_once_per_rule(caplog):
    ecs._WARNED.clear()
    with caplog.at_level(logging.WARNING, logger="lab.ecs"):
        for _ in range(3):
            _q(_long_contains_all(60), title="Budget Probe Once")
    assert len([r for r in caplog.records if "Budget Probe Once" in r.getMessage()]) == 1


def test_big_value_lists_are_skipped_but_small_items_still_expanded():
    items = "\n".join(f"    - ' -k Group{i}'" for i in range(150))
    q = _q(f"sel:\n  process.name: svchost.exe\nflt:\n  process.command_line|endswith:\n{items}\n"
           "condition: sel and not flt")
    t = _terms(q)
    assert "process.name:SVCHOST.EXE" in t and "process.name:Svchost.exe" in t
    assert not any("GROUP5" in x for x in t)  # the 150-entry list stays as written
    assert ecs.clause_count(q) <= BUDGET


def test_clause_count_counts_leaf_clauses():
    assert ecs.clause_count("a:1") == 1
    assert ecs.clause_count("a:1 AND (b:(x OR y OR z) OR NOT c:2)") == 5


# ---------------------------------------------------------------- shipped rules
def _all_converted():
    out = {}
    for p in RULE_FILES:
        out[p.name] = ecs.convert(p.read_text(encoding="utf-8"))
    return out


def test_every_shipped_rule_stays_under_the_clause_budget():
    counts = {name: max(ecs.clause_count(q) for q in qs) for name, qs in _all_converted().items()}
    over = {n: c for n, c in counts.items() if c > BUDGET}
    assert not over, over
    vals = list(counts.values())
    print(f"clauses per rule: max={max(vals)} mean={sum(vals) / len(vals):.1f} n={len(vals)}")


def test_expansion_only_ever_adds_clauses_to_shipped_rules(monkeypatch):
    monkeypatch.setenv("SF_CASE_VARIANTS", "0")
    base = {n: max(ecs.clause_count(q) for q in qs) for n, qs in _all_converted().items()}
    monkeypatch.delenv("SF_CASE_VARIANTS")
    new = {n: max(ecs.clause_count(q) for q in qs) for n, qs in _all_converted().items()}
    assert all(new[n] >= base[n] for n in base)
    assert any(new[n] > base[n] for n in base)


def test_rule_yaml_is_untouched_by_conversion():
    p = next(iter(RULE_FILES))
    before = p.read_bytes()
    ecs.convert(p.read_text(encoding="utf-8"))
    assert p.read_bytes() == before


# ---------------------------------------------------------------- golden queries
def _rule_by_id_prefix(prefix: str) -> str:
    import yaml
    for p in RULE_FILES:
        if yaml.safe_load(p.read_text(encoding="utf-8"))["id"].startswith(prefix):
            return p.read_text(encoding="utf-8")
    raise AssertionError(prefix)


# Reviewed by hand: each literal appears as written, lower, UPPER, Title (deduplicated);
# structure and escaping equal the SF_CASE_VARIANTS=0 rendering.
GOLDEN = {
    # plain equals on a keyword field
    "c27fffce": "event.code:1 AND (process.name:(sdbinst.exe OR SDBINST.EXE OR Sdbinst.exe))",
    # contains|all + lists + mixed-case flags; /d 1 has no distinct Title; Explorer\Advanced
    # is already Title so only 3 variants
    "0acbfe83": (
        "event.code:1 AND (((process.name:(reg.exe OR REG.EXE OR Reg.exe)) AND "
        "(process.parent.name:(*cmd.exe* OR *CMD.EXE* OR *Cmd.exe* OR *powershell.exe* OR "
        "*POWERSHELL.EXE* OR *Powershell.exe*))) AND "
        "((process.command_line:(*HideFileExt* OR *hidefileext* OR *HIDEFILEEXT* OR *Hidefileext*)) "
        r"AND (process.command_line:(*\/d\ 1* OR *\/D\ 1*)) AND "
        r"(process.command_line:(*Explorer\\Advanced* OR *explorer\\advanced* OR "
        r"*EXPLORER\\ADVANCED*))))"),
    # hand-written 'Domain Admins' / 'domain admins' pairs collapse into the generated variants
    "10edaa6c": (
        "event.code:1 AND ((process.name:(*net.exe* OR *NET.EXE* OR *Net.exe* OR *net1.exe* OR "
        r"*NET1.EXE* OR *Net1.exe*)) AND (process.command_line:(*group\ \/domain* OR "
        r"*GROUP\ \/DOMAIN* OR *Group\ \/Domain* OR *domain\ admins* OR *DOMAIN\ ADMINS* OR "
        r"*Domain\ Admins* OR *enterprise\ admins* OR *ENTERPRISE\ ADMINS* OR "
        r"*Enterprise\ Admins*)))"),
}


@pytest.mark.parametrize("rule_id", sorted(GOLDEN))
def test_golden_case_expanded_query(rule_id):
    assert ecs.convert(_rule_by_id_prefix(rule_id)) == [GOLDEN[rule_id]]


@pytest.mark.parametrize("rule_id", sorted(GOLDEN))
def test_golden_rules_are_verbatim_without_expansion(rule_id, monkeypatch):
    # sanity: every as-written literal of the verbatim query is still in the expanded one
    monkeypatch.setenv("SF_CASE_VARIANTS", "0")
    verbatim = ecs.convert(_rule_by_id_prefix(rule_id))[0]
    monkeypatch.delenv("SF_CASE_VARIANTS")
    assert verbatim != GOLDEN[rule_id]
    expanded = _terms(GOLDEN[rule_id])
    assert _terms(verbatim) <= expanded
