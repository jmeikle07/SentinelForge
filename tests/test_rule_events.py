"""Event-level tests for the shipped Sigma rules.

Schema/conversion tests cannot tell a rule that fires from one that never can
(review B4: a registry branch ANDed with event.code:1, filters on fields the
event type does not have, ...). This module therefore

1. converts every rule with lab.ecs.convert (exactly what gets deployed),
2. parses the Lucene with a small, strict evaluator (tested below),
3. checks every field a rule references exists for the Sysmon event it targets
   (guard test, driven by SYSMON_EVENT_FIELDS), and
4. replays hand-written ECS-flattened events from tests/fixtures/events/*.yml:
   every rule I changed or review B flagged has >=1 event that must match and
   >=1 realistic near-miss that must not.

Case sensitivity: the evaluator is case-SENSITIVE. pySigma's Lucene backend
renders literals verbatim (no case folding) and ECS process.* / registry.* /
dns.* fields are keyword-like types that Kibana's query_string compares
case-sensitively, whereas Sigma itself is case-insensitive. A literal's case
therefore matters in production; the fixtures use the casing Windows really
produces (e.g. HOSTNAME.EXE). Whether the lab's own index mapping adds a
case-insensitive normalizer could not be verified offline.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest
import yaml

from lab.ecs import convert

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections" / "sigma"
EVENTS_DIR = ROOT / "tests" / "fixtures" / "events"


# --------------------------------------------------------------------------
# Minimal Lucene-subset evaluator (the subset pySigma's LuceneBackend emits)
# --------------------------------------------------------------------------
class LuceneError(ValueError):
    pass


# AST: ("and", [n..]) ("or", [n..]) ("not", n) ("term", field, pattern)
# pattern: list of ("lit", ch) / ("any",) [*] / ("one",) [?]
def _parse(text: str):
    pos = 0
    n = len(text)

    def peek_ws():
        nonlocal pos
        while pos < n and text[pos].isspace():
            pos += 1

    def word_ahead(word):
        peek_ws()
        end = pos + len(word)
        return (text.startswith(word, pos)
                and (end == n or text[end].isspace() or text[end] == "("))

    def parse_expr():
        """operand (OP operand)* with a single operator kind per level."""
        nonlocal pos
        operands = [parse_operand()]
        op = None
        while True:
            peek_ws()
            if word_ahead("AND"):
                this = "and"
            elif word_ahead("OR"):
                this = "or"
            else:
                break
            if op not in (None, this):
                raise LuceneError("AND/OR mixed without parentheses (ambiguous)")
            op = this
            pos += len(this)
            operands.append(parse_operand())
        if op is None:
            return operands[0]
        return (op, operands)

    def parse_operand():
        nonlocal pos
        peek_ws()
        if word_ahead("NOT"):
            pos += 3
            return ("not", parse_operand())
        if pos < n and text[pos] == "(":
            pos += 1
            node = parse_expr()
            peek_ws()
            if pos >= n or text[pos] != ")":
                raise LuceneError("missing )")
            pos += 1
            return node
        return parse_term()

    def parse_term():
        nonlocal pos
        m = re.compile(r"[A-Za-z_@][\w.@\-]*:").match(text, pos)
        if not m:
            raise LuceneError(f"expected field: at {text[pos:pos + 30]!r}")
        field = m.group(0)[:-1]
        pos = m.end()
        if pos < n and text[pos] == "(":
            pos += 1
            node = parse_values(field)
            peek_ws()
            if pos >= n or text[pos] != ")":
                raise LuceneError("missing ) in field group")
            pos += 1
            return node
        return ("term", field, parse_value())

    def parse_values(field):
        nonlocal pos
        items = [("term", field, parse_value())]
        op = None
        while True:
            peek_ws()
            if word_ahead("OR"):
                this = "or"
            elif word_ahead("AND"):
                this = "and"
            else:
                break
            if op not in (None, this):
                raise LuceneError("mixed AND/OR in field group")
            op = this
            pos += len(this)
            peek_ws()
            items.append(("term", field, parse_value()))
        return items[0] if op is None else (op, items)

    def parse_value():
        nonlocal pos
        peek_ws()
        out = []
        if pos < n and text[pos] == '"':
            pos += 1
            while pos < n and text[pos] != '"':
                if text[pos] == "\\" and pos + 1 < n:
                    pos += 1
                out.append(("lit", text[pos]))
                pos += 1
            if pos >= n:
                raise LuceneError("unterminated quote")
            pos += 1
            return out
        while pos < n and not text[pos].isspace() and text[pos] != ")":
            ch = text[pos]
            if ch == "\\":
                if pos + 1 >= n:
                    raise LuceneError("dangling backslash")
                out.append(("lit", text[pos + 1]))
                pos += 2
                continue
            if ch == "*":
                out.append(("any",))
            elif ch == "?":
                out.append(("one",))
            elif ch in "[]{}~^/(:":
                # '(' / ':' unescaped inside a value would be nested groups or a
                # second field: refuse loudly instead of reading them as literals.
                raise LuceneError(f"unsupported Lucene syntax {ch!r}")
            else:
                out.append(("lit", ch))
            pos += 1
        if not out:
            raise LuceneError("empty value")
        return out

    tree = parse_expr()
    peek_ws()
    if pos != n:
        raise LuceneError(f"trailing text {text[pos:pos + 30]!r}")
    return tree


def _literal(pattern):
    """The pattern as a plain string if it has no wildcards, else None."""
    if any(p[0] != "lit" for p in pattern):
        return None
    return "".join(p[1] for p in pattern)


def _regex(pattern):
    parts = []
    for p in pattern:
        parts.append(re.escape(p[1]) if p[0] == "lit" else ".*" if p[0] == "any" else ".")
    return re.compile("".join(parts), re.DOTALL)


_CIDR = re.compile(r"[0-9a-fA-F:.]+/\d{1,3}")


def _term_matches(field, pattern, event):
    if field not in event:
        return False
    values = event[field]
    values = values if isinstance(values, (list, tuple)) else [values]
    lit = _literal(pattern)
    for value in values:
        sval = str(value)
        if lit is not None and _CIDR.fullmatch(lit):
            try:
                if ipaddress.ip_address(sval) in ipaddress.ip_network(lit, strict=False):
                    return True
            except ValueError:
                pass
            continue
        if _regex(pattern).fullmatch(sval):
            return True
    return False


def evaluate(tree, event) -> bool:
    kind = tree[0]
    if kind == "term":
        return _term_matches(tree[1], tree[2], event)
    if kind == "not":
        return not evaluate(tree[1], event)
    if kind == "and":
        return all(evaluate(c, event) for c in tree[1])
    if kind == "or":
        return any(evaluate(c, event) for c in tree[1])
    raise LuceneError(kind)


def matches(query, event) -> bool:
    """True if the Lucene query (string, or already parsed) matches the flat ECS event."""
    return evaluate(_parse(query) if isinstance(query, str) else query, event)


def rule_matches(queries, event) -> bool:
    return any(matches(q, event) for q in queries)


def _dnf(tree, negate=False, cap=20000):
    """Disjunctive normal form: list of conjuncts, each a list of (negated, field, pattern)."""
    kind = tree[0]
    if kind == "term":
        return [[(negate, tree[1], tree[2])]]
    if kind == "not":
        return _dnf(tree[1], not negate, cap)
    conj = (kind == "and") != negate  # De Morgan
    parts = [_dnf(c, negate, cap) for c in tree[1]]
    if not conj:
        return [c for p in parts for c in p]
    out = [[]]
    for p in parts:
        out = [a + b for a in out for b in p]
        if len(out) > cap:
            raise LuceneError("DNF too large")
    return out


# --------------------------------------------------------------------------
# Tests of the evaluator itself
# --------------------------------------------------------------------------
def test_eval_field_value_and_boolean_operators():
    ev = {"event.code": "1", "process.name": "net.exe"}
    assert matches("event.code:1 AND process.name:net.exe", ev)
    assert not matches("event.code:1 AND process.name:net1.exe", ev)
    assert matches("process.name:net1.exe OR process.name:net.exe", ev)
    assert matches("event.code:1 AND (NOT process.name:cmd.exe)", ev)
    assert not matches("NOT (event.code:1 AND process.name:net.exe)", ev)


def test_eval_wildcards_are_anchored_and_case_sensitive():
    ev = {"process.command_line": r"C:\Windows\system32\svchost.exe -k netsvcs -p"}
    assert matches(r"process.command_line:*\-k\ netsvcs*", ev)
    assert matches(r"process.command_line:C\:\\Windows*", ev)
    assert not matches(r"process.command_line:*\-K\ netsvcs*", ev)  # case matters
    assert not matches(r"process.command_line:svchost.exe", ev)  # no implicit substring
    assert matches(r"process.command_line:*svchost.ex?\ *", ev)  # ? is a single char


def test_eval_escaped_wildcard_and_specials_are_literal():
    assert matches(r"a.b:foo\*bar", {"a.b": "foo*bar"})
    assert not matches(r"a.b:foo\*bar", {"a.b": "fooXbar"})
    assert matches(r"a.b:*\\IPC$*", {"a.b": r"net use \\host\IPC$ /user:x"})
    assert matches(r"a.b:Password\!", {"a.b": "Password!"})


def test_eval_field_group_and_quoted_phrase():
    ev = {"destination.port": 443}
    assert matches("destination.port:(80 OR 443)", ev)  # ints compare as strings
    assert not matches("destination.port:(80 OR 8080)", ev)
    assert matches('a.b:"two words"', {"a.b": "two words"})
    assert matches(r"a.b:(*foo\ bar* OR *x*)", {"a.b": "a foo bar b"})


def test_eval_missing_field_never_matches_and_not_of_missing_is_true():
    assert not matches("process.parent.name:cmd.exe", {"event.code": "13"})
    assert matches("NOT process.parent.name:cmd.exe", {"event.code": "13"})


def test_eval_cidr_and_multivalued_fields():
    assert matches(r"source.ip:10.0.0.0\/8", {"source.ip": "10.2.3.4"})
    assert not matches(r"source.ip:10.0.0.0\/8", {"source.ip": "11.2.3.4"})
    assert matches(r"source.ip:77.83.240.70\/32", {"source.ip": "77.83.240.70"})
    assert not matches(r"source.ip:10.0.0.0\/8", {"source.ip": "not-an-ip"})
    assert matches("tags:b", {"tags": ["a", "b"]})


@pytest.mark.parametrize("bad", [
    "a:((1 OR 2) OR 3)",           # nested field group: would silently become literals
    "a:b:c",                       # unescaped ':' inside a value
    "a:1 AND b:2 OR c:3",          # ambiguous precedence must be rejected, not guessed
    "a:1 AND (b:2",                # unbalanced
    "a:[1 TO 5]",                  # ranges unsupported -> loud failure, never silent
    "bare",                        # keyword search without a field
    "a:1 AND",
])
def test_eval_rejects_what_it_cannot_evaluate(bad):
    with pytest.raises(LuceneError):
        _parse(bad)


def test_eval_not_and_or_precedence_through_groups():
    ev = {"event.code": "1", "process.name": "a.exe"}
    q = "event.code:1 AND ((process.name:b.exe OR process.name:c.exe) OR (process.name:a.exe AND NOT process.parent.name:x))"
    assert matches(q, ev)
    assert not matches(q, {**ev, "process.parent.name": "x"})
    assert rule_matches(["event.code:2", "process.name:a.exe"], ev)  # OR across queries
    assert not rule_matches([], ev)


def test_eval_on_real_pysigma_output_roundtrip():
    rule = """
title: t
id: 00000000-0000-4000-8000-000000000001
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel: {process.name: Foo.exe, process.command_line|contains|all: ['-a', 'b c']}
  flt: {process.parent.name: [x.exe, y.exe]}
  condition: sel and not flt
level: low
"""
    qs = convert(rule)
    ev = {"event.code": "1", "process.name": "foo.exe", "process.command_line": r"C:oo.exe -a b c"}
    # Sigma is case-insensitive; the rendered Lucene keeps the literal's case verbatim
    # and this evaluator (like keyword-typed ECS fields) compares case-sensitively.
    assert "Foo.exe" in qs[0] and "foo.exe" not in qs[0]
    assert rule_matches(qs, {**ev, "process.name": "Foo.exe"})
    assert not rule_matches(qs, ev)
    assert not rule_matches(qs, {**ev, "process.parent.name": "y.exe"})
    assert not rule_matches(qs, {**ev, "process.command_line": r"foo.exe -a"})


def test_dnf_expands_de_morgan():
    tree = _parse("a:1 AND NOT (b:2 AND c:3)")
    conj = _dnf(tree)
    assert len(conj) == 2
    assert [(neg, f) for neg, f, _ in conj[0]] == [(False, "a"), (True, "b")]
    assert [(neg, f) for neg, f, _ in conj[1]] == [(False, "a"), (True, "c")]


# --------------------------------------------------------------------------
# Guard: every field referenced must exist for the Sysmon event it targets
# --------------------------------------------------------------------------
_PROC = {  # Image / ProcessId / ProcessGuid / User shared by many Sysmon events
    "process.executable", "process.name", "process.pid", "process.entity_id",
    "user.name", "user.domain",
}
_COMMON = {"event.code", "event.action", "host.name", "@timestamp", "winlog.computer_name"}

# Allowed ECS fields per Sysmon event id. Source: Sysmon event schemas
# (Sysinternals docs), mapped to ECS the way Elastic's winlogbeat/Agent sysmon
# pipeline does. A field absent here does not exist on that event, so a rule
# using it can never match (B4).
SYSMON_EVENT_FIELDS = {
    # Sysmon event 1 "Process Create": Image, CommandLine, ParentImage,
    # ParentCommandLine, CurrentDirectory, User, IntegrityLevel, Hashes,
    # OriginalFileName, Description/Product/Company/FileVersion, LogonId...
    "1": _PROC | {
        "process.command_line", "process.parent.name", "process.parent.executable",
        "process.parent.command_line", "process.parent.pid", "process.parent.entity_id",
        "process.working_directory", "process.pe.original_file_name", "process.hash.md5",
        "process.hash.sha1", "process.hash.sha256",
        "winlog.event_data.IntegrityLevel", "winlog.event_data.LogonId",
        "winlog.event_data.ParentUser", "winlog.event_data.Description",
        "winlog.event_data.Product", "winlog.event_data.Company",
    },
    # Sysmon event 3 "Network connection": Image, User, Protocol, Initiated,
    # SourceIp/Port/Hostname, DestinationIp/Port/Hostname. No CommandLine, no parent.
    # (Protocol -> network.transport; network.protocol is the application protocol
    # and is NOT populated from event 3, so it is deliberately absent.)
    "3": _PROC | {
        "source.ip", "source.port", "source.domain", "destination.ip",
        "destination.port", "destination.domain", "network.transport",
        "network.direction", "network.type",
    },
    # Sysmon event 7 "Image loaded": Image, ImageLoaded, Signed, Signature, Hashes.
    # (ImageLoaded is dll.path/dll.name, not file.*.)
    "7": _PROC | {"dll.path", "dll.name", "dll.hash.sha256",
                  "dll.code_signature.subject_name", "dll.code_signature.status"},
    # Sysmon event 8 "CreateRemoteThread": SourceImage, TargetImage, StartAddress...
    "8": _PROC | {"winlog.event_data.TargetImage", "winlog.event_data.StartAddress",
                  "winlog.event_data.SourceImage"},
    # Sysmon event 10 "ProcessAccess": SourceImage, TargetImage, GrantedAccess, CallTrace.
    "10": _PROC | {"winlog.event_data.TargetImage", "winlog.event_data.GrantedAccess",
                   "winlog.event_data.SourceImage", "winlog.event_data.CallTrace"},
    # Sysmon event 11 "FileCreate": Image, TargetFilename, CreationUtcTime, User.
    "11": _PROC | {"file.path", "file.name", "file.directory", "file.extension"},
    # Sysmon events 12/13/14 "Registry create/delete, value set, rename": EventType,
    # Image, TargetObject, Details (13), NewName (14), User. No CommandLine,
    # no parent, no IntegrityLevel.
    # Details (the value written) exists on event 13 only; 12 has EventType+TargetObject,
    # 14 has TargetObject+NewName.
    "12": _PROC | {"registry.key", "registry.path", "registry.value", "registry.hive"},
    "13": _PROC | {"registry.key", "registry.path", "registry.value", "registry.hive",
                   "registry.data.strings", "registry.data.type"},
    "14": _PROC | {"registry.key", "registry.path", "registry.value", "registry.hive"},
    # Sysmon event 17 "Pipe created": PipeName, Image, User.
    "17": _PROC | {"file.name", "file.path"},
    # Sysmon event 22 "DNSEvent": QueryName, QueryStatus, QueryResults, Image, User.
    # No CommandLine, no parent.
    "22": _PROC | {"dns.question.name", "dns.question.type", "dns.resolved_ip",
                   "dns.answers.data", "dns.response_code"},
    # Sysmon 2 FileCreateTime change, 6 DriverLoad, 23/26 FileDelete(+Detected),
    # 19/20/21 WMI filter/consumer/binding. No command line, no parent.
    "2": _PROC | {"file.path", "file.name", "file.directory"},
    "6": _PROC | {"file.path", "file.name", "dll.path", "dll.code_signature.status"},
    "23": _PROC | {"file.path", "file.name", "file.directory", "file.extension"},
    "26": _PROC | {"file.path", "file.name", "file.directory", "file.extension"},
    "19": _PROC | {"winlog.event_data.EventNamespace", "winlog.event_data.Name",
                   "winlog.event_data.Query"},
    "20": _PROC | {"winlog.event_data.Name", "winlog.event_data.Destination",
                   "winlog.event_data.Type"},
    "21": _PROC | {"winlog.event_data.Consumer", "winlog.event_data.Filter"},
}
# The pySigma sysmon pipeline pins each logsource category to these events.
CATEGORY_EVENTS = {
    "process_creation": {"1"}, "network_connection": {"3"}, "image_load": {"7"},
    "create_remote_thread": {"8"}, "process_access": {"10"}, "file_event": {"11"},
    "registry_add": {"12"}, "registry_delete": {"12"}, "registry_set": {"13"},
    "registry_event": {"12", "13", "14"}, "pipe_created": {"17"}, "dns_query": {"22"},
    "file_change": {"2"}, "driver_load": {"6"}, "file_delete": {"23", "26"},
    "wmi_event": {"19", "20", "21"},
}

RULE_FILES = sorted(RULES_DIR.glob("*.yml"))
RULES = {p.name: yaml.safe_load(p.read_text(encoding="utf-8")) for p in RULE_FILES}


def _positive_codes(conjunct):
    return {_literal(p) for neg, f, p in conjunct if not neg and f == "event.code"}


def analyse(queries):
    """Yield (problem, detail) for every conjunct of every query that cannot work."""
    problems = []
    for q in queries:
        for conj in _dnf(_parse(q)):
            codes = _positive_codes(conj)
            if None in codes:
                problems.append(("wildcard event.code", q))
                continue
            if len(codes) != 1:
                problems.append((f"conjunct needs event.code {sorted(codes)}", q))
                continue
            (code,) = codes
            allowed = SYSMON_EVENT_FIELDS.get(code)
            if allowed is None:
                problems.append((f"no schema for Sysmon event {code}", q))
                continue
            bad = sorted({f for _, f, _ in conj if f not in allowed | _COMMON})
            if bad:
                problems.append((f"fields {bad} do not exist on Sysmon event {code}", q))
    return problems


@pytest.mark.parametrize("name", sorted(RULES))
def test_rule_only_uses_fields_that_exist_for_its_event(name):
    queries = convert((RULES_DIR / name).read_text(encoding="utf-8"))
    problems = analyse(queries)
    assert not problems, f"{name}: {problems[:2]}"


@pytest.mark.parametrize("name", sorted(RULES))
def test_rule_event_ids_agree_with_its_category(name):
    category = RULES[name]["logsource"].get("category")
    if category is None:
        return
    allowed = CATEGORY_EVENTS[category]
    for q in convert((RULES_DIR / name).read_text(encoding="utf-8")):
        for conj in _dnf(_parse(q)):
            assert _positive_codes(conj) <= allowed, f"{name}: {q}"


def test_guard_catches_the_b4_failure_modes():
    # registry branch ANDed with process creation (5c8ea8be as shipped before the fix)
    impossible = "event.code:1 AND ((event.code:1 AND process.name:a) OR (event.code:13 AND registry.key:*x*))"
    assert any("event.code" in p for p, _ in analyse([impossible]))
    # event 13 with process.command_line / parent fields (dead filter)
    dead = "event.code:13 AND registry.key:*x* AND (NOT (process.parent.name:a AND process.command_line:*b*))"
    assert any("do not exist on Sysmon event 13" in p for p, _ in analyse([dead]))
    # DNS event with command line
    assert analyse(["event.code:22 AND NOT process.command_line:*NlaSvc*"])
    # sane rules pass
    assert analyse(["event.code:1 AND process.command_line:*x* AND NOT winlog.event_data.IntegrityLevel:System"]) == []


# --------------------------------------------------------------------------
# Event fixtures
# --------------------------------------------------------------------------
def _load_fixtures():
    out = {}
    for p in sorted(EVENTS_DIR.glob("*.yml")):
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert data["id"] not in out, f"duplicate fixture for {data['id']}"
        out[data["id"]] = (p.name, data)
    return out


FIXTURES = _load_fixtures()
BY_ID = {r["id"]: (n, r) for n, r in RULES.items()}

# Every rule changed in the review-B pass, or flagged by review B.
REVIEWED_IDS = {
    "5c8ea8be-7a0e-4809-b65a-2d26f91ee077",  # sdbinst -m -bg (process half)
    "132c70fd-1074-4d10-a9f5-cd1be4e40ef6",  # new: AppCompatFlags shim registration (registry half)
    "d54e55da-9600-4e18-92a2-25a442b3efab",  # was T1547.001 run keys; deprecated duplicate
    "9d19c38d-a376-4e18-a517-db535a8322be",  # was T1218.011; deprecated duplicate
    "63a6f63d-043a-4ddc-9f24-febd436a77f5",  # was T1574.010
    "c27fffce-2372-458e-ae4b-4f247823dc2c",  # any sdbinst
    "575160f3-5822-495e-afce-54fee80dca9a",  # registry write to SdbUpdates
    "1020dcc4-0817-41c0-ba1e-7d3034e816c6",  # T1016 NCSI DNS
    "28a2bef3-af7f-4b3a-8e7f-08616e25b694",  # T1059.001 download
    "0d36e12f-4b63-4cf0-8483-8552b1d57090",  # T1033
    "446e7f75-e0c5-48f7-a701-807d8b0a481c",  # was T1057; deprecated
    "1457a8cc-0e8f-4a18-ae3c-1ee41e4bb8c6",  # was T1087.001; deprecated
    "61399e8c-6e6d-46d7-8257-ada4b2f3ea76",  # was T1482; deprecated
    "b8ee8991-c2af-4d5e-9dd8-4702f01a2e14",  # was T1216
    "c1ced7af-9d77-402a-aebd-b93426ebec3a",  # T1218.007
    "b8765da9-bc02-4c22-8b48-01096420d98a",  # was T1614.001
    "831565f9-d936-4dcc-abaf-0112e0cb5bb4",  # was T1555.004
    "3f9a6b93-3242-4661-b8bc-e6871b802615",  # was T1046
    "a4a0b85e-6503-452f-8506-f9c30505ce72",  # T1021.002
    "6d060b71-5faf-425c-bf21-bb7751cc0e83",  # T1035/T1569.002
    "723b2878-ced4-4052-ab1c-05629a5f4127",  # T1048.003
    "9aa53a2b-66bc-4f8d-a40f-b6962cf9c927",  # T1053.005
    "73cfc61f-1ee0-4dcc-ad78-edb3fda1ed6c",  # T1036.005
    "0acbfe83-9428-4eda-8c9c-6482e4d60c0a",  # T1112
    "57053051-8d37-43fc-b572-c3c2c320da81",  # was T1564.001; deprecated
    "c17705f9-58e7-4834-a3fb-8eba1da3b0b0",  # T1055 simulation signature
    "77ecdffa-3fa9-462a-a86d-ea87e42455d0",  # T1110.001 simulation signature
    "27b56c7b-ad80-4099-8416-bdb353facd67",  # T1204.002 simulation signature
    "40c64994-869e-4907-967b-6ff05bd0f8d8",  # T1012 simulation signature
}


def test_every_reviewed_rule_has_a_positive_and_a_negative_event():
    missing = sorted(REVIEWED_IDS - set(FIXTURES))
    assert not missing, f"no event fixtures for {missing}"
    for rid in REVIEWED_IDS:
        _, data = FIXTURES[rid]
        assert data.get("positive"), f"{rid}: needs >=1 positive event"
        assert data.get("negative"), f"{rid}: needs >=1 negative event"


def test_fixtures_reference_existing_rules():
    assert set(FIXTURES) <= set(BY_ID), sorted(set(FIXTURES) - set(BY_ID))


def _cases():
    for rid, (fname, data) in sorted(FIXTURES.items()):
        for kind, expect in (("positive", True), ("negative", False)):
            for case in data.get(kind) or []:
                yield pytest.param(rid, case["event"], expect,
                                   id=f"{fname[:-4]}:{kind}:{case['name']}")


@pytest.mark.parametrize("rid,event,expect", list(_cases()))
def test_rule_event_behaviour(rid, event, expect):
    name, _ = BY_ID[rid]
    queries = convert((RULES_DIR / name).read_text(encoding="utf-8"))
    assert rule_matches(queries, event) is expect, (name, queries, event)


@pytest.mark.parametrize("rid,event,expect", list(_cases()))
def test_fixture_events_are_realistic_for_their_event_code(rid, event, expect):
    code = str(event["event.code"])
    bad = sorted(set(event) - SYSMON_EVENT_FIELDS[code] - _COMMON)
    assert not bad, f"{rid}: fixture uses fields absent on Sysmon event {code}: {bad}"


def test_fixture_ids_unique_and_file_named_after_rule_id():
    for rid, (fname, _) in FIXTURES.items():
        assert fname.startswith(rid[:8]), fname
