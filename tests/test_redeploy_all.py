"""Behavioural tests for tools/redeploy_all.py. `responses` only, no network."""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import responses

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import deploy_rule  # noqa: E402
from lab.config import Settings  # noqa: E402
from lab.kibana_rule import ENGINE_OWNED_FIELDS, build_payload  # noqa: E402
from tools import redeploy_all as ra  # noqa: E402

BASE = "https://kibana.test:5601"
URL = BASE + "/api/detection_engine/rules"
FIND = URL + "/_find"
KEY = "super-secret-key-123"
AUTHOR = "Jahsean Meikle"


def rid(n):
    return f"{n:08d}-0000-4000-8000-000000000000"


def rule_text(n, tags=("attack.execution", "attack.t1059.001"), status="test", image="powershell.exe",
              author=AUTHOR, title=None):
    tag_lines = "\n".join(f"    - {t}" for t in tags)
    return f"""title: {title or 'Rule %d' % n}
id: {rid(n)}
status: {status}
description: test
author: {author}
date: 2026/01/01
tags:
{tag_lines}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\{image}'
    condition: selection
falsepositives:
    - admin
level: medium
"""


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")
    monkeypatch.setenv("KIBANA_URL", BASE)
    monkeypatch.setenv("ELASTIC_API_KEY", KEY)
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)


@pytest.fixture
def rules(tmp_path):
    d = tmp_path / "sigma"
    d.mkdir()
    return d


def put(rules, name, text):
    (rules / name).write_text(text, encoding="utf-8")
    return str(rules / name)


def settings():
    return Settings(elastic_url="https://es.test:9200", kibana_url=BASE, verify_tls=True,
                    elastic_api_key=KEY)


def kibana_copy(path, **over):
    """What Kibana would hold for this file if it were deployed from it, plus analyst work."""
    meta = deploy_rule.load_rule_metadata(path)
    payload = build_payload(meta, deploy_rule.convert_sigma(path), meta["author"])
    body = dict(payload)
    body.update(enabled=True, exceptions_list=[{"id": "ex"}], actions=[{"id": "a"}], note="analyst",
                id="kibana-internal-id")
    body.update(over)
    return body


def get_rule(rule_id, body=None, status=200):
    responses.add(responses.GET, URL, json=body if body is not None else {"message": "nf"}, status=status,
                  match=[responses.matchers.query_param_matcher({"rule_id": rule_id})])


def find(data=(), total=None):
    responses.add(responses.GET, FIND, json={"data": list(data), "page": 1, "per_page": 100,
                                             "total": len(data) if total is None else total})


def by_id(plan):
    return {e["rule_id"]: e for e in plan["plan"]}


def plan_of(rules, allow=()):
    return ra.build_plan(str(rules), settings(), ra.ReadOnlySession(ra.make_session()), set(allow))


def writes():
    return [c for c in responses.calls if c.request.method in ("POST", "PATCH", "PUT", "DELETE")]


# ---------------------------------------------------------------- classification matrix

@responses.activate
def test_create_when_not_in_kibana(rules):
    put(rules, "a.yml", rule_text(1))
    get_rule(rid(1), status=404)
    find()
    e = by_id(plan_of(rules))[rid(1)]
    assert e["action"] == "CREATE"


@responses.activate
def test_update_shows_query_length_and_differing_fields(rules):
    p = put(rules, "a.yml", rule_text(1))
    body = kibana_copy(p, query="short", severity="low")
    get_rule(rid(1), body)
    find()
    e = by_id(plan_of(rules))[rid(1)]
    assert e["action"] == "UPDATE"
    assert e["diff"]["query_len"]["old"] == 5
    assert e["diff"]["query_len"]["new"] > 5
    assert set(e["diff"]["fields"]) == {"query", "severity"}
    assert "5->" in e["detail"]


@responses.activate
def test_unchanged_ignores_analyst_fields_and_list_order(rules):
    p = put(rules, "a.yml", rule_text(1))
    body = kibana_copy(p)
    body["tags"] = list(reversed(body["tags"]))
    get_rule(rid(1), body)
    find()
    assert by_id(plan_of(rules))[rid(1)]["action"] == "UNCHANGED"


@responses.activate
def test_deprecated_enabled_is_disable(rules):
    put(rules, "a.yml", rule_text(1, status="deprecated"))
    get_rule(rid(1), {"rule_id": rid(1), "enabled": True, "tags": []})
    find()
    assert by_id(plan_of(rules))[rid(1)]["action"] == "DISABLE"


@responses.activate
def test_deprecated_absent_or_disabled_is_noop(rules):
    put(rules, "a.yml", rule_text(1, status="deprecated"))
    put(rules, "b.yml", rule_text(2, status="deprecated"))
    get_rule(rid(1), status=404)
    get_rule(rid(2), {"rule_id": rid(2), "enabled": False})
    find()
    got = by_id(plan_of(rules))
    assert got[rid(1)]["action"] == "NOOP-DEPRECATED"
    assert got[rid(2)]["action"] == "NOOP-DEPRECATED"


@responses.activate
def test_retag_needed_when_no_shared_lineage(rules):
    p = put(rules, "a.yml", rule_text(1, tags=("attack.discovery", "attack.t1082")))
    get_rule(rid(1), kibana_copy(p, tags=["attack.execution", "attack.t1059.001"], query="old"))
    find()
    e = by_id(plan_of(rules))[rid(1)]
    assert e["action"] == "RETAG-NEEDED" and e["approved"] is False
    e = by_id(plan_of(rules, allow=[rid(1)]))[rid(1)]
    assert e["action"] == "RETAG-NEEDED" and e["approved"] is True


@responses.activate
def test_subtechnique_move_is_plain_update_not_retag(rules):
    p = put(rules, "a.yml", rule_text(1, tags=("attack.execution", "attack.t1059.001")))
    get_rule(rid(1), kibana_copy(p, tags=["attack.execution", "attack.t1059"], query="old"))
    find()
    assert by_id(plan_of(rules))[rid(1)]["action"] == "UPDATE"


@responses.activate
def test_errors_conversion_http_missing_id_and_bad_yaml(rules):
    put(rules, "a_unconvertible.yml", rule_text(1).replace("category: process_creation", "category: nonexistent_zz"))
    put(rules, "b_http.yml", rule_text(2))
    put(rules, "c_noid.yml", "title: x\nstatus: test\n")
    put(rules, "d_notmap.yml", "- a\n- b\n")
    get_rule(rid(2), {"message": "boom"}, status=500)
    find()
    plan = plan_of(rules)
    acts = {e["file"]: e["action"] for e in plan["plan"]}
    assert acts == {"a_unconvertible.yml": "ERROR", "b_http.yml": "ERROR",
                    "c_noid.yml": "ERROR", "d_notmap.yml": "ERROR"}
    assert all(e["detail"] for e in plan["plan"])


@responses.activate
def test_different_rule_id_returned_is_error(rules):
    p = put(rules, "a.yml", rule_text(1))
    get_rule(rid(1), kibana_copy(p, rule_id=rid(9)))
    find()
    assert by_id(plan_of(rules))[rid(1)]["action"] == "ERROR"


# ---------------------------------------------------------------- orphans

@responses.activate
def test_orphans_reported_with_safe_identification_and_never_deleted(rules, tmp_path, capsys):
    put(rules, "a.yml", rule_text(1))
    get_rule(rid(1), status=404)
    shipped = {"rule_id": rid(1), "name": "s", "tags": ["attack.t1059"], "author": [AUTHOR]}
    orphan = {"rule_id": rid(50), "name": "gone", "tags": ["attack.t1059"], "author": [AUTHOR]}
    other_author = {"rule_id": rid(51), "name": "elastic prebuilt", "tags": ["attack.t1059"], "author": ["Elastic"]}
    no_attack = {"rule_id": rid(52), "name": "x", "tags": ["foo"], "author": [AUTHOR]}
    not_uuid = {"rule_id": "custom-name", "name": "y", "tags": ["attack.t1059"], "author": [AUTHOR]}
    find([shipped, orphan, other_author, no_attack, not_uuid])
    report = tmp_path / "r.json"
    code = ra.main(["--rules-dir", str(rules), "--report", str(report)])
    data = json.loads(report.read_text())
    assert [o["rule_id"] for o in data["orphans"]] == [rid(50)]
    assert not [c for c in responses.calls if c.request.method == "DELETE"]
    assert rid(50) in capsys.readouterr().out
    assert code == 0


@responses.activate
def test_orphan_scan_pages_through_find(rules):
    put(rules, "a.yml", rule_text(1))
    get_rule(rid(1), status=404)
    page1 = [{"rule_id": rid(60 + i), "tags": ["attack.t1059"], "author": [AUTHOR]} for i in range(2)]
    page2 = [{"rule_id": rid(70), "tags": ["attack.t1059"], "author": [AUTHOR]}]
    responses.add(responses.GET, FIND, json={"data": page1, "page": 1, "per_page": 2, "total": 3})
    responses.add(responses.GET, FIND, json={"data": page2, "page": 2, "per_page": 2, "total": 3})
    plan = plan_of(rules)
    assert [o["rule_id"] for o in plan["orphans"]] == [rid(60), rid(61), rid(70)]


@responses.activate
def test_orphan_scan_failure_is_not_fatal(rules):
    put(rules, "a.yml", rule_text(1))
    get_rule(rid(1), status=404)
    responses.add(responses.GET, FIND, json={}, status=500)
    plan = plan_of(rules)
    assert plan["orphans"] == [] and plan["orphans_error"]


# ---------------------------------------------------------------- dry run

@responses.activate
def test_dry_run_makes_zero_write_calls(rules, tmp_path):
    p1 = put(rules, "a.yml", rule_text(1))
    put(rules, "b.yml", rule_text(2))
    put(rules, "c.yml", rule_text(3, status="deprecated"))
    get_rule(rid(1), kibana_copy(p1, query="old"))
    get_rule(rid(2), status=404)
    get_rule(rid(3), {"rule_id": rid(3), "enabled": True})
    find()
    for m in (responses.POST, responses.PATCH, responses.PUT, responses.DELETE):
        responses.add(m, URL, json={}, status=200)
    code = ra.main(["--rules-dir", str(rules), "--report", str(tmp_path / "r.json")])
    assert code == 0
    assert writes() == []
    assert json.loads((tmp_path / "r.json").read_text())["mode"] == "dry-run"


def test_read_only_session_blocks_writes():
    s = ra.ReadOnlySession(object())
    for m in ("post", "patch", "put", "delete", "request"):
        with pytest.raises(RuntimeError):
            getattr(s, m)("http://x")


# ---------------------------------------------------------------- apply

def _setup_matrix(rules):
    """create, update, unchanged, disable, noop, retag(blocked)."""
    p_up = put(rules, "02_update.yml", rule_text(2))
    p_un = put(rules, "03_same.yml", rule_text(3))
    p_rt = put(rules, "06_retag.yml", rule_text(6, tags=("attack.discovery", "attack.t1082")))
    put(rules, "01_create.yml", rule_text(1))
    put(rules, "04_dep.yml", rule_text(4, status="deprecated"))
    put(rules, "05_dep_gone.yml", rule_text(5, status="deprecated"))
    get_rule(rid(1), status=404)
    get_rule(rid(2), kibana_copy(p_up, query="old"))
    get_rule(rid(3), kibana_copy(p_un))
    get_rule(rid(4), {"rule_id": rid(4), "enabled": True})
    get_rule(rid(5), status=404)
    get_rule(rid(6), kibana_copy(p_rt, tags=["attack.execution", "attack.t1059"], query="old"))
    find()
    return p_up


@responses.activate
def test_apply_performs_exactly_planned_calls_and_preserves_analyst_fields(rules, tmp_path, capsys):
    _setup_matrix(rules)
    # create
    responses.add(responses.POST, URL, json={"id": "x"}, status=200,
                  match=[responses.matchers.json_params_matcher({"rule_id": rid(1)}, strict_match=False)])
    # update: POST -> 409
    responses.add(responses.POST, URL, json={"m": "exists"}, status=409,
                  match=[responses.matchers.json_params_matcher({"rule_id": rid(2)}, strict_match=False)])
    responses.add(responses.PATCH, URL, json={}, status=200)
    sleeps = []
    report = tmp_path / "r.json"
    code = ra.main(["--rules-dir", str(rules), "--apply", "--yes", "--report", str(report), "--delay", "0.5"],
                   sleep=sleeps.append)
    w = [(c.request.method, json.loads(c.request.body)) for c in writes()]
    posts = [b["rule_id"] for m, b in w if m == "POST"]
    patches = {b["rule_id"]: b for m, b in w if m == "PATCH"}
    assert sorted(posts) == [rid(1), rid(2)]          # create + the update's initial POST (409)
    assert set(patches) == {rid(2), rid(4)}            # update + disable only
    assert patches[rid(4)] == {"rule_id": rid(4), "enabled": False}
    for forbidden in ("enabled", "exceptions_list", "actions", "note", "id", "version"):
        assert forbidden not in patches[rid(2)]
    assert set(patches[rid(2)]) <= set(ENGINE_OWNED_FIELDS) | {"rule_id"}
    assert not [c for c in responses.calls if c.request.method in ("PUT", "DELETE")]
    assert sleeps == [0.5, 0.5, 0.5]                   # one polite pause per write action
    data = json.loads(report.read_text())
    assert data["mode"] == "apply"
    res = {e["rule_id"]: e.get("result") for e in data["plan"]}
    assert res[rid(1)] == res[rid(2)] == res[rid(4)] == "ok"
    assert res[rid(3)] is None and res[rid(6)] is None
    assert code == 1                                   # blocked retag remained
    assert "RETAG-NEEDED" in capsys.readouterr().out


@responses.activate
def test_failing_rule_does_not_stop_others_and_exit_nonzero(rules):
    put(rules, "a.yml", rule_text(1))
    put(rules, "b.yml", rule_text(2))
    get_rule(rid(1), status=404)
    get_rule(rid(2), status=404)
    find()
    responses.add(responses.POST, URL, json={"message": "bad"}, status=500,
                  match=[responses.matchers.json_params_matcher({"rule_id": rid(1)}, strict_match=False)])
    responses.add(responses.POST, URL, json={}, status=200,
                  match=[responses.matchers.json_params_matcher({"rule_id": rid(2)}, strict_match=False)])
    code = ra.main(["--rules-dir", str(rules), "--apply", "--yes", "--delay", "0"], sleep=lambda s: None)
    assert [json.loads(c.request.body)["rule_id"] for c in writes()] == [rid(1), rid(2)]
    assert code == 1


@responses.activate
def test_allow_retag_only_for_named_ids(rules, tmp_path):
    ps = []
    for n in (1, 2):
        p = put(rules, f"{n}.yml", rule_text(n, tags=("attack.discovery", "attack.t1082")))
        get_rule(rid(n), kibana_copy(p, tags=["attack.execution", "attack.t1059"], query="old"))
        ps.append(p)
    find()
    responses.add(responses.POST, URL, json={"m": "exists"}, status=409)
    responses.add(responses.PATCH, URL, json={}, status=200)
    code = ra.main(["--rules-dir", str(rules), "--apply", "--yes", "--allow-retag", rid(1), "--delay", "0"],
                   sleep=lambda s: None)
    patched = [json.loads(c.request.body)["rule_id"] for c in writes() if c.request.method == "PATCH"]
    assert patched == [rid(1)]
    assert code == 1  # rid(2) remained unapproved


@responses.activate
def test_all_retags_approved_and_clean_run_exits_zero(rules):
    p = put(rules, "1.yml", rule_text(1, tags=("attack.discovery", "attack.t1082")))
    get_rule(rid(1), kibana_copy(p, tags=["attack.execution", "attack.t1059"], query="old"))
    find()
    responses.add(responses.POST, URL, json={"m": "exists"}, status=409)
    responses.add(responses.PATCH, URL, json={}, status=200)
    code = ra.main(["--rules-dir", str(rules), "--apply", "--yes", "--allow-retag", rid(1)], sleep=lambda s: None)
    assert code == 0


# ---------------------------------------------------------------- safety / config / output

@responses.activate
def test_apply_without_yes_non_interactive_exits_2_and_touches_nothing(rules, monkeypatch):
    put(rules, "a.yml", rule_text(1))
    class NoTty:
        def isatty(self):
            return False
    code = ra.main(["--rules-dir", str(rules), "--apply"], stdin=NoTty())
    assert code == 2
    assert len(responses.calls) == 0


@responses.activate
def test_interactive_confirmation_yes_and_no(rules):
    put(rules, "a.yml", rule_text(1))
    get_rule(rid(1), status=404)
    find()
    responses.add(responses.POST, URL, json={}, status=200)
    class Tty:
        def isatty(self):
            return True
    assert ra.main(["--rules-dir", str(rules), "--apply"], stdin=Tty(), ask=lambda p: "no",
                   sleep=lambda s: None) == 2
    assert writes() == []
    assert ra.main(["--rules-dir", str(rules), "--apply"], stdin=Tty(), ask=lambda p: "yes",
                   sleep=lambda s: None) == 0
    assert len(writes()) == 1


@pytest.mark.parametrize("missing", ["ELASTIC_API_KEY", "KIBANA_URL", "ELASTIC_URL"])
@responses.activate
def test_refuses_when_config_missing(rules, monkeypatch, capsys, missing):
    put(rules, "a.yml", rule_text(1))
    monkeypatch.delenv(missing)
    if missing == "ELASTIC_URL":
        monkeypatch.delenv("KIBANA_URL")
    code = ra.main(["--rules-dir", str(rules)])
    assert code == 2
    assert len(responses.calls) == 0
    assert "FAIL" in capsys.readouterr().err


@responses.activate
def test_report_schema_and_no_api_key_anywhere(rules, tmp_path, capsys):
    put(rules, "a.yml", rule_text(1))
    put(rules, "b.yml", rule_text(2).replace("category: process_creation", "category: nonexistent_zz"))
    get_rule(rid(1), status=404)
    find()
    report = tmp_path / "r.json"
    ra.main(["--rules-dir", str(rules), "--report", str(report)])
    out = capsys.readouterr()
    text = report.read_text()
    assert KEY not in out.out and KEY not in out.err and KEY not in text
    data = json.loads(text)
    assert set(data) >= {"mode", "generated_at", "rules_dir", "summary", "plan", "orphans", "orphans_error"}
    assert set(data["summary"]) >= set(ra.ACTIONS)
    assert data["summary"]["CREATE"] == 1 and data["summary"]["ERROR"] == 1
    for e in data["plan"]:
        assert {"file", "rule_id", "action", "detail"} <= set(e)


@responses.activate
def test_order_is_deterministic_by_filename(rules):
    for name, n in (("z.yml", 1), ("B.yml", 2), ("a.yml", 3), ("m.yml", 4)):
        put(rules, name, rule_text(n))
        get_rule(rid(n), status=404)
    find()
    files = [e["file"] for e in plan_of(rules)["plan"]]
    assert files == sorted(files)
    gets = [c.request.url for c in responses.calls if "rule_id=" in c.request.url]
    assert [re.search(r"rule_id=([^&]+)", u).group(1) for u in gets] == [rid(n) for n in (2, 3, 4, 1)]


def test_summary_table_counts(capsys):
    plan = {"plan": [{"action": "CREATE"}, {"action": "CREATE"}, {"action": "ERROR"}]}
    counts = ra.summarize(plan["plan"])
    assert counts["CREATE"] == 2 and counts["ERROR"] == 1 and counts["UPDATE"] == 0


# ---------------------------------------------------------------- --suggest-retags

def _git(repo, *a):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a], cwd=repo,
                   check=True, capture_output=True)


def test_suggest_retags_lists_changed_technique_tags(tmp_path, capsys):
    repo = tmp_path / "repo"
    sig = repo / "detections" / "sigma"
    sig.mkdir(parents=True)
    _git(repo, "init", "-q")
    (sig / "a.yml").write_text(rule_text(1, tags=("attack.execution", "attack.t1059.001")))
    (sig / "b.yml").write_text(rule_text(2, tags=("attack.discovery", "attack.t1082")))
    (sig / "c.yml").write_text(rule_text(3, tags=("attack.discovery", "attack.t1016")))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    (sig / "a.yml").write_text(rule_text(1, tags=("attack.discovery", "attack.t1082")))      # disjoint
    (sig / "b.yml").write_text(rule_text(2, tags=("attack.discovery", "attack.t1082.001")))  # same lineage
    _git(repo, "commit", "-qam", "retag")
    code = ra.main(["--suggest-retags", "--since", base, "--repo-dir", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert rid(1) in out and "attack.t1059.001" in out and "attack.t1082" in out
    assert "--allow-retag" in out
    line_a = [l for l in out.splitlines() if rid(1) in l][0]
    line_b = [l for l in out.splitlines() if rid(2) in l][0]
    assert "NEEDS-ALLOW-RETAG" in line_a and "NEEDS-ALLOW-RETAG" not in line_b
    assert rid(3) not in out


def test_suggest_retags_needs_no_credentials(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ELASTIC_API_KEY")
    repo = tmp_path / "repo"
    (repo / "detections" / "sigma").mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "detections" / "sigma" / "a.yml").write_text(rule_text(1))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "x")
    assert ra.main(["--suggest-retags", "--since", "HEAD", "--repo-dir", str(repo)]) == 0
