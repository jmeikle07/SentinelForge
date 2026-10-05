"""Behavioural tests for the inline page scripts, run under Node against a stub DOM and a fake fetch.
Skipped when Node is not installed. They exercise the real script text of each page; what they cannot
show is layout, CSS, focus handling or real browser APIs (no browser is available offline)."""
import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

HARNESS = textwrap.dedent(r"""
    const fs = require('fs'), vm = require('vm');
    const [, pagePath, scenarioJson, action] = process.argv;
    const scenario = JSON.parse(scenarioJson);
    const html = fs.readFileSync(pagePath, 'utf8');
    const script = html.split('<script>')[1].split('</script>')[0];

    const elements = {};
    function mk(name) {
      const store = {};
      const fn = function () { return mk(name + '()'); };
      return new Proxy(fn, {
        get(t, p) {
          if (p === Symbol.toPrimitive) return () => '';
          if (p === 'then') return undefined;
          if (p in store) return store[p];
          if (p === 'innerHTML' || p === 'textContent' || p === 'value') return '';
          if (p === 'style') { store.style = {}; return store.style; }
          if (p === 'dataset') { store.dataset = {}; return store.dataset; }
          return mk(name + '.' + String(p));
        },
        set(t, p, v) { store[p] = v; return true; },
        apply() { return mk(name + '()'); },
      });
    }
    global.document = {
      getElementById(id) { return elements[id] || (elements[id] = mk('#' + id)); },
      querySelector() { return mk('qs'); },
      querySelectorAll() { return []; },
      addEventListener() {}, body: mk('body'),
    };
    global.window = global;
    global.requestAnimationFrame = () => 0;
    global.setTimeout = () => 0;
    global.sessionStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
    global.performance = { now: () => 0 };
    const calls = [];
    global.fetch = async (url, opts) => {
      calls.push({ url, opts: opts || null });
      const r = scenario.fetch[url] || scenario.fetch['*'];
      if (r.throw) throw new Error(r.throw);
      return {
        ok: r.status >= 200 && r.status < 300, status: r.status,
        headers: { get: (h) => (r.headers || {})[h] ?? null },
        json: async () => { if (r.text !== undefined) throw new SyntaxError('not json'); return r.body; },
        text: async () => (r.text !== undefined ? r.text : JSON.stringify(r.body)),
      };
    };
    global.elements = elements; global.calls = calls; global.result = {};
    global.settle = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)); };
    vm.runInThisContext(script);
    vm.runInThisContext('(async () => {' + action + '})()').then(
      () => { console.log(JSON.stringify(result)); },
      (e) => { console.log(JSON.stringify({ harness_error: String(e && e.stack || e) })); process.exit(0); });
""")


def run_page(page, fetch, action):
    r = subprocess.run([NODE, "-e", HARNESS, str(ROOT / "web" / page), json.dumps({"fetch": fetch}), action],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert "harness_error" not in out, out["harness_error"]
    return out


HUNT_ACTION = """
    elements.ioc.value = '8.8.8.8';
    await run(); await settle();
    result.out = elements.out.innerHTML; result.calls = calls;
"""


# ── index.html: W23 + POST ───────────────────────────────────────────────────
def test_index_posts_json_and_never_puts_the_ioc_in_the_url():
    r = run_page("index.html", {"*": {"status": 400, "body": {"detail": "x"}}}, HUNT_ACTION)
    call = r["calls"][0]
    assert call["url"] == "/api/hunt" and call["opts"]["method"] == "POST"
    assert json.loads(call["opts"]["body"]) == {"ioc": "8.8.8.8"}
    assert "json" in call["opts"]["headers"]["Content-Type"]


@pytest.mark.parametrize("status,body,headers,expect", [
    (429, {"detail": "rate limit exceeded"}, {"Retry-After": "42"}, ["too many", "42"]),
    (400, {"detail": "non-public address or internal hostname: not sent"}, {}, ["non-public address"]),
    (422, {"detail": [{"msg": "Field required"}]}, {}, ["doesn", "check"]),
    (500, None, {}, ["500", "server"]),
    (503, {"detail": "state unavailable"}, {}, ["503"]),
    (404, None, {}, ["404"]),
])
def test_index_shows_a_useful_error_for_every_failure_status(status, body, headers, expect):
    resp = {"status": status, "headers": headers}
    if body is None:
        resp["text"] = "<html>Internal Server Error</html>"
    else:
        resp["body"] = body
    out = run_page("index.html", {"*": resp}, HUNT_ACTION)["out"]
    low = out.lower()
    assert 'class="err"' in out, out
    for frag in expect:
        assert frag.lower() in low, (frag, out)
    assert "<html>" not in out                        # raw server text is never injected unescaped
    assert "undefined" not in low and "[object" not in low


def test_index_error_detail_is_escaped():
    out = run_page("index.html", {"*": {"status": 400, "body": {"detail": "<img src=x onerror=alert(1)>"}}},
                   HUNT_ACTION)["out"]
    assert "<img" not in out and "&lt;img" in out


def test_index_network_failure_is_reported():
    out = run_page("index.html", {"*": {"throw": "connection refused"}}, HUNT_ACTION)["out"]
    assert "Something went wrong" in out and "connection refused" in out


def test_index_insufficient_data_never_says_safe_to_allow():
    body = {"ioc": "8.8.8.8", "ioc_type": "ipv4", "supported": True, "external": {},
            "verdict": {"verdict": "unknown", "action": "INSUFFICIENT DATA", "score": 0,
                        "insufficient_data": True, "floors_applied": []}}
    out = run_page("index.html", {"*": {"status": 200, "body": body}}, HUNT_ACTION)["out"]
    assert "not enough data" in out.lower() and "safe to allow" not in out.lower()


def test_index_benign_verdict_renders_normally():
    body = {"ioc": "8.8.8.8", "ioc_type": "ipv4", "supported": True, "external": {},
            "verdict": {"verdict": "benign", "action": "IGNORE", "score": 3, "floors_applied": []}}
    out = run_page("index.html", {"*": {"status": 200, "body": body}}, HUNT_ACTION)["out"]
    assert "safe to allow" in out.lower()


# ── review.html: W7 ──────────────────────────────────────────────────────────
LOAD_ACTION = "await load(); await settle(); result.queue = elements.queue.innerHTML;"


def test_review_corrupt_state_shows_an_error_not_all_clear():
    r = run_page("review.html", {"*": {"status": 503, "body": {"detail": "pending_rules.json is corrupt and was quarantined"}}},
                 LOAD_ACTION)
    assert "All clear" not in r["queue"]
    assert "pending_rules.json is corrupt" in r["queue"] and "Could not load" in r["queue"]


def test_review_empty_queue_is_all_clear_only_on_a_real_200():
    r = run_page("review.html", {"*": {"status": 200, "body": {"pending": []}}}, LOAD_ACTION)
    assert "All clear" in r["queue"]


def test_review_unexpected_200_body_is_not_all_clear():
    r = run_page("review.html", {"*": {"status": 200, "body": {"oops": 1}}}, LOAD_ACTION)
    assert "All clear" not in r["queue"] and "unexpected" in r["queue"].lower()


def test_review_network_failure_is_reported_not_all_clear():
    r = run_page("review.html", {"*": {"throw": "offline"}}, LOAD_ACTION)
    assert "Could not load" in r["queue"] and "All clear" not in r["queue"]


@pytest.mark.parametrize("status,headers,expect", [
    (429, {"Retry-After": "120"}, ["too many", "120"]),
    (403, {}, ["403"]),
    (401, {}, ["401"]),
])
def test_review_approve_failures_are_explained(status, headers, expect):
    action = """
        global._pending = {id: 'abc', kind: 'approve', name: 'n'};
        _memToken = 'tok';
        await fire(); await settle();
        result.flash = elements.flash.textContent;
    """
    # `_pending` is a `let` in the page script: assign through the page's own scope
    action = action.replace("global._pending = {id: 'abc', kind: 'approve', name: 'n'};",
                            "_pending = {id: 'abc', kind: 'approve', name: 'n'};")
    r = run_page("review.html", {"*": {"status": status, "headers": headers,
                                       "body": {"detail": "server says no"}}}, action)
    low = r["flash"].lower()
    for frag in expect:
        assert frag in low, r["flash"]


# ── engine.html: W22 ─────────────────────────────────────────────────────────
def _engine(**over):
    d = {"outcomes": {"deployed": 2}, "validations": None, "efficacy": None, "timeline": []}
    d.update(over)
    return d


ENGINE_ACTION = """
    await load(); await settle();
    result.decisions = elements.decisions.innerHTML;
    result.receipts = elements.receipts.innerHTML;
    result.efficacy = elements.efficacy.innerHTML;
"""


def _votes(*approvals, scores=None):
    names = ["Claude", "Gemini", "Ollama"]
    return {n: {"score": (scores or [7] * 3)[i], "approve": a} for i, (n, a) in enumerate(zip(names, approvals))}


def _rec(outcome, attempts, **kw):
    rec = {"title": "Rule A", "outcome": outcome, "final_attempt": len(attempts), "avg_score": 7.0,
           "backtest_hits": 51, "attempts": attempts, "healed": len(attempts) > 1}
    rec.update(kw)
    return rec


def test_engine_agreement_count_comes_from_the_record_not_a_constant():
    recs = [
        _rec("approved", [{"attempt": 1, "votes": _votes(True, True, True)}], title="Unanimous"),
        _rec("approved", [{"attempt": 1, "votes": _votes(True, True, False)}], title="TwoOfThree"),
        _rec("approved", [{"attempt": 1, "votes": _votes(True, True, True, )}], title="Another"),
    ]
    r = run_page("engine.html", {"*": {"status": 200, "body": _engine(validations=recs)}}, ENGINE_ACTION)
    txt = r["receipts"]
    assert txt.count("3 of 3 agreed") == 2 and txt.count("2 of 3 agreed") == 1


def test_engine_first_try_versus_rewritten_follows_the_outcome():
    first = _rec("approved", [{"attempt": 1, "votes": _votes(True, True, True)}], title="First")
    healed = _rec("approved", [{"attempt": 1, "votes": _votes(True, False, False)},
                               {"attempt": 2, "votes": _votes(True, True, True)}], title="Healed")
    failed = _rec("failed", [{"attempt": 1, "votes": _votes(True, False, False)},
                             {"attempt": 2, "votes": _votes(False, False, False)},
                             {"attempt": 3, "votes": _votes(True, False, False)}], title="Failed")
    r = run_page("engine.html", {"*": {"status": 200, "body": _engine(validations=[first, healed, failed])}},
                 ENGINE_ACTION)
    cards = r["receipts"].split('<div class="rcpt">')[1:]
    by_title = {("First" if "First" in c else "Healed" if "Healed" in c else "Failed"): c for c in cards}
    assert "passed first try" in by_title["First"]
    assert "rewritten, then passed" in by_title["Healed"]
    assert "passed first try" not in by_title["Failed"] and "then passed" not in by_title["Failed"]
    assert "did not pass" in by_title["Failed"]
    last_label = by_title["Failed"].split("attempt 3")[1].split("</div>")[0]
    assert "not approved" in last_label                       # the final attempt of a failed rule was not approved


def test_engine_decision_bars_account_for_every_run():
    outcomes = {"no_events": 175, "deployed": 41, "pending_review": 14, "hunt_triggered_pending_review": 7,
                "confidence_too_low": 5, "already_covered": 5, "hunt_triggered_generation_failed": 2}
    r = run_page("engine.html", {"*": {"status": 200, "body": _engine(outcomes=outcomes)}}, ENGINE_ACTION)
    html = r["decisions"]
    import re
    assert f"Out of {sum(outcomes.values())} runs" in html
    bars = [int(m) for m in re.findall(r'data-w="\d+">(\d+)</div>', html)]
    assert sorted(bars) == sorted(outcomes.values())            # no run is counted but not drawn
    assert sum(bars) == sum(outcomes.values())


def test_engine_unknown_outcome_is_still_drawn():
    r = run_page("engine.html", {"*": {"status": 200, "body": _engine(outcomes={"brand_new_state": 3, "deployed": 1})}},
                 ENGINE_ACTION)
    assert "Out of 4 runs" in r["decisions"] and ">3</div>" in r["decisions"]


def test_engine_load_failure_is_visible_in_every_panel_not_stuck_on_loading():
    r = run_page("engine.html", {"*": {"status": 503, "body": {"detail": "hunt_log.json is corrupt"}}},
                 ENGINE_ACTION)
    for panel in ("decisions", "receipts", "efficacy"):
        assert "loading…" not in r[panel].lower(), panel
        assert "hunt_log.json is corrupt" in r[panel], panel


def test_engine_network_failure_is_visible():
    r = run_page("engine.html", {"*": {"throw": "offline"}}, ENGINE_ACTION)
    assert "Could not load" in r["decisions"] and "offline" in r["decisions"]


def test_engine_a_section_that_cannot_be_drawn_says_so_instead_of_staying_blank():
    bad = _engine(validations=[{"title": "x", "attempts": 5}], efficacy={"fired": 7})
    r = run_page("engine.html", {"*": {"status": 200, "body": bad}}, ENGINE_ACTION)
    assert "could not be drawn" in r["receipts"].lower()
    assert "loading…" not in r["receipts"].lower()
    assert "Out of" in r["decisions"]                          # the healthy panel still rendered
