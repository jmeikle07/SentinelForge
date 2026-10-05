import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sf_web

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["index.html", "review.html", "engine.html"]
BRANDED_FILES = [ROOT / "web" / p for p in PAGES] + [ROOT / "topology.svg", ROOT / "docs" / "coverage_layer.json"]
LEGACY = re.compile(r"1x" r"lozec|tall\s?kitchen|hunt-and-water|al" r"bundy|\bwater\b|tk" r"-hunt", re.I)


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.fixture
def client():
    return TestClient(sf_web.app)


@pytest.mark.parametrize("page", PAGES)
def test_page_title_has_brand(page):
    m = re.search(r"<title>(.*?)</title>", _read(f"web/{page}"), re.S)
    assert m and "SentinelForge" in m.group(1)


@pytest.mark.parametrize("page", PAGES)
def test_page_has_brand_element_and_landmarks(page):
    html = _read(f"web/{page}")
    assert re.search(r'class="brand"[^>]*>[^<]*(<[^>]+>[^<]*)*SentinelForge', html)
    assert "<main" in html and "<header" in html and "<footer" in html
    assert 'lang="en"' in html


@pytest.mark.parametrize("page", PAGES)
def test_page_has_no_external_assets(page):
    html = _read(f"web/{page}")
    assert not re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", html, re.I)
    assert not re.search(r"@import|url\(\s*['\"]?(https?:)?//", html, re.I)
    assert "fonts.googleapis" not in html and "fonts.gstatic" not in html
    assert not re.search(r"""fetch\(\s*['"]https?://""", html)


@pytest.mark.parametrize("page", PAGES)
def test_page_has_focus_styles_and_reduced_motion(page):
    html = _read(f"web/{page}")
    assert ":focus-visible" in html
    assert "prefers-reduced-motion" in html


def test_review_sends_admin_token_from_session_storage_in_try():
    html = _read("web/review.html")
    assert "X-Admin-Token" in html
    assert "sessionStorage" in html
    for m in re.finditer(r"sessionStorage", html):
        before = html[: m.start()]
        assert before.rfind("try{") > before.rfind("}catch"), "sessionStorage use outside try"
    assert "localStorage" not in html
    assert not re.search(r"[?&]token=", html)
    # each refusal status is handled by an actual branch, not merely mentioned in a comment or text
    for status in (401, 403, 429):
        assert re.search(rf"resp\.status\s*===?\s*{status}\b", html), status
    assert re.search(r"headers:\s*\{\s*'X-Admin-Token'\s*:\s*getToken\(\)", html)


# ── static audit of HTML built in the page scripts ──────────────────────────
# Every operand glued into an HTML string must be provably text-safe: a literal, esc(...), a
# numeric coercion, a ternary of safe branches, or a variable whose EVERY assignment is itself safe.
# Anything else must be listed in AUDITED_SAFE by its exact expression text AND occurrence count, so
# a new use of the same expression (or an unreviewed one) fails instead of riding on a variable name.
SAFE_CALLS = {"esc", "Number", "parseInt", "parseFloat", "encodeURIComponent", "String(Number",
              "Math.round", "Math.floor", "Math.ceil", "Math.min", "Math.max", "Math.abs"}
AUDITED_SAFE = {
    "index.html": {   # operand text -> (occurrences, why it is safe)
        "acc": (1, "from the constant ACCENT table"),
        "accGlow": (1, "from the constant ACCENT table"),
        "info.led": (1, "srcInfo() returns literal class names"),
        "info.tag": (1, "srcInfo() returns literal class names"),
        "info.summary": (1, "srcInfo() builds it from literals and esc()"),
    },
    "review.html": {},
    "engine.html": {
        "buildDetail(n)": (1, "builds its HTML from the constant STEPS table through esc()"),
    },
}
AUDITED_SAFE["index.html"].update({
    "failureBox(r.status,data,r.headers.get('Retry-After'))": (1, "failureBox() escapes every part"),
    "failureBox(502,null,null)": (1, "failureBox() escapes every part"),
})

_PUNCT3 = ("===", "!==", "...")
_PUNCT2 = ("=>", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "++", "--", "?.")
_REGEX_PREV = set("(,=:[!&|?{};+") | {"return", None}


def _tokenize(src: str) -> list:
    toks, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
        elif src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            i = src.find("*/", i) + 2
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            toks.append(("S", src[i + 1:j]))
            i = j + 1
        elif c == "`":
            j = i + 1
            while j < n and src[j] != "`":
                j += 2 if src[j] == "\\" else 1
            toks.append(("T", src[i + 1:j]))
            i = j + 1
        elif c == "/" and (not toks or toks[-1][1] in _REGEX_PREV and toks[-1][0] in ("P", "I")):
            j, in_class = i + 1, False
            while j < n and (src[j] != "/" or in_class):
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            toks.append(("R", src[i:j]))
            i = j
        elif c.isalnum() or c in "_$":
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(("I", src[i:j]))
            i = j
        else:
            for op in _PUNCT3 + _PUNCT2:
                if src.startswith(op, i):
                    toks.append(("P", op))
                    i += len(op)
                    break
            else:
                toks.append(("P", c))
                i += 1
    return toks


_OPEN, _CLOSE = "([{", ")]}"
_KEYWORD_STOP = {"return", "case", "in", "of", "typeof", "else", "throw", "const", "let", "var"}
_STOP = {",", ";", ":", "?", "=>", "=", "+=", "-=", "||", "&&", "==", "===", "!=", "!==", "<", ">", "<=", ">="}


def _scan_operand(toks, start, step):
    """Index just past an operand beginning at `start`, scanning in direction `step`."""
    k, depth = start, 0
    opening, closing = (_OPEN, _CLOSE) if step > 0 else (_CLOSE, _OPEN)
    while 0 <= k < len(toks):
        kind, text = toks[k]
        if kind == "I" and depth == 0 and text in _KEYWORD_STOP:
            break
        if kind == "P":
            if text in opening:
                depth += 1
            elif text in closing:
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (text == "+" or text in _STOP):
                break
        k += step
    return k


def _chain(toks, i):
    """Operand token ranges of the '+' chain through the string literal at toks[i]."""
    ops = [(i, i + 1)]
    j = i + 1
    while j < len(toks) and toks[j] == ("P", "+"):
        k = _scan_operand(toks, j + 1, 1)
        ops.append((j + 1, k))
        j = k
    j = i - 1
    while j >= 0 and toks[j] == ("P", "+"):
        k = _scan_operand(toks, j - 1, -1)
        ops.insert(0, (k + 1, j))
        j = k
    return ops


def _text(toks) -> str:
    out = []
    for kind, text in toks:
        out.append(f"'{text}'" if kind == "S" else text)
    return "".join(out)


def _split_top(toks, seps):
    parts, cur, depth = [], [], 0
    for t in toks:
        if t[0] == "P" and t[1] in _OPEN:
            depth += 1
        elif t[0] == "P" and t[1] in _CLOSE:
            depth -= 1
        if depth == 0 and t[0] == "P" and t[1] in seps:
            parts.append(cur)
            cur = []
        else:
            cur.append(t)
    parts.append(cur)
    return parts


def _wrapped(toks) -> bool:
    if len(toks) < 2 or toks[0] != ("P", "(") or toks[-1] != ("P", ")"):
        return False
    depth = 0
    for idx, t in enumerate(toks):
        if t[0] == "P" and t[1] in _OPEN:
            depth += 1
        elif t[0] == "P" and t[1] in _CLOSE:
            depth -= 1
            if depth == 0 and idx < len(toks) - 1:
                return False
    return True


class _Audit:
    def __init__(self, script: str, audited=()):
        self.audited = set(audited)
        self.toks = _tokenize(script)
        self.assign = {}                       # identifier -> [token slices assigned to it]
        t = self.toks
        for i, (kind, name) in enumerate(t):
            if kind == "I" and i + 1 < len(t) and t[i + 1] in (("P", "="), ("P", "+=")):
                if i > 0 and t[i - 1] == ("P", "."):
                    continue
                end = _scan_operand_to_end(t, i + 2)
                self.assign.setdefault(name, []).append(t[i + 2:end])

    def safe(self, toks, seen=frozenset(), via_var=False) -> bool:
        if not toks:
            return True
        if via_var and _text(toks) in self.audited:     # already counted where it was first used
            return True
        if len(toks) == 1:
            kind, text = toks[0]
            if kind == "S":
                return True
            if kind == "T":
                return "${" not in text
            if kind == "I" and (text[0].isdigit() or text in ("true", "false", "null", "undefined")):
                return True
        if _wrapped(toks):
            return self.safe(toks[1:-1], seen, via_var)
        parts = _split_top(toks, {"||", "&&"})
        if len(parts) > 1:
            return all(self.safe(p, seen, via_var) for p in parts)
        q = _split_top(toks, {"?"})
        if len(q) > 1:                                   # cond ? a : b   (condition is not output)
            branches = _split_top(toks[len(q[0]) + 1:], {":"})
            return all(self.safe(b, seen, via_var) for b in branches)
        parts = _split_top(toks, {"+"})
        if len(parts) > 1:
            return all(self.safe(p, seen, via_var) for p in parts)
        if len(_split_top(toks, {"-", "*", "/", "%"})) > 1:     # arithmetic: always a number
            return True
        if toks[0] == ("P", "!"):
            return True
        # call whose parentheses span the rest of the operand
        for idx, tk in enumerate(toks):
            if tk == ("P", "(") and idx > 0 and _wrapped(toks[idx:]):
                name = _text(toks[:idx])
                if name in SAFE_CALLS or name.startswith("Number"):
                    return True
                if name.endswith(".toFixed"):
                    return True
                break
        if len(toks) >= 3 and toks[-2] == ("P", ".") and toks[-1] == ("I", "length"):
            return True
        if len(toks) == 1 and toks[0][0] == "I":
            name = toks[0][1]
            if name in seen or name not in self.assign:
                return False
            return all(self.safe(rhs, seen | {name}, True) for rhs in self.assign[name])
        return False

    def unsafe_operands(self) -> list:
        """Source text of every operand in an HTML-building concatenation, or on the right of an
        innerHTML assignment, that is not provably text-safe."""
        t, found, seen_ranges = self.toks, [], set()

        def check(a, b):
            if (a, b) in seen_ranges:
                return
            seen_ranges.add((a, b))
            if not self.safe(t[a:b]):
                found.append(_text(t[a:b]))

        for i, (kind, text) in enumerate(t):
            if kind == "T" and "${" in text:
                found.append("template literal with ${...}")
            if kind == "S" and ("<" in text or ">" in text or '="' in text):
                for a, b in _chain(t, i):
                    check(a, b)
            if kind == "I" and text == "innerHTML" and i > 0 and t[i - 1] == ("P", ".") \
                    and i + 1 < len(t) and t[i + 1] in (("P", "="), ("P", "+=")):
                end = _scan_operand_to_end(t, i + 2)
                for a, b in _top_level_plus(t, i + 2, end):
                    check(a, b)
        return found


def _scan_operand_to_end(toks, start) -> int:
    """End index of an assignment's right-hand side: first top-level ';' ',' or closing bracket."""
    k, depth = start, 0
    while k < len(toks):
        kind, text = toks[k]
        if kind == "P":
            if text in _OPEN:
                depth += 1
            elif text in _CLOSE:
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and text in (";", ","):
                break
        k += 1
    return k


def _top_level_plus(toks, start, end):
    ranges, a, depth = [], start, 0
    for k in range(start, end):
        kind, text = toks[k]
        if kind == "P" and text in _OPEN:
            depth += 1
        elif kind == "P" and text in _CLOSE:
            depth -= 1
        elif kind == "P" and text == "+" and depth == 0:
            ranges.append((a, k))
            a = k + 1
    ranges.append((a, end))
    return ranges


def _unsafe(script: str, audited=()) -> list:
    return _Audit(script, audited).unsafe_operands()


@pytest.mark.parametrize("snippet", [
    "el.innerHTML = x;",
    "el.innerHTML=data.name;",
    "var h=''; h+='<b>'+x;",
    "var h=''; h += x; el.innerHTML = h;",
    "el.innerHTML = '<i>'+a.b+'</i>';",
    "el.innerHTML += '<i>' + y + '</i>';",
    "h = '<p class=\"'+cls+'\">'; ",
    "el.innerHTML = `<b>${x}</b>`;",
    "var s = u.name; el.innerHTML = '<a>' + s + '</a>';",
    "function f(v){ return '<td>'+v+'</td>'; }",
])
def test_audit_catches_unsafe_html_construction(snippet):
    assert _unsafe(snippet), snippet


@pytest.mark.parametrize("snippet", [
    "el.innerHTML = '<p>static</p>';",
    "el.innerHTML = '<i>' + esc(a.b) + '</i>';",
    "var h=''; h+='<b>'+esc(x)+'</b>'; el.innerHTML = h;",
    "var n = Number(d.n)||0; el.innerHTML = '<b>' + n + '</b>';",
    "el.innerHTML = '<b>' + (ok ? 'yes' : 'no') + '</b>' + (x ? '<i>' + esc(x) + '</i>' : '');",
    "var w = a ? ('<i>'+esc(a)+'</i>') : 'none'; el.innerHTML = '<p>'+w+'</p>';",
    "el.innerHTML = '<p>' + list.length + ' items ' + (n/3).toFixed(1) + '</p>';",
])
def test_audit_accepts_properly_escaped_construction(snippet):
    assert not _unsafe(snippet), (snippet, _unsafe(snippet))


def test_audit_does_not_trust_a_variable_just_because_another_use_of_its_name_is_safe():
    # `v` is a safe number here ...
    safe_use = "var v = Number(a); el.innerHTML = '<b>' + v + '</b>';"
    assert not _unsafe(safe_use)
    # ... but reusing the name for untrusted text elsewhere makes every use unsafe.
    assert _unsafe(safe_use + " v = data.name;")


def test_audit_regex_literal_does_not_derail_the_tokenizer():
    assert not _unsafe("function esc(s){return String(s).replace(/[&<>\"]/g,'x');} el.innerHTML='<b>'+esc(q)+'</b>';")


@pytest.mark.parametrize("page", PAGES)
def test_dynamic_html_goes_through_esc(page):
    html = _read(f"web/{page}")
    assert "function esc(" in html
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    # esc() itself is the one place that handles raw text; audit everything else
    esc_def = re.search(r"function esc\(s\)\{.*?\n", script)
    script = script.replace(esc_def.group(0), "") if esc_def else script
    from collections import Counter
    allowed = {k: v[0] for k, v in AUDITED_SAFE[page].items()}
    found = Counter(_unsafe(script, audited=allowed))
    assert dict(found) == allowed, (f"unreviewed (or no longer present) interpolation in {page}: "
                                    f"{dict(found)} vs audited {allowed}")


@pytest.mark.parametrize("page", PAGES)
def test_no_other_html_injection_sinks(page):
    script = _read(f"web/{page}").split("<script>", 1)[1]
    for sink in ("insertAdjacentHTML", "outerHTML", "document.write", "eval(", "new Function", "javascript:"):
        assert sink not in script, sink
    assert not re.search(r"""['"][^'"]*<[^'"]*\son[a-z]+\s*=""", script), "inline event handler in a string"
    assert not re.search(r"setTimeout\(\s*['\"]", script)


@pytest.mark.parametrize("page", PAGES)
def test_pages_have_balanced_main_header_footer_and_divs(page):
    from html.parser import HTMLParser
    stack, problems = [], []

    class P(HTMLParser):
        VOID = {"meta", "link", "br", "img", "input", "hr", "path", "circle", "rect", "line", "stop", "use"}

        def handle_starttag(self, tag, attrs):
            if tag not in self.VOID:
                stack.append(tag)

        def handle_startendtag(self, tag, attrs):
            pass

        def handle_endtag(self, tag):
            if tag in self.VOID:
                return
            if not stack or stack[-1] != tag:
                problems.append(f"</{tag}> closes <{stack[-1] if stack else None}>")
                if tag in stack:
                    while stack and stack.pop() != tag:
                        pass
            else:
                stack.pop()

    P().feed(_read(f"web/{page}"))
    assert not problems, problems
    assert not stack, f"unclosed: {stack}"


def test_engine_route_serves_engine_page(client):
    r = client.get("/engine")
    assert r.status_code == 200
    assert r.content == (ROOT / "web" / "engine.html").read_bytes()
    assert not (ROOT / "web" / "water.html").exists()


def test_old_water_routes_are_gone(client):
    assert client.get("/water").status_code == 404
    assert client.get("/api/water").status_code == 404
    paths = {r.path for r in sf_web.app.routes}
    assert "/engine" in paths and "/api/engine" in paths
    assert "/water" not in paths and "/api/water" not in paths


def test_api_engine_route_responds(client):
    assert client.get("/api/engine").status_code == 200


def test_pages_link_to_engine_not_water():
    for p in PAGES:
        assert 'href="/water"' not in _read(f"web/{p}")
        assert "/api/water" not in _read(f"web/{p}")


def _rule_techniques():
    from lab import coverage
    return set(coverage.rule_techniques(ROOT / "detections" / "sigma"))


def test_layer_technique_count_matches_shipped_rules():
    layer = json.loads(_read("docs/coverage_layer.json"))
    rules = _rule_techniques()
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert len(ids) == len(set(ids)) == len(rules)
    assert set(ids) == rules
    assert f"{len(rules)} Techniques" in layer["name"]
    assert layer["name"].startswith("SentinelForge")
    assert "%" not in layer["name"]  # no ATT&CK total data file; never invent a denominator


@pytest.mark.parametrize("path", BRANDED_FILES, ids=lambda p: p.name)
def test_no_legacy_strings(path):
    text = path.read_text(encoding="utf-8")
    assert not LEGACY.search(text), LEGACY.search(text).group(0)


def test_no_personal_links_in_pages():
    for p in PAGES:
        html = _read(f"web/{p}")
        assert "github.com/" not in html
    assert "github.com/" not in _read("topology.svg")
    assert "demo." not in _read("topology.svg")


def test_layer_comments_never_invent_deploy_dates_or_confidence():
    layer = json.loads(_read("docs/coverage_layer.json"))
    for t in layer["techniques"]:
        assert "Deployed:  " not in t["comment"] and "Deployed: |" not in t["comment"], t
        if "not assessed" in t["comment"]:
            assert t["color"] == "#9e9e9e", t  # unassessed techniques are neutral, not "MEDIUM" orange
        assert "Tactic:" in t["comment"] and "_" not in t["comment"], t  # human tactic names, no underscores


def test_engine_api_coverage_comes_from_the_rule_tags_in_a_controlled_tree(tmp_path, monkeypatch):
    """Independent expectation: two tiny rules with known tags, an empty state directory."""
    (tmp_path / "state").mkdir()
    sigma = tmp_path / "detections" / "sigma"
    sigma.mkdir(parents=True)
    (sigma / "a.yml").write_text("title: a\ntags:\n- attack.discovery\n- attack.t1082\n", encoding="utf-8")
    (sigma / "b.yml").write_text("title: b\ntags:\n- attack.execution\n- attack.t1059.001\n", encoding="utf-8")
    monkeypatch.setattr(sf_web, "HERE", tmp_path)
    data = TestClient(sf_web.app).get("/api/engine").json()
    assert data["techniques_covered"] == 2
    assert data["prod_rules"] == 2 and data["hunt_triggered"] == 0
    assert {t["id"] for t in data["by_tactic"]["discovery"]} == {"T1082"}
    assert {t["id"] for t in data["by_tactic"]["execution"]} == {"T1059.001"}
    assert set(data["by_tactic"]) <= set(data["tactic_order"]), "only hyphenated ATT&CK tactic names"


def test_engine_api_matches_shipped_rules_and_layer():
    data = TestClient(sf_web.app).get("/api/engine").json()
    layer = json.loads(_read("docs/coverage_layer.json"))
    shipped = _rule_techniques()
    assert data["techniques_covered"] == len(shipped)          # the rule tags, not the engine's own count
    assert {t["techniqueID"] for t in layer["techniques"]} == shipped
