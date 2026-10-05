import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sf_web

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["index.html", "review.html", "engine.html"]
BRANDED_FILES = [ROOT / "web" / p for p in PAGES] + [ROOT / "topology.svg", ROOT / "docs" / "coverage_layer.json"]
LEGACY = re.compile(r"1xlozec|tall\s?kitchen|hunt-and-water|albundy|\bwater\b", re.I)


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
    assert "401" in html and "403" in html


# Interpolated expressions that were audited by hand and are NOT passed through esc():
# constants, booleans, Number()-coerced values, locally computed numbers, and variables that
# are themselves assembled from esc()'d parts. Anything new must go through esc() or be added
# here after the same review.
AUDITED_SAFE = {
    "index.html": {
        "(f>0?'bad':'ok')", "(tg==='bad'?'bad':(tg==='ok'?'ok':''))", "C.toFixed(1)", "R",
        "Number(d.match_count)", "Number(d.pulse_count)", "acc", "accGlow", "bottom", "f", "t", "s",
        "info.led", "info.tag", "info.summary", "v.length", "what",
    },
    "review.html": {
        "(r.healed?'Rewritten once, then ':'')", "(v.approve?'approve':'reject')",
        "d.triggers.join(', and ')", "encodeURIComponent(kind)",
    },
    "engine.html": {"(ap?'APPROVE':'REJECT')", "(ap?'approve':'reject')", "(r.count===1?'time':'times')"},
}
INTERP = re.compile(r"""(['"`])\s*\+\s*(?!esc\()([^+
]{1,60}?)\s*\+\s*(['"`])""")


@pytest.mark.parametrize("page", PAGES)
def test_dynamic_html_goes_through_esc(page):
    html = _read(f"web/{page}")
    assert "function esc(" in html
    script = html.split("<script>", 1)[1]
    found = {m.group(2) for m in INTERP.finditer(script) if not m.group(2).startswith("'<")}
    assert found <= AUDITED_SAFE[page], f"unreviewed interpolation: {found - AUDITED_SAFE[page]}"


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
    import glob
    import yaml
    ids = set()
    for f in glob.glob(str(ROOT / "detections" / "sigma" / "*.yml")):
        with open(f, encoding="utf-8") as fh:
            for t in yaml.safe_load(fh).get("tags", []):
                if re.match(r"attack\.t\d", str(t)):
                    ids.add(str(t)[7:].upper())
    return ids


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
