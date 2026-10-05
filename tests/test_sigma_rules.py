"""Quality gates for every shipped Sigma rule (offline, no network)."""
import re
import uuid
from pathlib import Path

import pytest
import yaml

from lab.ecs import convert

RULES_DIR = Path(__file__).resolve().parent.parent / "detections" / "sigma"
RULE_FILES = sorted(RULES_DIR.glob("*.yml"))
AUTHOR = "Jahsean Meikle"

REQUIRED = ("title", "id", "status", "logsource", "detection", "level", "tags",
            "falsepositives")

# Sigma logsource categories this lab's pipeline understands.
VALID_CATEGORIES = {
    "process_creation", "network_connection", "dns_query", "file_event",
    "file_change", "file_delete", "registry_set", "registry_add",
    "registry_delete", "registry_event", "image_load", "create_remote_thread",
    "process_access", "pipe_created", "driver_load", "wmi_event",
}

# ATT&CK IDs that were deprecated/merged, mapped to their replacement.
DEPRECATED_ATTACK_IDS = {
    "t1035": "t1569.002",
    "t1086": "t1059.001",
    "t1064": "t1059",
    "t1117": "t1218.010",
    "t1170": "t1218.005",
    "t1085": "t1218.011",
    "t1500": "t1127",
}

# Filenames are stable (deployed rules); a legacy filename may keep a
# deprecated technique ID as long as the tag carries the replacement.
LEGACY_FILENAME_ALIASES = {"t1035": "t1569.002"}

# Groups of intentionally kept duplicate rules (must cross-link via related).
DUPLICATE_GROUPS = {
    "sdbinst": [
        "c27fffce-2372-458e-ae4b-4f247823dc2c",
        "9d19c38d-a376-4e18-a517-db535a8322be",
        "5c8ea8be-7a0e-4809-b65a-2d26f91ee077",
    ],
    "hidefileext": [
        "0acbfe83-9428-4eda-8c9c-6482e4d60c0a",
        "57053051-8d37-43fc-b572-c3c2c320da81",
    ],
    "msiexec": [
        "b8ee8991-c2af-4d5e-9dd8-4702f01a2e14",
        "c1ced7af-9d77-402a-aebd-b93426ebec3a",
    ],
}


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


RULES = {f.name: _load(f) for f in RULE_FILES}
BY_ID = {r["id"]: r for r in RULES.values()}


def _technique_tags(rule):
    return [t[len("attack."):] for t in rule["tags"]
            if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]


def _filename_technique(name):
    m = re.match(r"T(\d{4})(?:[-.](\d{3}))?(?=-|\.)", name)
    assert m, f"filename {name} does not start with a technique id"
    return f"t{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")


@pytest.mark.parametrize("name", sorted(RULES))
def test_rule_has_required_fields(name):
    rule = RULES[name]
    missing = [k for k in REQUIRED if not rule.get(k)]
    assert not missing, f"{name} missing {missing}"
    uuid.UUID(str(rule["id"]))
    assert rule["tags"], name


@pytest.mark.parametrize("name", sorted(RULES))
def test_rule_converts_without_error(name):
    queries = convert((RULES_DIR / name).read_text(encoding="utf-8"))
    assert queries and all(q.strip() for q in queries)


def test_ids_are_unique():
    ids = [r["id"] for r in RULES.values()]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("name", sorted(RULES))
def test_filename_technique_matches_attack_tag(name):
    techs = _technique_tags(RULES[name])
    assert techs, f"{name} has no attack.tNNNN tag"
    fn = _filename_technique(name)
    expected = LEGACY_FILENAME_ALIASES.get(fn, fn)
    assert techs[0] == expected, (
        f"{name}: filename says {fn} but primary tag is {techs[0]}")


@pytest.mark.parametrize("name", sorted(RULES))
def test_logsource_category_is_valid(name):
    ls = RULES[name]["logsource"]
    assert ls.get("product") == "windows", name
    if "category" in ls:
        assert ls["category"] in VALID_CATEGORIES, (
            f"{name}: invalid category {ls['category']!r}")


@pytest.mark.parametrize("name", sorted(RULES))
def test_network_rules_use_network_connection_category(name):
    text = yaml.safe_dump(RULES[name]["detection"])
    if re.search(r"\b(source\.ip|destination\.(ip|port))\b", text):
        assert RULES[name]["logsource"].get("category") == "network_connection", name


@pytest.mark.parametrize("name", sorted(RULES))
def test_date_is_not_before_2026(name):
    date = str(RULES[name]["date"])
    assert re.fullmatch(r"\d{4}/\d{2}/\d{2}", date), f"{name}: bad date {date}"
    assert int(date[:4]) >= 2026, f"{name}: date {date}"


@pytest.mark.parametrize("name", sorted(RULES))
def test_no_deprecated_attack_ids(name):
    bad = [t for t in _technique_tags(RULES[name])
           if t.split(".")[0] in DEPRECATED_ATTACK_IDS or t in DEPRECATED_ATTACK_IDS]
    assert not bad, f"{name} uses deprecated {bad}"


@pytest.mark.parametrize("name", sorted(RULES))
def test_author_is_real_name(name):
    assert RULES[name]["author"] == AUTHOR


@pytest.mark.parametrize("group", sorted(DUPLICATE_GROUPS))
def test_duplicate_rules_are_cross_linked_as_similar(group):
    ids = DUPLICATE_GROUPS[group]
    for rid in ids:
        assert rid in BY_ID, f"rule {rid} was deleted"
        links = {r["id"] for r in BY_ID[rid].get("related", [])
                 if r["type"] == "similar"}
        assert set(ids) - {rid} <= links, f"{rid} lacks similar links in {group}"


def test_related_references_resolve_to_existing_rules():
    for name, rule in RULES.items():
        for rel in rule.get("related", []):
            assert rel["type"] in {"similar", "derived", "obsolete", "merged", "renamed"}
            assert rel["id"] in BY_ID, f"{name} relates to unknown {rel['id']}"


def test_t1046_uses_maintainable_cidr_list():
    rule = next(r for r in RULES.values() if "t1046" in _technique_tags(r))
    sel = rule["detection"]["selection_source_ip"]
    assert "source.ip|cidr" in sel and isinstance(sel["source.ip|cidr"], list)
    assert all("/" in c for c in sel["source.ip|cidr"])
