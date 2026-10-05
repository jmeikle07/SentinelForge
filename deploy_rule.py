"""Deploy a Sigma rule to Kibana as a detection-engine rule (or retire one).

Configuration comes from the environment via lab.config (ELASTIC_URL, KIBANA_URL,
ELASTIC_API_KEY, LAB_INSECURE_TLS). Library code raises DeployError/ConfigError; only main() exits.

Redeploy never resets analyst work: on a 409 the existing rule is fetched, checked to be the
same lineage, and updated with PATCH using only the engine-owned fields (see
lab.kibana_rule.ENGINE_OWNED_FIELDS). enabled/exceptions_list/actions/note are never sent on update.
"""
import logging
import re
import sys

import requests
import yaml

from lab import ecs
from lab.config import ConfigError, Settings, load
from lab.http import session as make_session
from lab.kibana_rule import build_payload, build_update_payload, technique_tags

log = logging.getLogger("sf.deploy")

RULES_PATH = "/api/detection_engine/rules"
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class DeployError(RuntimeError):
    """The rule could not be converted or Kibana rejected it."""


def convert_sigma(rule_path):
    """Sigma file -> list of Lucene queries (ECS field names) using the shared lab.ecs pipeline."""
    with open(rule_path, "r", encoding="utf-8") as f:
        return ecs.convert(f.read())


def load_rule_metadata(rule_path):
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _headers(settings: Settings) -> dict:
    key = (settings.elastic_api_key or "").strip()
    if not key:
        raise ConfigError("ELASTIC_API_KEY is not set; refusing to call Kibana without credentials")
    return {
        "Authorization": f"ApiKey {key}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


def _url(settings: Settings) -> str:
    return f"{settings.kibana_url.rstrip('/')}{RULES_PATH}"


def _fetch_existing(http, url, headers, rule_id) -> dict:
    resp = http.get(url, headers=headers, params={"rule_id": rule_id})
    if resp.status_code != 200:
        raise DeployError(f"rule {rule_id} conflicted on create but could not be read: "
                          f"{resp.status_code} {resp.text[:300]}")
    try:
        existing = resp.json()
    except ValueError as exc:
        raise DeployError(f"rule {rule_id}: unreadable response from Kibana") from exc
    if not isinstance(existing, dict):
        raise DeployError(f"rule {rule_id}: unexpected response from Kibana")
    return existing


def _check_same_lineage(existing: dict, new_payload: dict) -> None:
    """Refuse to overwrite a Kibana rule that is not an earlier version of this one.

    The lookup is by rule_id, so equal rule_ids prove nothing (that is how a collision looks);
    the evidence is a shared ATT&CK technique tag."""
    rid = new_payload["rule_id"]
    if str(existing.get("rule_id") or rid) != rid:
        raise DeployError(f"Kibana returned a different rule_id for {rid}; refusing to overwrite")
    new_t = technique_tags(new_payload.get("tags"))
    old_t = technique_tags(existing.get("tags"))
    if not (new_t & old_t):
        raise DeployError(
            f"existing Kibana rule {rid} ('{existing.get('name')}') is not the same rule: its technique "
            f"tags {sorted(old_t)} share nothing with {sorted(new_t)}; refusing to overwrite "
            f"(possible rule id collision)")


def deploy_to_kibana(path: str, settings: Settings, session=None) -> dict:
    metadata = load_rule_metadata(path)
    if not isinstance(metadata, dict):
        raise DeployError(f"{path}: not a Sigma rule mapping")
    if not str(metadata.get("id") or "").strip():
        raise DeployError(f"{path}: Sigma rule has no id; refusing to deploy")
    headers = _headers(settings)  # ConfigError on empty key, before any conversion or HTTP
    try:
        queries = convert_sigma(path)
    except Exception as exc:  # pySigma raises many distinct error types
        raise DeployError(f"could not convert {path}: {exc}") from exc

    queries = [q for q in (queries or []) if q]
    if not queries:
        raise DeployError(f"could not convert {path}: no query produced")

    author = metadata.get("author")
    try:
        kibana_rule = build_payload(metadata, queries, str(author) if author else "")
    except ValueError as exc:
        raise DeployError(f"{path}: {exc}") from exc

    url = _url(settings)
    http = session or make_session()
    title = metadata.get("title")

    try:
        response = http.post(url, headers=headers, json=kibana_rule)
        if response.status_code in (200, 201):
            log.info("Deployed '%s' to Kibana", title)
        elif response.status_code == 409:
            existing = _fetch_existing(http, url, headers, kibana_rule["rule_id"])
            _check_same_lineage(existing, kibana_rule)
            response = http.patch(url, headers=headers, json=build_update_payload(kibana_rule))
            if response.status_code not in (200, 201):
                raise DeployError(f"could not update rule: {response.status_code} {response.text[:300]}")
            log.info("Updated '%s' in Kibana (exceptions/actions/enabled state preserved)", title)
        else:
            raise DeployError(f"deployment failed with status {response.status_code}: {response.text[:300]}")
    except requests.RequestException as exc:
        raise DeployError(f"Kibana request failed: {exc}") from exc

    try:
        return response.json()
    except ValueError:
        return {}


def delete_rule(rule_id, settings: Settings, session=None) -> None:
    """Retire a rule from Kibana by rule_id. A rule that is already gone (404) is not an error."""
    if not isinstance(rule_id, str) or not _UUID_RE.match(rule_id.strip()):
        raise DeployError(f"refusing to delete: {rule_id!r} is not a rule UUID")
    rule_id = rule_id.strip()
    headers = _headers(settings)
    http = session or make_session()
    try:
        response = http.delete(_url(settings), headers=headers, params={"rule_id": rule_id})
    except requests.RequestException as exc:
        raise DeployError(f"Kibana request failed: {exc}") from exc
    if response.status_code == 404:
        log.info("Rule %s is not in Kibana (already retired)", rule_id)
    elif response.status_code in (200, 204):
        log.info("Deleted rule %s from Kibana", rule_id)
    else:
        raise DeployError(f"could not delete rule {rule_id}: {response.status_code} {response.text[:300]}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level="INFO", format="%(message)s")
    delete = len(argv) == 2 and argv[0] == "--delete"
    if not delete and len(argv) != 1:
        print("usage: deploy_rule.py <sigma-rule.yml> | --delete <rule_id>", file=sys.stderr)
        sys.exit(2)
    try:
        settings = load()
        if delete:
            delete_rule(argv[1], settings)
            print(f"SUCCESS: deleted {argv[1]}")
        else:
            deploy_to_kibana(argv[0], settings)
            print(f"SUCCESS: deployed {argv[0]}")
    except (ConfigError, DeployError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
