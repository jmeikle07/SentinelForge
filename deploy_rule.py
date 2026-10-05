"""Deploy a Sigma rule to Kibana as a detection-engine rule.

Configuration comes from the environment via lab.config (ELASTIC_URL, KIBANA_URL,
ELASTIC_API_KEY, LAB_INSECURE_TLS). Library code raises DeployError; only main() exits.
"""
import logging
import sys

import requests
import yaml

from lab import ecs
from lab.config import ConfigError, Settings, load
from lab.http import session as make_session
from lab.kibana_rule import build_payload

log = logging.getLogger("sf.deploy")

RULES_PATH = "/api/detection_engine/rules"


class DeployError(RuntimeError):
    """The rule could not be converted or Kibana rejected it."""


def convert_sigma(rule_path):
    """Sigma file -> Lucene query (ECS field names) using the shared lab.ecs pipeline."""
    with open(rule_path, "r", encoding="utf-8") as f:
        result = ecs.convert(f.read())
    return result[0] if result else None


def load_rule_metadata(rule_path):
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def deploy_to_kibana(path: str, settings: Settings, session=None) -> dict:
    metadata = load_rule_metadata(path)
    if not isinstance(metadata, dict):
        raise DeployError(f"{path}: not a Sigma rule mapping")
    try:
        query = convert_sigma(path)
    except Exception as exc:  # pySigma raises many distinct error types
        raise DeployError(f"could not convert {path}: {exc}") from exc

    if not query:
        raise DeployError(f"could not convert {path}: no query produced")

    author = metadata.get("author")
    kibana_rule = build_payload(metadata, [query], str(author) if author else "")

    url = f"{settings.kibana_url.rstrip('/')}{RULES_PATH}"
    headers = {
        "Authorization": f"ApiKey {settings.elastic_api_key}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }
    http = session or make_session()
    title = metadata.get("title")

    try:
        response = http.post(url, headers=headers, json=kibana_rule)
        if response.status_code in (200, 201):
            log.info("Deployed '%s' to Kibana", title)
        elif response.status_code == 409:
            # Update API: PUT with rule_id in the body (no query-string overwrite).
            response = http.put(url, headers=headers, json=kibana_rule)
            if response.status_code not in (200, 201):
                raise DeployError(f"could not update rule: {response.status_code} {response.text[:300]}")
            log.info("Updated '%s' in Kibana", title)
        else:
            raise DeployError(f"deployment failed with status {response.status_code}: {response.text[:300]}")
    except requests.RequestException as exc:
        raise DeployError(f"Kibana request failed: {exc}") from exc

    try:
        return response.json()
    except ValueError:
        return {}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level="INFO", format="%(message)s")
    if len(argv) != 1:
        print("usage: deploy_rule.py <sigma-rule.yml>", file=sys.stderr)
        sys.exit(2)
    try:
        settings = load()
        deploy_to_kibana(argv[0], settings)
    except (ConfigError, DeployError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"SUCCESS: deployed {argv[0]}")


if __name__ == "__main__":
    main()
