"""Static checks on the GitHub Actions workflows (offline, YAML only)."""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WF_DIR = ROOT / ".github" / "workflows"
DEPLOY = WF_DIR / "deploy-detections.yml"
TEST = WF_DIR / "test.yml"
SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def load(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def triggers(wf):
    on = wf["on"]
    return set(on) if isinstance(on, (dict, list)) else {on}


def all_steps(wf):
    for job_name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            yield job_name, step


def run_scripts(wf):
    for job_name, step in all_steps(wf):
        if "run" in step:
            yield job_name, step["run"]


@pytest.fixture(scope="module")
def deploy():
    return load(DEPLOY)


@pytest.fixture(scope="module")
def testwf():
    return load(TEST)


def test_deploy_job_depends_on_validate_success(deploy):
    jobs = deploy["jobs"]
    assert "validate" in jobs and "deploy" in jobs
    needs = jobs["deploy"].get("needs")
    needs = [needs] if isinstance(needs, str) else needs
    assert "validate" in needs
    text = DEPLOY.read_text(encoding="utf-8")
    for bypass in ("cancelled()", "always()", "failure()"):
        assert bypass not in text, f"{bypass} would let deploy bypass validation"
    cond = str(jobs["deploy"].get("if", ""))
    assert "needs.validate.result" not in cond or "success" in cond


def test_test_workflow_uses_github_hosted_runner_on_pull_request(testwf):
    assert {"pull_request", "push"} <= triggers(testwf)
    for name, job in testwf["jobs"].items():
        assert job["runs-on"] == "ubuntu-latest", name
    assert "pull_request_target" not in TEST.read_text(encoding="utf-8")
    runs = "\n".join(s for _, s in run_scripts(testwf))
    assert "pytest" in runs
    assert "tools/tag_compliance.py --check" in runs
    pys = [s["with"]["python-version"] for _, s in all_steps(testwf)
           if "with" in s and "python-version" in s["with"]]
    assert pys and all(str(p) == "3.12" for p in pys)


def test_pull_requests_never_run_on_self_hosted(deploy):
    assert "pull_request" not in triggers(deploy)
    assert "pull_request_target" not in triggers(deploy)
    assert triggers(deploy) == {"push"}
    assert deploy["on"]["push"]["branches"] == ["main"]
    for name, job in deploy["jobs"].items():
        assert "self-hosted" in str(job["runs-on"]), name
        assert "refs/heads/main" in str(job.get("if", "")), name
        assert "'push'" in str(job.get("if", "")), name


def test_no_secrets_exposed_to_pull_request_from_forks(deploy, testwf):
    # The test workflow has PR triggers: it must not touch any secret
    # beyond the implicit read-only GITHUB_TOKEN.
    text = TEST.read_text(encoding="utf-8")
    assert not re.findall(r"secrets\.(?!GITHUB_TOKEN)\w+", text)
    assert "secrets: inherit" not in text
    # Deploy workflow (which uses secrets) must not be PR-triggered at all.
    assert "pull_request" not in triggers(deploy)


def test_permissions_are_least_privilege(deploy, testwf):
    assert deploy["permissions"] == {}  # nothing by default
    assert deploy["jobs"]["deploy"]["permissions"] == {"contents": "read"}
    assert deploy["jobs"]["validate"]["permissions"] == {"contents": "write"}
    assert testwf["permissions"] == {"contents": "read"}
    for wf in (deploy, testwf):
        for job in wf["jobs"].values():
            assert "pull-requests" not in job.get("permissions", {})


def test_installs_from_requirements_file(deploy, testwf):
    for wf in (deploy, testwf):
        runs = "\n".join(s for _, s in run_scripts(wf))
        assert re.search(r"pip install -r requirements(-dev)?\.txt", runs)
        assert not re.search(r"pip install\s+(?!-r)\S+==", runs)
        for _, step in all_steps(wf):
            if str(step.get("uses", "")).startswith("actions/setup-python"):
                assert step["with"]["cache"] == "pip"
                assert "requirements" in step["with"]["cache-dependency-path"]


def test_changed_files_not_interpolated_into_shell(deploy):
    for job, script in run_scripts(deploy):
        assert "${{" not in script, f"{job}: expression interpolated into run script"
    loops = [s for _, s in run_scripts(deploy) if "CHANGED_FILES" in s]
    assert loops, "changed files must be passed through an env var"
    for s in loops:
        if "while" in s:
            assert "IFS= read -r" in s
            assert '"$file"' in s
    assert any("while IFS= read -r" in s for s in loops)
    for job_name, step in all_steps(deploy):
        if "CHANGED_FILES" in step.get("run", "") and "while" in step["run"]:
            assert "CHANGED_FILES" in step.get("env", {})
    # The unquoted `for file in <expansion>` word-splitting pattern is gone.
    assert not re.search(r"for\s+\w+\s+in\s+\$", DEPLOY.read_text(encoding="utf-8"))


def test_checkout_has_full_history_and_correct_push_diff(deploy):
    for job_name, job in deploy["jobs"].items():
        co = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout")]
        assert co and co[0]["with"]["fetch-depth"] == 0, job_name
    diffs = [s for _, s in run_scripts(deploy) if "diff" in s and "--name-only" in s]
    assert diffs
    for s in diffs:
        assert "BEFORE_SHA" in s and "AFTER_SHA" in s
        assert "HEAD~1" not in s
        assert '"$BEFORE_SHA" "$AFTER_SHA"' in s


def test_third_party_actions_pinned_by_sha(deploy, testwf):
    known = {
        "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    }
    for wf in (deploy, testwf):
        for _, step in all_steps(wf):
            if "uses" in step:
                assert SHA_RE.match(step["uses"]), step["uses"]
                name, sha = step["uses"].split("@")
                assert known.get(name) == sha, step["uses"]


def test_deploy_env_matches_script_configuration(deploy):
    env_names = set()
    for job in deploy["jobs"].values():
        for step in job["steps"]:
            env_names |= set(step.get("env", {}))
    assert {"ELASTIC_URL", "ELASTIC_API_KEY", "KIBANA_URL"} <= env_names
    # Old Gmail-specific names were replaced by SMTP_* in validate_rule.py.
    assert not any(n.startswith("GMAIL_") for n in env_names)
    assert "SMTP_HOST" in env_names and "SF_REPO_URL" in env_names


def test_deploy_documents_self_hosted_reason():
    text = DEPLOY.read_text(encoding="utf-8")
    assert "self-hosted" in text
    assert re.search(r"#.*lab network", text, re.I)


def test_no_legacy_branding():
    for p in WF_DIR.glob("*.yml"):
        low = p.read_text(encoding="utf-8").lower()
        assert "1xlozec" not in low and "tallkitchen" not in low
