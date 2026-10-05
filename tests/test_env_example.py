"""Every environment variable the code reads is listed in .env.example (commented out when it is
optional), so the example cannot silently fall behind the code."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CODE_FILES = [p for p in list(ROOT.glob("*.py")) + list((ROOT / "lab").glob("*.py")) + list((ROOT / "tools").glob("*.py"))]
READ = re.compile(r"""(?:os\.environ\.get|os\.getenv|os\.environ)\s*[\(\[]\s*["']([A-Z][A-Z0-9_]+)["']""")
# Variables owned by other tools or by the shell/CI, not by this project's configuration.
NOT_PROJECT_CONFIG = {"PATH", "HOME", "USERPROFILE", "PYTHONIOENCODING", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
                      "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_REPOSITORY", "CI", "TERM", "NO_COLOR", "COLUMNS"}


def _example_names():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    return set(re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]+)=", text, re.M))


def test_every_variable_the_code_reads_is_in_env_example():
    read = set()
    for p in CODE_FILES:
        read |= set(READ.findall(p.read_text(encoding="utf-8")))
    missing = sorted(read - NOT_PROJECT_CONFIG - _example_names())
    assert not missing, f"read by the code but missing from .env.example: {missing}"


def test_optional_variables_are_commented_out_not_set_empty():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    for var in ("LAB_ADMIN_TOKEN", "SF_ALLOWED_HOSTS", "SF_CASE_VARIANTS", "WATER_REVIEW_GATE", "STOP_SF_ENGINE"):
        assert f"# {var}=" in text, var
        assert not re.search(rf"^{var}=", text, re.M), f"{var} must not be set (even empty) by default"


def test_admin_token_guidance_mentions_the_minimum_length():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"16", text.split("LAB_ADMIN_TOKEN")[0][-400:] + text.split("LAB_ADMIN_TOKEN")[1][:200])
