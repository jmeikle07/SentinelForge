from pathlib import Path

from lab import ecs

FIXTURE = Path(__file__).parent / "fixtures" / "t1059_001.yml"

# Captured from the pre-refactor deploy_rule.convert_sigma / validate_rule.convert_sigma
# (both produced identical output) for the T1059.001 rule.
GOLDEN_T1059 = (
    'event.code:1 AND (((process.name:(*\\\\powershell.exe OR *powershell.exe)) AND '
    '(process.command_line:*Invoke\\-WebRequest* AND process.command_line:*OutFile*) AND '
    '(process.command_line:(*$env\\:TEMP* OR *%TEMP%* OR *\\\\AppData\\\\Local\\\\Temp* OR '
    '*\\\\AppData\\\\Roaming* OR *\\\\Users\\\\Public* OR *C\\:\\\\Windows\\\\Temp*)) AND '
    '(process.command_line:(*raw.githubusercontent.com* OR *http\\:\\/\\/* OR *https\\:\\/\\/*))) OR '
    '((process.name:(*\\\\powershell.exe OR *powershell.exe)) AND dns.question.name:raw.githubusercontent.com))'
)


def test_convert_t1059_matches_current_output():
    assert ecs.convert(FIXTURE.read_text(encoding="utf-8")) == [GOLDEN_T1059]


def test_pipeline_is_ecs_fieldmap():
    p = ecs.pipeline()
    assert p.name == "sysmon-to-ecs-fieldmap"
    assert p.priority == 100


def test_convert_returns_list_of_str():
    out = ecs.convert(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(out, list) and all(isinstance(q, str) for q in out)
