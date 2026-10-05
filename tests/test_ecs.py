from pathlib import Path

from lab import ecs

FIXTURE = Path(__file__).parent / "fixtures" / "t1059_001.yml"

# Captured from the pre-refactor deploy_rule.convert_sigma / validate_rule.convert_sigma
# (both produced identical output) for the T1059.001 rule.
GOLDEN_T1059_VERBATIM = (
    'event.code:1 AND (((process.name:(*\\\\powershell.exe OR *powershell.exe)) AND '
    '(process.command_line:*Invoke\\-WebRequest* AND process.command_line:*OutFile*) AND '
    '(process.command_line:(*$env\\:TEMP* OR *%TEMP%* OR *\\\\AppData\\\\Local\\\\Temp* OR '
    '*\\\\AppData\\\\Roaming* OR *\\\\Users\\\\Public* OR *C\\:\\\\Windows\\\\Temp*)) AND '
    '(process.command_line:(*raw.githubusercontent.com* OR *http\\:\\/\\/* OR *https\\:\\/\\/*))) OR '
    '((process.name:(*\\\\powershell.exe OR *powershell.exe)) AND dns.question.name:raw.githubusercontent.com))'
)


# Intentional update (case-variant expansion, docs/ARCHITECTURE.md "Case sensitivity"): every
# string literal on a case-insensitive field (process.name, process.command_line,
# dns.question.name) now appears as written + lower + UPPER + Title (deduplicated), e.g.
# `*\powershell.exe` -> `*\powershell.exe OR *\POWERSHELL.EXE OR *\Powershell.exe`.
# The structure (event.code, AND/OR shape, wildcards, escaping) and the as-written literals
# are unchanged; GOLDEN_T1059_VERBATIM above is what SF_CASE_VARIANTS=0 still produces.
GOLDEN_T1059_CASE = (
    'event.code:1 AND (((process.name:(*\\\\powershell.exe OR *\\\\POWERSHELL.EXE OR *\\\\Powershell.exe'
    ' OR *powershell.exe OR *POWERSHELL.EXE'
    ' OR *Powershell.exe)) AND ((process.command_line:(*Invoke\\-WebRequest* OR *invoke\\-webrequest*'
    ' OR *INVOKE\\-WEBREQUEST* OR *Invoke\\-Webrequest*)) AND (process.command_line:(*OutFile*'
    ' OR *outfile* OR *OUTFILE* OR *Outfile*))) AND (process.command_line:(*$env\\:TEMP*'
    ' OR *$env\\:temp* OR *$ENV\\:TEMP* OR *$env\\:Temp* OR *%TEMP%* OR *%temp%*'
    ' OR *\\\\AppData\\\\Local\\\\Temp* OR *\\\\appdata\\\\local\\\\temp* OR *\\\\APPDATA\\\\LOCAL\\\\TEMP*'
    ' OR *\\\\Appdata\\\\Local\\\\Temp* OR *\\\\AppData\\\\Roaming* OR *\\\\appdata\\\\roaming*'
    ' OR *\\\\APPDATA\\\\ROAMING* OR *\\\\Appdata\\\\Roaming* OR *\\\\Users\\\\Public* OR *\\\\users\\\\public*'
    ' OR *\\\\USERS\\\\PUBLIC* OR *C\\:\\\\Windows\\\\Temp* OR *c\\:\\\\windows\\\\temp*'
    ' OR *C\\:\\\\WINDOWS\\\\TEMP*)) AND (process.command_line:(*raw.githubusercontent.com*'
    ' OR *RAW.GITHUBUSERCONTENT.COM* OR *Raw.githubusercontent.com* OR *http\\:\\/\\/* OR *HTTP\\:\\/\\/*'
    ' OR *Http\\:\\/\\/* OR *https\\:\\/\\/* OR *HTTPS\\:\\/\\/* OR *Https\\:\\/\\/*)))'
    ' OR ((process.name:(*\\\\powershell.exe OR *\\\\POWERSHELL.EXE OR *\\\\Powershell.exe'
    ' OR *powershell.exe OR *POWERSHELL.EXE'
    ' OR *Powershell.exe)) AND (dns.question.name:(raw.githubusercontent.com'
    ' OR RAW.GITHUBUSERCONTENT.COM OR Raw.githubusercontent.com))))'
)


def test_convert_t1059_matches_current_output():
    assert ecs.convert(FIXTURE.read_text(encoding="utf-8")) == [GOLDEN_T1059_CASE]


def test_convert_t1059_verbatim_when_case_variants_disabled(monkeypatch):
    monkeypatch.setenv("SF_CASE_VARIANTS", "0")
    assert ecs.convert(FIXTURE.read_text(encoding="utf-8")) == [GOLDEN_T1059_VERBATIM]


def test_pipeline_is_ecs_fieldmap():
    p = ecs.pipeline()
    assert p.name == "sysmon-to-ecs-fieldmap"
    assert p.priority == 100


def test_convert_returns_list_of_str():
    out = ecs.convert(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(out, list) and all(isinstance(q, str) for q in out)


def _rule(selection_field: str) -> str:
    return f"""title: integrity probe
id: 11111111-2222-4333-8444-555555555555
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        {selection_field}: System
    condition: selection
level: low
"""


def test_sigma_integritylevel_maps_to_integration_field():
    # Verified against elastic/integrations (windows sysmon_operational): Sysmon's
    # IntegrityLevel is indexed as winlog.event_data.IntegrityLevel (keyword); ECS core has
    # no integrity-level field, so that is the canonical target for the Sigma name.
    out = ecs.convert(_rule("IntegrityLevel"))
    assert out == ["event.code:1 AND winlog.event_data.IntegrityLevel:System"]


def test_already_qualified_integritylevel_is_unchanged():
    out = ecs.convert(_rule("winlog.event_data.IntegrityLevel"))
    assert out == ["event.code:1 AND winlog.event_data.IntegrityLevel:System"]


_BAD_BASE = ("title: t\nid: 11111111-1111-1111-1111-111111111111\nstatus: test\n{extra}"
             "logsource: {{category: process_creation, product: windows}}\n"
             "detection:\n  s: {{Image|endswith: a.exe}}\n  condition: s\n")


def test_convert_surfaces_real_error_for_null_tags():
    import pytest
    with pytest.raises(Exception) as ei:
        ecs.convert(_BAD_BASE.format(extra="tags:\n"))
    assert not isinstance(ei.value, PermissionError) and "WinError" not in str(ei.value)


def test_convert_surfaces_real_error_for_string_falsepositives():
    import pytest
    from sigma.exceptions import SigmaFalsePositivesError
    with pytest.raises(SigmaFalsePositivesError, match="falsepositives must be a list"):
        ecs.convert(_BAD_BASE.format(extra="falsepositives: none\n"))
