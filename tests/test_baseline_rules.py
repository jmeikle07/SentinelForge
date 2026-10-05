"""Characterization test: every shipped Sigma rule must parse and convert."""
from pathlib import Path

import pytest
import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    FieldMappingTransformation,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "detections" / "sigma"


def _ecs_pipeline():
    return ProcessingPipeline(name="sysmon-to-ecs-fieldmap", priority=100, items=[
        ProcessingItem(
            transformation=DropDetectionItemTransformation(),
            field_name_conditions=[IncludeFieldCondition(fields=["Channel"])],
        ),
        ProcessingItem(transformation=FieldMappingTransformation({
            "EventID": "event.code",
            "Image": "process.executable",
            "ParentImage": "process.parent.executable",
            "CommandLine": "process.command_line",
            "ParentCommandLine": "process.parent.command_line",
            "TargetFilename": "file.path",
            "DestinationIp": "destination.ip",
            "DestinationPort": "destination.port",
            "User": "user.name",
        })),
    ])


def _backend():
    resolver = ProcessingPipelineResolver()
    resolver.add_pipeline_class(windows_logsource_pipeline())
    resolver.add_pipeline_class(sysmon_pipeline())
    resolved = resolver.resolve(resolver.pipelines) + _ecs_pipeline()
    return LuceneBackend(processing_pipeline=resolved)


def test_all_sigma_rules_parse_and_convert():
    files = sorted(RULES_DIR.glob("*.yml"))
    assert len(files) == 39
    backend = _backend()
    errors = {}
    for f in files:
        try:
            yaml.safe_load(f.read_text(encoding="utf-8"))
            queries = backend.convert(SigmaCollection.load_ruleset([str(f)]))
            if not queries:
                errors[f.name] = "no query produced"
        except Exception as exc:  # noqa: BLE001 - collecting all failures
            errors[f.name] = f"{type(exc).__name__}: {exc}"
    assert errors == {}, f"{len(errors)} conversion errors: {errors}"
