"""Sigma -> Lucene conversion with the ECS field map (single shared copy).

Moved verbatim from deploy_rule.py / validate_rule.py (previously duplicated).
Our Elastic data is ECS-normalized, but the pySigma sysmon pipeline emits raw
Sysmon names (EventID, Image, ...). Without this map, deployed rules are
enabled and scheduled yet match nothing. Runs late (high priority number).
"""
from __future__ import annotations

import os
import tempfile

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline as windows_pipeline
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    FieldMappingTransformation,
)


def pipeline() -> ProcessingPipeline:
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


def _backend() -> LuceneBackend:
    resolver = ProcessingPipelineResolver()
    resolver.add_pipeline_class(windows_pipeline())
    resolver.add_pipeline_class(sysmon_pipeline())
    resolved = resolver.resolve(resolver.pipelines) + pipeline()
    return LuceneBackend(processing_pipeline=resolved)


def convert_path(rule_path: str) -> list[str]:
    return list(_backend().convert(SigmaCollection.load_ruleset([str(rule_path)])))


def convert(rule_yaml: str) -> list[str]:
    """Convert Sigma YAML text to a list of Lucene queries (ECS field names)."""
    fd, tmp_path = tempfile.mkstemp(suffix=".yml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(rule_yaml)
        return convert_path(tmp_path)
    finally:
        os.unlink(tmp_path)
