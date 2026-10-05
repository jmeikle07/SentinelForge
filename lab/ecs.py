"""Sigma -> Lucene conversion with the ECS field map (single shared copy).

Moved verbatim from deploy_rule.py / validate_rule.py (previously duplicated).

Case sensitivity: Sigma matches strings case-insensitively but the rendered Lucene
query_string does not on keyword / wildcard typed fields. A late pipeline step
(CaseVariantTransformation) therefore expands string literals on Windows
case-insensitive fields into a small bounded set of case variants at conversion
time; rule YAML is untouched. See docs/ARCHITECTURE.md, "Case sensitivity".

Our Elastic data is ECS-normalized, but the pySigma sysmon pipeline emits raw
Sysmon names (EventID, Image, ...). Without this map, deployed rules are
enabled and scheduled yet match nothing. Runs late (high priority number).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionOR
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline as windows_pipeline
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.transformations import (
    DetectionItemTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString, SpecialChars

log = logging.getLogger("lab.ecs")

# ---------------------------------------------------------------------------
# Case-variant expansion
# ---------------------------------------------------------------------------
# Fields whose values Windows treats case-insensitively (binary / path / registry / DNS names
# and command lines). Deliberately NOT covered: hashes, event.code / event.action, ports,
# IPs, registry DATA (registry.data.strings: the written value, case can matter),
# winlog.event_data.IntegrityLevel (Sysmon emits a fixed vocabulary), Description / Product /
# Company (free text), GrantedAccess / StartAddress / CallTrace (hex), anything unlisted.
CASE_INSENSITIVE_FIELDS = frozenset({
    "process.name", "process.executable", "process.command_line", "process.working_directory",
    "process.pe.original_file_name",
    "process.parent.name", "process.parent.executable", "process.parent.command_line",
    "process.parent.working_directory",
    "file.name", "file.path", "file.directory", "file.extension",
    "dll.name", "dll.path",
    "registry.path", "registry.key", "registry.value",
    "dns.question.name", "source.domain", "destination.domain",
    "user.name", "user.domain",
    # Sysmon fields that have no ECS core field and stay under winlog.event_data.*
    "winlog.event_data.Image", "winlog.event_data.ParentImage",
    "winlog.event_data.SourceImage", "winlog.event_data.TargetImage",
    "winlog.event_data.ImageLoaded", "winlog.event_data.CommandLine",
    "winlog.event_data.ParentCommandLine", "winlog.event_data.CurrentDirectory",
    "winlog.event_data.TargetFilename", "winlog.event_data.TargetObject",
    "winlog.event_data.PipeName", "winlog.event_data.OriginalFileName",
    "winlog.event_data.QueryName",
})

CASE_VARIANTS = True          # module default; env SF_CASE_VARIANTS=0 turns the step off
MAX_CASE_VARIANTS = 4         # hard cap per literal: as written, lower, UPPER, Title
QUERY_CLAUSE_BUDGET = 200     # max leaf clauses per generated query
SMALL_LIST_MAX = 10           # last-resort tier: only expand items with at most this many values

# (max variants per literal, max values of an item to expand or None). The first tier that
# fits QUERY_CLAUSE_BUDGET wins; if none fits the rule is converted without expansion.
_TIERS: tuple[tuple[int, Optional[int]], ...] = (
    (MAX_CASE_VARIANTS, None),
    (3, None),                 # as written + lower + UPPER
    (3, SMALL_LIST_MAX),       # ... and only for short value lists
)
_AUTO = object()
_WARNED: set[tuple[str, str]] = set()
# Title-case word starts: after these characters (and after wildcards / the string start) the
# next letter is capitalised. "." is NOT one, so "cmd.exe" becomes "Cmd.exe", not "Cmd.Exe".
_TITLE_BOUNDARY = frozenset(" \t\\/:-=,;\"'(")


def case_variants_enabled() -> bool:
    return os.environ.get("SF_CASE_VARIANTS", "1" if CASE_VARIANTS else "0").strip() != "0"


def is_case_insensitive_field(field: Optional[str]) -> bool:
    return field in CASE_INSENSITIVE_FIELDS


def _map_parts(parts, mode: str) -> tuple:
    out = []
    boundary = True
    for p in parts:
        if not isinstance(p, str):  # wildcard: next letter starts a word
            out.append(p)
            boundary = True
        elif mode == "lower":
            out.append(p.lower())
        elif mode == "upper":
            out.append(p.upper())
        else:
            chars = []
            for ch in p:
                chars.append(ch.upper() if boundary else ch.lower())
                boundary = ch in _TITLE_BOUNDARY
            out.append("".join(chars))
    return tuple(out)


def _variant_parts(parts: tuple, max_variants: int) -> list[tuple]:
    seen: list[tuple] = []
    for cand in (tuple(parts), _map_parts(parts, "lower"), _map_parts(parts, "upper"),
                 _map_parts(parts, "title")):
        if cand not in seen:
            seen.append(cand)
    return seen[:max(1, max_variants)]


def case_variants(text: str, max_variants: int = MAX_CASE_VARIANTS) -> list[str]:
    """Bounded case variants of a plain string: as written, lower, UPPER, Title (deduplicated)."""
    return ["".join(v) for v in _variant_parts((text,), max_variants)]


def clause_count(query: str) -> int:
    """Leaf clauses of a generated query (values are space-escaped, so raw ' OR '/' AND ' are operators)."""
    return 1 + query.count(" OR ") + query.count(" AND ")


def _expandable(value) -> bool:
    # exact type: SigmaCasedString (|cased) and every non-string type are left alone
    return type(value) is SigmaString and all(isinstance(p, (str, SpecialChars)) for p in value.s)


def _blocked_modifiers(item: SigmaDetectionItem) -> bool:
    # base64 / wide / utf16 produce encoded text where the case is part of the data
    return any(any(tag in m.__name__ for tag in ("Base64", "Wide", "Utf16", "UTF16", "Cased"))
               for m in item.modifiers)


def _string_from_parts(parts: tuple) -> SigmaString:
    s = SigmaString.from_str("")
    s.s = parts
    s.original = "".join(
        p if isinstance(p, str) else "*" if p is SpecialChars.WILDCARD_MULTI else "?" for p in parts)
    return s


@dataclass
class CaseVariantTransformation(DetectionItemTransformation):
    """Expand string literals of case-insensitive fields into bounded case variants."""

    max_variants: int = MAX_CASE_VARIANTS
    max_item_values: Optional[int] = None

    def apply(self, pipeline, rule) -> None:
        product = getattr(getattr(rule, "logsource", None), "product", None)
        self._skip = product is not None and str(product).lower() != "windows"
        super().apply(pipeline, rule)

    def apply_detection_item(self, item):
        if self._skip or not is_case_insensitive_field(item.field) or _blocked_modifiers(item):
            return None
        if self.max_item_values is not None and len(item.value) > self.max_item_values:
            return None
        groups = []
        for v in item.value:
            groups.append([_string_from_parts(p) for p in _variant_parts(v.s, self.max_variants)]
                          if _expandable(v) else [v])
        if all(len(g) == 1 for g in groups):
            return None
        if item.value_linking is ConditionAND and len(groups) > 1:
            # contains|all: every value stays required, each as an OR of its own variants
            return SigmaDetection([SigmaDetectionItem(item.field, [], g, ConditionOR, item.source)
                                   for g in groups], item_linking=ConditionAND)
        merged, seen = [], set()
        for g in groups:
            for v in g:
                key = v.s if isinstance(v, SigmaString) else id(v)
                if key not in seen:   # also dedupes against hand-written case variants
                    seen.add(key)
                    merged.append(v)
        return SigmaDetectionItem(item.field, [], merged, ConditionOR, item.source)


def pipeline(case_tier=_AUTO) -> ProcessingPipeline:
    """ECS field map (+ case-variant step). case_tier: (max_variants, max_item_values), None = off."""
    if case_tier is _AUTO:
        case_tier = _TIERS[0] if case_variants_enabled() else None
    items = [
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
            # No ECS core field exists for integrity level; the Elastic Agent / Winlogbeat
            # Sysmon integration indexes it as winlog.event_data.IntegrityLevel.
            "IntegrityLevel": "winlog.event_data.IntegrityLevel",
        })),
    ]
    if case_tier is not None:
        items.append(ProcessingItem(transformation=CaseVariantTransformation(*case_tier)))
    return ProcessingPipeline(name="sysmon-to-ecs-fieldmap", priority=100, items=items)


def _backend(case_tier=_AUTO) -> LuceneBackend:
    resolver = ProcessingPipelineResolver()
    resolver.add_pipeline_class(windows_pipeline())
    resolver.add_pipeline_class(sysmon_pipeline())
    resolved = resolver.resolve(resolver.pipelines) + pipeline(case_tier)
    return LuceneBackend(processing_pipeline=resolved)


def _convert(load) -> list[str]:
    """Convert with case variants, degrading tier by tier until every query fits the budget."""
    if not case_variants_enabled():
        return list(_backend(None).convert(load()))
    for n, tier in enumerate(_TIERS):
        queries = list(_backend(tier).convert(load()))
        if all(clause_count(q) <= QUERY_CLAUSE_BUDGET for q in queries):
            break
    else:
        n, queries = len(_TIERS), list(_backend(None).convert(load()))
    if n:
        titles = ", ".join(r.title for r in load().rules)
        what = ("as written + lower + UPPER" if n == 1 else
                "as written + lower + UPPER on short value lists only" if n == 2 else
                "no case variants (as written only)")
        if (titles, what) not in _WARNED:
            _WARNED.add((titles, what))
            log.warning("rule %r: case-variant expansion exceeds the %d clause budget; using %s",
                        titles, QUERY_CLAUSE_BUDGET, what)
    return queries


def convert_path(rule_path: str) -> list[str]:
    return _convert(lambda: SigmaCollection.load_ruleset([str(rule_path)]))


def convert(rule_yaml: str) -> list[str]:
    """Convert Sigma YAML text to a list of Lucene queries (ECS field names).

    Parses the text directly (no temp file): on Windows the temp-file route leaked an
    open handle when pySigma raised, and the cleanup PermissionError [WinError 32]
    masked the real Sigma error.
    """
    return _convert(lambda: SigmaCollection.from_yaml(rule_yaml))
