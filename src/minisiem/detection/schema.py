"""Validated schema for YAML detection rules.

A rules file looks like::

    rules:
      - id: ssh-bruteforce
        name: SSH brute force
        type: threshold          # threshold | pattern | sequence
        severity: high           # low | medium | high | critical
        match: {event_type: ssh_failed}
        group_by: src_ip
        threshold: 5
        window: 60               # seconds
        cooldown: 600            # seconds between alerts for the same rule + key
        mitre: [T1110.001]

See the README for the full reference.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..mitre import TECHNIQUE_RE
from ..models import Severity

Scalar = str | int | float | bool
Conditions = dict[str, Scalar | list[Scalar]]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PatternSpec(_Strict):
    field: str
    regex: list[str] = Field(min_length=1)
    decode: bool = True  # URL-decode (repeatedly) before matching; raw value is checked too
    ignore_case: bool = True

    @field_validator("regex", mode="before")
    @classmethod
    def _listify(cls, v):
        return [v] if isinstance(v, str) else v

    @field_validator("regex")
    @classmethod
    def _compiles(cls, v: list[str]) -> list[str]:
        for expr in v:
            try:
                re.compile(expr)
            except re.error as exc:
                raise ValueError(f"invalid regex {expr!r}: {exc}") from exc
        return v


class _RuleBase(_Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    enabled: bool = True
    match: Conditions = Field(default_factory=dict)
    exclude: Conditions = Field(default_factory=dict)
    group_by: str = "src_ip"
    cooldown: int = Field(default=300, ge=0)
    message: str | None = None
    mitre: list[str] = Field(default_factory=list)

    @field_validator("mitre")
    @classmethod
    def _mitre_ids(cls, v: list[str]) -> list[str]:
        for tid in v:
            if not TECHNIQUE_RE.match(tid):
                raise ValueError(f"not a MITRE ATT&CK technique id: {tid!r}")
        return v

    @property
    def severity_level(self) -> Severity:
        return Severity.parse(self.severity)


class ThresholdRule(_RuleBase):
    """Fire when ``threshold`` matching events (or distinct values of
    ``distinct``) are seen for the same ``group_by`` key within ``window`` seconds."""

    type: Literal["threshold"]
    threshold: int = Field(ge=1)
    window: int = Field(gt=0)
    distinct: str | None = None


class PatternRule(_RuleBase):
    """Fire on a single event that satisfies ``match`` and, if given, any of ``patterns``."""

    type: Literal["pattern"]
    patterns: list[PatternSpec] = Field(default_factory=list)


class SequenceRule(_RuleBase):
    """Fire when an event matching ``followed_by`` arrives after at least
    ``threshold`` events matching ``match`` for the same key within ``window``."""

    type: Literal["sequence"]
    threshold: int = Field(ge=1)
    window: int = Field(gt=0)
    followed_by: Conditions = Field(min_length=1)


Rule = Annotated[ThresholdRule | PatternRule | SequenceRule, Field(discriminator="type")]


class RuleFile(_Strict):
    rules: list[Rule] = Field(default_factory=list)


class RuleError(Exception):
    pass


def load_rules(path: str | Path) -> list[ThresholdRule | PatternRule | SequenceRule]:
    """Load every ``*.yml`` / ``*.yaml`` file in a directory (or a single file)."""
    path = Path(path)
    files = sorted([*path.glob("*.yml"), *path.glob("*.yaml")]) if path.is_dir() else [path]
    if not files:
        raise RuleError(f"no rule files found in {path}")
    rules: list = []
    seen: dict[str, Path] = {}
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            parsed = RuleFile.model_validate(data)
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}") from exc
        except ValidationError as exc:
            raise RuleError(f"{f}: {exc}") from exc
        for rule in parsed.rules:
            if rule.id in seen:
                raise RuleError(f"{f}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})")
            seen[rule.id] = f
            rules.append(rule)
    return rules
