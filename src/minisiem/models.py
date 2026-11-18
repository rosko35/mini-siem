"""Core data types shared by parsers, the rule engine, storage and notifiers."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any


class EventType:
    """Normalised event type names produced by the parsers."""

    SSH_FAILED = "ssh_failed"
    SSH_INVALID_USER = "ssh_invalid_user"
    SSH_ACCEPTED = "ssh_accepted"
    HTTP_REQUEST = "http_request"

    SSH_FAILURES = frozenset({SSH_FAILED, SSH_INVALID_USER})


BENIGN_404 = frozenset(
    {"/favicon.ico", "/robots.txt", "/sitemap.xml", "/ads.txt", "/.well-known/security.txt"}
)


@dataclass(slots=True)
class Event:
    """A single parsed log line.

    Well-known attributes live on the dataclass; anything parser-specific
    (HTTP method, status, user agent, auth method, ...) goes into ``fields``.
    """

    ts: datetime
    source: str
    type: str
    src_ip: str | None = None
    user: str | None = None
    host: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    country: str | None = None
    # Set by the rule engine when a pattern rule matched this event.
    tags: list[str] = field(default_factory=list)

    def get(self, name: str, default: Any = None) -> Any:
        """Look up a field by name for rules: attributes first, then ``fields``."""
        if name in ("ts", "source", "type", "src_ip", "user", "host", "raw", "country"):
            value = getattr(self, name)
            return default if value is None else value
        if name == "event_type":
            return self.type
        return self.fields.get(name, default)

    @property
    def suspicious(self) -> bool:
        """Heuristic used for the attack map and storage filtering."""
        if self.type in EventType.SSH_FAILURES or self.tags:
            return True
        status = self.fields.get("status")
        if not isinstance(status, int) or status not in (400, 401, 403, 404, 405, 444):
            return False
        # Browsers and crawlers ask for these on every site; a 404 here means nothing.
        path = str(self.fields.get("path", "")).split("?", 1)[0]
        return path not in BENIGN_404 and not path.startswith("/apple-touch-icon")


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def label(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Alert:
    ts: datetime
    rule_id: str
    rule_name: str
    severity: Severity
    key: str
    message: str
    src_ip: str | None = None
    count: int = 1
    mitre: list[str] = field(default_factory=list)
    country: str | None = None
    sample: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
