"""Log line parsers. Each parser exposes ``name`` and ``parse(line) -> Event | None``."""

from __future__ import annotations

from datetime import tzinfo
from typing import Protocol

from ..models import Event
from .auth import AuthLogParser
from .journald import JournaldParser
from .nginx import NginxParser


class Parser(Protocol):
    name: str

    def parse(self, line: str) -> Event | None: ...


def get_parser(name: str, tz: tzinfo | None = None) -> Parser:
    if name == "auth":
        return AuthLogParser(tz=tz)
    if name == "nginx":
        return NginxParser()
    if name == "journald":
        return JournaldParser()
    raise ValueError(f"unknown parser: {name!r} (expected auth, nginx or journald)")


__all__ = ["AuthLogParser", "JournaldParser", "NginxParser", "Parser", "get_parser"]
