"""Parser for ``journalctl -o json`` records from sshd.

Newer distributions (Debian 12 minimal, Fedora, Arch, ...) no longer ship
rsyslog, so there is no /var/log/auth.log. journald exports one JSON object
per line; the interesting keys are MESSAGE, __REALTIME_TIMESTAMP
(microseconds since the epoch), _HOSTNAME and SYSLOG_IDENTIFIER.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import Event
from .auth import parse_sshd_message

_SSHD_IDENTIFIERS = frozenset({"sshd", "sshd-session"})


class JournaldParser:
    name = "journald"

    def parse(self, line: str) -> Event | None:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(record, dict):
            return None
        ident = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM")
        if ident not in _SSHD_IDENTIFIERS:
            return None
        message = record.get("MESSAGE")
        if isinstance(message, list):  # journald encodes non-UTF-8 messages as byte arrays
            message = bytes(message).decode("utf-8", "replace")
        if not isinstance(message, str):
            return None
        try:
            ts = datetime.fromtimestamp(int(record["__REALTIME_TIMESTAMP"]) / 1_000_000, tz=UTC)
        except (KeyError, ValueError, TypeError):
            return None
        event = parse_sshd_message(message, ts, record.get("_HOSTNAME"), self.name, message)
        if event is not None and record.get("__CURSOR"):
            event.fields["cursor"] = record["__CURSOR"]
        return event
