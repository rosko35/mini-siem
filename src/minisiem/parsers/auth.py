"""Parser for sshd messages in /var/log/auth.log (or /var/log/secure).

Two timestamp layouts are supported:

* classic BSD syslog:  ``Nov 18 10:15:01 web1 sshd[1234]: ...``
* RFC 3339 (rsyslog high-precision template, default on Debian 12+ /
  Ubuntu 24.04): ``2026-11-18T10:15:01.123456+00:00 web1 sshd[1234]: ...``

OpenSSH 9.8+ logs from the ``sshd-session`` binary instead of ``sshd``,
so both program names are accepted.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, tzinfo

from ..models import Event, EventType

_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)

_SSHD_PROGRAMS = frozenset({"sshd", "sshd-session"})

_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)
_INVALID = re.compile(
    r"^Invalid user (?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+)(?: port (?P<port>\d+))?\s*$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) "
    r"port (?P<port>\d+)"
)

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _local_tz() -> tzinfo:
    tz = datetime.now().astimezone().tzinfo
    assert tz is not None
    return tz


def parse_classic_ts(mon: str, day: str, clock: str, tz: tzinfo, now: datetime) -> datetime:
    """Classic syslog has no year: assume the current one, unless that lands
    more than a day in the future (log written last December, read in January)."""
    hh, mm, ss = (int(x) for x in clock.split(":"))
    ts = datetime(now.year, _MONTHS[mon], int(day), hh, mm, ss, tzinfo=tz)
    if ts - now > timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def parse_sshd_message(
    msg: str, ts: datetime, host: str | None, source: str, raw: str
) -> Event | None:
    """Turn the message part of an sshd log line into an Event (or None)."""
    msg = msg.strip()
    if m := _FAILED.match(msg):
        return Event(
            ts=ts,
            source=source,
            type=EventType.SSH_FAILED,
            src_ip=m["ip"],
            user=m["user"],
            host=host,
            fields={
                "method": m["method"],
                "port": int(m["port"]),
                "invalid_user": bool(m["invalid"]),
            },
            raw=raw,
        )
    if m := _INVALID.match(msg):
        return Event(
            ts=ts,
            source=source,
            type=EventType.SSH_INVALID_USER,
            src_ip=m["ip"],
            user=m["user"],
            host=host,
            fields={"port": int(m["port"]) if m["port"] else None},
            raw=raw,
        )
    if m := _ACCEPTED.match(msg):
        return Event(
            ts=ts,
            source=source,
            type=EventType.SSH_ACCEPTED,
            src_ip=m["ip"],
            user=m["user"],
            host=host,
            fields={"method": m["method"], "port": int(m["port"])},
            raw=raw,
        )
    return None


class AuthLogParser:
    name = "auth"

    def __init__(self, tz: tzinfo | None = None, now: datetime | None = None) -> None:
        self.tz = tz or _local_tz()
        self._fixed_now = now

    def parse(self, line: str) -> Event | None:
        line = line.rstrip("\r\n")
        if "sshd" not in line:  # cheap pre-filter: auth.log is mostly sudo/cron/systemd
            return None
        if m := _RFC3339.match(line):
            try:
                ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
            except ValueError:
                return None
        elif m := _CLASSIC.match(line):
            now = self._fixed_now or datetime.now(self.tz)
            try:
                ts = parse_classic_ts(m["mon"], m["day"], m["time"], self.tz, now)
            except (KeyError, ValueError):
                return None
        else:
            return None
        if m["prog"] not in _SSHD_PROGRAMS:
            return None
        return parse_sshd_message(m["msg"], ts, m["host"], self.name, line)
