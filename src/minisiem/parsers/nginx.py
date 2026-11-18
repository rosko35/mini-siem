"""Parser for the nginx (and Apache) "combined" access log format.

    $remote_addr - $remote_user [$time_local] "$request" $status
    $body_bytes_sent "$http_referer" "$http_user_agent"

Anything appended after the user agent (e.g. a custom ``$request_time``)
is ignored. If the site sits behind a CDN or reverse proxy, make sure nginx
logs the real client address (``real_ip_header``), otherwise every request
appears to come from the proxy.
"""

from __future__ import annotations

import re
from datetime import datetime

from ..models import Event, EventType

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<ruser>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-)"
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


class NginxParser:
    name = "nginx"

    def parse(self, line: str) -> Event | None:
        line = line.rstrip("\r\n")
        m = _COMBINED.match(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m["time"], _TIME_FMT)
        except ValueError:
            return None

        request = m["request"]
        parts = request.split(" ")
        if len(parts) == 3 and parts[2].startswith("HTTP/"):
            method, path, protocol = parts
        else:
            # Garbage such as TLS handshakes sent to port 80 ("\x16\x03\x01...")
            method, path, protocol = "", request, ""

        ruser = m["ruser"]
        return Event(
            ts=ts,
            source=self.name,
            type=EventType.HTTP_REQUEST,
            src_ip=m["ip"],
            user=None if ruser == "-" else ruser,
            fields={
                "method": method,
                "path": path,
                "protocol": protocol,
                "status": int(m["status"]),
                "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
                "referer": _dash_none(m["referer"]),
                "user_agent": _dash_none(m["ua"]) or "",
            },
            raw=line,
        )


def _dash_none(value: str | None) -> str | None:
    return None if value in (None, "-") else value
