"""Persistence for events, alerts and source offsets.

``Storage`` is the interface the rest of the code depends on. ``SQLiteStorage``
is the only implementation: SQLite in WAL mode handles one writer (the
monitor) plus concurrent readers (the dashboard) without any server process.
The SQL sticks to the portable subset, so a PostgreSQL backend would mostly
be a matter of swapping the driver and placeholders.

Timestamps are stored as UTC epoch seconds (REAL) to make range queries and
hourly bucketing trivial.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .models import Alert, Event
from .sources import SourceState

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          REAL    NOT NULL,
    source      TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    src_ip      TEXT,
    user        TEXT,
    host        TEXT,
    country     TEXT,
    suspicious  INTEGER NOT NULL DEFAULT 0,
    tags        TEXT,
    fields      TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type_ts  ON events(type, ts);
CREATE INDEX IF NOT EXISTS idx_events_ip       ON events(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT    PRIMARY KEY,
    ts          REAL    NOT NULL,
    rule_id     TEXT    NOT NULL,
    rule_name   TEXT    NOT NULL,
    severity    INTEGER NOT NULL,
    key         TEXT    NOT NULL,
    src_ip      TEXT,
    country     TEXT,
    message     TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    mitre       TEXT,
    sample      TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_ts ON alerts(rule_id, ts);

CREATE TABLE IF NOT EXISTS source_state (
    key      TEXT PRIMARY KEY,
    inode    INTEGER NOT NULL DEFAULT 0,
    offset   INTEGER NOT NULL DEFAULT 0,
    cursor   TEXT,
    updated  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# One SSH login attempt. With password auth OpenSSH logs both "Invalid user X" and
# "Failed password for invalid user X" for the same attempt, so the latter is skipped;
# key-only servers only log the former, plus "authenticating user ... [preauth]"
# disconnects for existing accounts (stored as ssh_failed with method "preauth").
SSH_ATTEMPT = (
    "(type = 'ssh_invalid_user' OR (type = 'ssh_failed'"
    " AND COALESCE(json_extract(fields, '$.invalid_user'), 0) = 0))"
)


def _epoch(ts: datetime) -> float:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat(timespec="seconds")


class Storage(Protocol):
    """What the monitor, the dashboard and ``siem stats`` need from a backend."""

    def add_events(self, events: Iterable[Event]) -> None: ...
    def add_alert(self, alert: Alert) -> None: ...
    def commit(self, states: Sequence[SourceState] = ()) -> None: ...
    def load_state(self, key: str) -> SourceState | None: ...
    def save_state(self, state: SourceState) -> None: ...
    def prune(self, older_than_days: int) -> tuple[int, int]: ...
    def close(self) -> None: ...

    # read side
    def summary(self, since: float) -> dict[str, Any]: ...
    def top_ips(self, since: float, limit: int = 10) -> list[dict[str, Any]]: ...
    def top_users(self, since: float, limit: int = 10) -> list[dict[str, Any]]: ...
    def countries(self, since: float) -> list[dict[str, Any]]: ...
    def hourly(self, since: float) -> list[dict[str, Any]]: ...
    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]: ...
    def alerts_by_rule(self, since: float) -> list[dict[str, Any]]: ...
    def mitre_counts(self, since: float) -> list[dict[str, Any]]: ...


class SQLiteStorage:
    def __init__(self, path: str | Path, *, readonly: bool = False) -> None:
        self.path = str(path)
        self.readonly = readonly
        if readonly:
            uri = Path(self.path).resolve().as_uri() + "?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10)
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(_SCHEMA)
            self.conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row

    # -- write side --------------------------------------------------------
    def add_events(self, events: Iterable[Event]) -> None:
        self.conn.executemany(
            "INSERT INTO events (ts, source, type, src_ip, user, host, country, suspicious,"
            " tags, fields, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    _epoch(e.ts),
                    e.source,
                    e.type,
                    e.src_ip,
                    e.user,
                    e.host,
                    e.country,
                    int(e.suspicious),
                    ",".join(e.tags) or None,
                    json.dumps(e.fields, default=str) if e.fields else None,
                    e.raw[:2000],
                )
                for e in events
            ],
        )

    def add_alert(self, alert: Alert) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO alerts (id, ts, rule_id, rule_name, severity, key, src_ip,"
            " country, message, count, mitre, sample) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                alert.id,
                _epoch(alert.ts),
                alert.rule_id,
                alert.rule_name,
                int(alert.severity),
                alert.key,
                alert.src_ip,
                alert.country,
                alert.message,
                alert.count,
                json.dumps(alert.mitre),
                alert.sample,
            ),
        )

    def commit(self, states: Sequence[SourceState] = ()) -> None:
        """Commit buffered rows together with the source offsets they correspond to."""
        for state in states:
            self.save_state(state, commit=False)
        self.conn.commit()

    def load_state(self, key: str) -> SourceState | None:
        row = self.conn.execute(
            "SELECT key, inode, offset, cursor FROM source_state WHERE key = ?", (key,)
        ).fetchone()
        return SourceState(row[0], row[1], row[2], row[3]) if row else None

    def save_state(self, state: SourceState, *, commit: bool = True) -> None:
        self.conn.execute(
            "INSERT INTO source_state (key, inode, offset, cursor, updated) VALUES (?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET inode=excluded.inode, offset=excluded.offset,"
            " cursor=excluded.cursor, updated=excluded.updated",
            (state.key, state.inode, state.offset, state.cursor, time.time()),
        )
        if commit:
            self.conn.commit()

    def prune(self, older_than_days: int) -> tuple[int, int]:
        """Delete events and alerts older than the retention period."""
        cutoff = time.time() - older_than_days * 86400
        ev = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
        al = self.conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,)).rowcount
        self.conn.commit()
        return ev, al

    def close(self) -> None:
        if not self.readonly:
            self.conn.commit()
        self.conn.close()

    # -- read side ---------------------------------------------------------
    def _all(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def summary(self, since: float) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT"
            " (SELECT COUNT(*) FROM events WHERE ts >= :s) AS events,"
            f" (SELECT COUNT(*) FROM events WHERE ts >= :s AND {SSH_ATTEMPT}) AS ssh_attempts,"
            " (SELECT COUNT(*) FROM events WHERE ts >= :s AND type = 'ssh_accepted')"
            "   AS ssh_logins,"
            " (SELECT COUNT(*) FROM events WHERE ts >= :s AND type = 'http_request'"
            "   AND suspicious = 1) AS http_suspicious,"
            " (SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts >= :s AND suspicious = 1)"
            "   AS attacker_ips,"
            f" (SELECT COUNT(DISTINCT user) FROM events WHERE ts >= :s AND {SSH_ATTEMPT})"
            "   AS usernames,"
            " (SELECT COUNT(*) FROM alerts WHERE ts >= :s) AS alerts,"
            " (SELECT MIN(ts) FROM events) AS first_event,"
            " (SELECT MAX(ts) FROM events) AS last_event",
            {"s": since},
        ).fetchone()
        out = dict(row)
        for k in ("first_event", "last_event"):
            out[k] = _iso(out[k]) if out[k] is not None else None
        return out

    def top_ips(self, since: float, limit: int = 10) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT src_ip AS ip, MAX(country) AS country, COUNT(*) AS count,"
            f" SUM(CASE WHEN {SSH_ATTEMPT} THEN 1 ELSE 0 END) AS ssh,"
            " SUM(CASE WHEN type = 'http_request' THEN 1 ELSE 0 END) AS http,"
            " MIN(ts) AS first_seen, MAX(ts) AS last_seen"
            " FROM events WHERE ts >= ? AND suspicious = 1 AND src_ip IS NOT NULL"
            " GROUP BY src_ip ORDER BY count DESC, ip LIMIT ?",
            (since, limit),
        )
        for r in rows:
            r["first_seen"], r["last_seen"] = _iso(r["first_seen"]), _iso(r["last_seen"])
        return rows

    def top_users(self, since: float, limit: int = 10) -> list[dict[str, Any]]:
        return self._all(
            "SELECT user, COUNT(*) AS count, COUNT(DISTINCT src_ip) AS ips FROM events"
            f" WHERE ts >= ? AND {SSH_ATTEMPT} AND user IS NOT NULL AND user != ''"
            " GROUP BY user ORDER BY count DESC, user LIMIT ?",
            (since, limit),
        )

    def countries(self, since: float) -> list[dict[str, Any]]:
        return self._all(
            "SELECT COALESCE(country, '??') AS country, COUNT(*) AS count,"
            " COUNT(DISTINCT src_ip) AS ips"
            " FROM events WHERE ts >= ? AND suspicious = 1"
            " GROUP BY COALESCE(country, '??') ORDER BY count DESC",
            (since,),
        )

    def hourly(self, since: float) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT CAST(ts / 3600 AS INTEGER) * 3600 AS hour,"
            f" SUM(CASE WHEN {SSH_ATTEMPT} THEN 1 ELSE 0 END) AS ssh_attempts,"
            " SUM(CASE WHEN type = 'http_request' AND suspicious = 1 THEN 1 ELSE 0 END)"
            "   AS http_suspicious"
            " FROM events WHERE ts >= ? GROUP BY hour",
            (since,),
        )
        alerts = {
            r["hour"]: r["alerts"]
            for r in self._all(
                "SELECT CAST(ts / 3600 AS INTEGER) * 3600 AS hour, COUNT(*) AS alerts"
                " FROM alerts WHERE ts >= ? GROUP BY hour",
                (since,),
            )
        }
        by_hour = {r["hour"]: r for r in rows}
        start = int(since // 3600) * 3600
        end = int(time.time() // 3600) * 3600
        if by_hour or alerts:
            end = max(end, *by_hour.keys(), *alerts.keys())
        out = []
        for hour in range(start, end + 1, 3600):
            r = by_hour.get(hour, {})
            out.append(
                {
                    "hour": _iso(hour),
                    "ssh_attempts": r.get("ssh_attempts", 0) or 0,
                    "http_suspicious": r.get("http_suspicious", 0) or 0,
                    "alerts": alerts.get(hour, 0),
                }
            )
        return out

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT id, ts, rule_id, rule_name, severity, key, src_ip, country, message, count,"
            " mitre, sample FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        for r in rows:
            r["ts"] = _iso(r["ts"])
            r["mitre"] = json.loads(r["mitre"] or "[]")
        return rows

    def alerts_by_rule(self, since: float) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT rule_id, MAX(rule_name) AS rule_name, MAX(severity) AS severity,"
            " COUNT(*) AS count, MAX(mitre) AS mitre, MAX(ts) AS last_seen"
            " FROM alerts WHERE ts >= ? GROUP BY rule_id ORDER BY count DESC",
            (since,),
        )
        for r in rows:
            r["mitre"] = json.loads(r["mitre"] or "[]")
            r["last_seen"] = _iso(r["last_seen"])
        return rows

    def mitre_counts(self, since: float) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        for (mitre,) in self.conn.execute("SELECT mitre FROM alerts WHERE ts >= ?", (since,)):
            for tid in json.loads(mitre or "[]"):
                counts[tid] = counts.get(tid, 0) + 1
        return [
            {"technique": t, "count": c}
            for t, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]
