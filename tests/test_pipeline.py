import asyncio
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

from conftest import auth_line
from minisiem.config import load_config
from minisiem.geoip import GeoIP
from minisiem.monitor import Monitor
from minisiem.notifiers import Notifier, NotifierHub
from minisiem.stats import mask_ip, render_markdown
from minisiem.storage import SQLiteStorage

ROOT = Path(__file__).resolve().parent.parent


class Collect(Notifier):
    name = "collect"

    def __init__(self):
        self.alerts = []

    async def send(self, alert):
        self.alerts.append(alert)


def rows(db_path, sql):
    con = sqlite3.connect(db_path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_replay_end_to_end(scenario):
    cfg, logs = scenario
    storage = SQLiteStorage(cfg.database)
    sink = Collect()
    mon = Monitor(cfg, storage, NotifierHub([sink]))
    asyncio.run(mon.replay([logs / "auth.log"], "auth"))
    asyncio.run(mon.replay([logs / "access.log"], "nginx"))
    storage.close()

    fired = sorted({a.rule_id for a in sink.alerts})
    assert fired == [
        "ssh-bruteforce",
        "web-directory-scan",
        "web-path-traversal",
        "web-scanner-user-agent",
    ]
    stored = dict(rows(cfg.database, "SELECT rule_id, COUNT(*) FROM alerts GROUP BY rule_id"))
    assert stored == {r: 1 for r in fired}
    brute = next(a for a in sink.alerts if a.rule_id == "ssh-bruteforce")
    assert brute.country == "CN"
    assert brute.mitre == ["T1110.001"]

    # Normal HTTP 200s are not stored, attack traffic and all SSH events are.
    types = dict(rows(cfg.database, "SELECT type, COUNT(*) FROM events GROUP BY type"))
    assert types["ssh_failed"] == 8
    assert types["ssh_invalid_user"] == 6
    assert types["ssh_accepted"] == 1
    assert types["http_request"] == 27  # 25 x 404, traversal, sqlmap (5 normal requests dropped)
    assert rows(cfg.database, "PRAGMA journal_mode")[0][0] == "wal"


def test_storage_queries(scenario):
    cfg, logs = scenario
    storage = SQLiteStorage(cfg.database)
    mon = Monitor(cfg, storage, NotifierHub([]))
    asyncio.run(mon.replay([logs / "auth.log"], "auth"))
    asyncio.run(mon.replay([logs / "access.log"], "nginx"))
    since = time.time() - 86400

    s = storage.summary(since)
    # 2 root failures + 6 invalid-user attempts (each logged twice by sshd, counted once)
    assert s["ssh_attempts"] == 8
    assert s["ssh_logins"] == 1
    assert s["usernames"] == 6
    assert s["attacker_ips"] == 4

    users = {u["user"]: u["count"] for u in storage.top_users(since)}
    assert users["root"] == 2 and users["admin"] == 2 and users["pi"] == 1

    ips = storage.top_ips(since, 2)
    assert ips[0]["ip"] == "198.51.100.200" and ips[0]["country"] == "ID"
    assert ips[1]["ip"] == "203.0.113.5" and ips[1]["ssh"] == 8

    countries = {c["country"]: c["count"] for c in storage.countries(since)}
    assert countries["CN"] == 14 and countries["RU"] == 1 and countries["US"] == 1

    hourly = storage.hourly(since)
    assert len(hourly) >= 24
    assert sum(h["ssh_attempts"] for h in hourly) == 8
    assert sum(h["alerts"] for h in hourly) == 4

    by_rule = {r["rule_id"]: r for r in storage.alerts_by_rule(since)}
    assert by_rule["web-path-traversal"]["mitre"] == ["T1190", "T1083"]
    techniques = {m["technique"] for m in storage.mitre_counts(since)}
    assert {"T1110.001", "T1595.003", "T1190", "T1595.002"} <= techniques
    assert len(storage.recent_alerts(2)) == 2
    storage.close()


def test_live_monitor_follows_and_resumes(scenario, now):
    cfg, logs = scenario
    sink = Collect()

    async def run_until(predicate, timeout=10.0):
        storage = SQLiteStorage(cfg.database)
        mon = Monitor(cfg, storage, NotifierHub([sink]))
        stop = asyncio.Event()
        task = asyncio.create_task(mon.run(stop))
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        stop.set()
        await task
        storage.close()

    asyncio.run(run_until(lambda: len(sink.alerts) >= 4))
    assert len(sink.alerts) == 4
    first_events = rows(cfg.database, "SELECT COUNT(*) FROM events")[0][0]
    states = rows(cfg.database, "SELECT key, offset FROM source_state")
    assert len(states) == 2 and all(offset > 0 for _, offset in states)

    # New brute force appended while the monitor is stopped is picked up on restart,
    # and nothing that was already processed is read again.
    with open(logs / "auth.log", "a", encoding="utf-8") as fh:
        for i in range(5):
            t = now + timedelta(hours=1, seconds=i)
            fh.write(auth_line(t, f"Failed password for root from 203.0.113.99 port {i} ssh2"))
            fh.write("\n")
    asyncio.run(run_until(lambda: len(sink.alerts) >= 5))
    assert [a.key for a in sink.alerts[4:]] == ["203.0.113.99"]
    assert rows(cfg.database, "SELECT COUNT(*) FROM events")[0][0] == first_events + 5


def test_retention_prune(scenario):
    cfg, logs = scenario
    storage = SQLiteStorage(cfg.database)
    mon = Monitor(cfg, storage, NotifierHub([]))
    asyncio.run(mon.replay([logs / "auth.log"], "auth"))
    storage.conn.execute("UPDATE events SET ts = ts - 40 * 86400 WHERE type = 'ssh_failed'")
    storage.conn.commit()
    deleted, _ = storage.prune(30)
    assert deleted == 8
    storage.close()


def test_stats_markdown(scenario):
    cfg, logs = scenario
    storage = SQLiteStorage(cfg.database)
    mon = Monitor(cfg, storage, NotifierHub([]))
    asyncio.run(mon.replay([logs / "auth.log"], "auth"))
    asyncio.run(mon.replay([logs / "access.log"], "nginx"))
    md = render_markdown(storage, days=30)
    storage.close()
    assert "| SSH login attempts | 8 |" in md
    assert "| 1 | `admin` | 2 | 1 |" in md or "| 1 | `root` | 2 | 1 |" in md
    assert "`203.0.113.x`" in md and "203.0.113.5`" not in md
    assert "China (CN)" in md
    assert "SSH brute force | T1110.001 | 1 |" in md


def test_mask_ip():
    assert mask_ip("203.0.113.42") == "203.0.113.x"
    assert mask_ip("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert mask_ip("not-an-ip") == "not-an-ip"


def test_geoip_without_database_is_unknown(tmp_path):
    geo = GeoIP(database=str(tmp_path / "missing.mmdb"))
    assert geo.lookup("8.8.8.8") is None
    assert not geo.enabled
    geo = GeoIP(static_map=str(ROOT / "demo" / "demo-geo.yml"))
    assert geo.lookup("203.0.113.5") == "CN"
    assert geo.lookup("203.0.113.40") == "RU"
    assert geo.lookup("2001:db8::1") == "FR"
    assert geo.lookup("10.0.0.1") is None
    assert geo.lookup("garbage") is None


def test_shipped_configs_load(monkeypatch):
    monkeypatch.delenv("SIEM_DB", raising=False)
    prod = load_config(ROOT / "config.yml")
    assert prod.dashboard.host == "127.0.0.1"
    assert [s.parser for s in prod.sources] == ["auth", "nginx"]
    demo = load_config(ROOT / "config.demo.yml")
    assert Path(demo.rules).is_dir()
    assert demo.sources[0].from_beginning
