import asyncio
import importlib.util
import sqlite3
import sys
from pathlib import Path

from minisiem.monitor import Monitor
from minisiem.notifiers import NotifierHub
from minisiem.parsers import AuthLogParser, NginxParser
from minisiem.storage import SQLiteStorage

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("generate_logs", ROOT / "tools" / "generate_logs.py")
gen = importlib.util.module_from_spec(spec)
sys.modules["generate_logs"] = gen
spec.loader.exec_module(gen)


def test_generated_lines_parse_and_trigger_rules(tmp_path, scenario):
    cfg, _ = scenario
    out = tmp_path / "gen"
    for fmt in ("classic", "rfc3339"):
        assert (
            gen.main(["--out", str(out), "--hours", "6", "--seed", "7", "--auth-format", fmt]) == 0
        )
        auth = (out / "auth.log").read_text(encoding="utf-8").splitlines()
        web = (out / "access.log").read_text(encoding="utf-8").splitlines()
        assert len(auth) > 100 and len(web) > 500
        parser = AuthLogParser()
        assert all(parser.parse(line) is not None for line in auth), "every sshd line parses"
        assert all(NginxParser().parse(line) is not None for line in web)

    storage = SQLiteStorage(cfg.database)
    mon = Monitor(cfg, storage, NotifierHub([]))
    asyncio.run(mon.replay([out / "auth.log"], "auth"))
    asyncio.run(mon.replay([out / "access.log"], "nginx"))
    storage.close()
    con = sqlite3.connect(cfg.database)
    fired = {r for (r,) in con.execute("SELECT DISTINCT rule_id FROM alerts")}
    con.close()
    for rule in (
        "ssh-bruteforce",
        "ssh-login-after-failures",
        "ssh-root-login",
        "web-directory-scan",
        "web-path-traversal",
        "web-sensitive-file-probe",
    ):
        assert rule in fired, rule


def test_only_documentation_addresses(tmp_path):
    import ipaddress

    gen.main(["--out", str(tmp_path), "--hours", "3", "--seed", "1"])
    doc_nets = [
        ipaddress.ip_network(n)
        for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    ]
    for line in (tmp_path / "access.log").read_text().splitlines():
        ip = ipaddress.ip_address(line.split(" ", 1)[0])
        assert any(ip in n for n in doc_nets), ip


def test_rotation_option(tmp_path):
    gen.main(["--out", str(tmp_path), "--hours", "2", "--seed", "3", "--rotate-after", "50"])
    assert (tmp_path / "access.log.1").exists()
