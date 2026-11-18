import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from minisiem.models import EventType
from minisiem.parsers import AuthLogParser, JournaldParser, NginxParser, get_parser

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def auth():
    return AuthLogParser(tz=UTC, now=NOW)


class TestAuthLog:
    def test_failed_password_classic(self, auth):
        line = (
            "Nov 18 10:15:01 web1 sshd[2231]: Failed password for root from 203.0.113.7 "
            "port 52144 ssh2"
        )
        ev = auth.parse(line)
        assert ev is not None
        assert ev.type == EventType.SSH_FAILED
        assert ev.src_ip == "203.0.113.7"
        assert ev.user == "root"
        assert ev.host == "web1"
        assert ev.fields["port"] == 52144
        assert ev.fields["invalid_user"] is False
        assert ev.ts == datetime(2026, 11, 18, 10, 15, 1, tzinfo=UTC)

    def test_failed_password_invalid_user(self, auth):
        line = (
            "Nov  3 04:02:17 web1 sshd[991]: Failed password for invalid user admin from "
            "198.51.100.23 port 40022 ssh2"
        )
        ev = auth.parse(line)
        assert ev.type == EventType.SSH_FAILED
        assert ev.user == "admin"
        assert ev.fields["invalid_user"] is True
        assert ev.ts.day == 3

    def test_invalid_user(self, auth):
        ev = auth.parse(
            "Nov 18 10:15:00 web1 sshd[2230]: Invalid user oracle from 203.0.113.7 port 52140"
        )
        assert ev.type == EventType.SSH_INVALID_USER
        assert ev.user == "oracle"
        assert ev.fields["port"] == 52140

    def test_invalid_user_without_port_old_openssh(self, auth):
        ev = auth.parse("Nov 18 10:15:00 web1 sshd[2230]: Invalid user test from 203.0.113.7")
        assert ev.type == EventType.SSH_INVALID_USER
        assert ev.fields["port"] is None

    def test_accepted_publickey(self, auth):
        ev = auth.parse(
            "Nov 18 09:00:12 web1 sshd[1800]: Accepted publickey for emre from 192.0.2.10 "
            "port 51515 ssh2: ED25519 SHA256:abcdefghijklmnopqrstuvwxyz"
        )
        assert ev.type == EventType.SSH_ACCEPTED
        assert ev.user == "emre"
        assert ev.fields["method"] == "publickey"

    def test_rfc3339_timestamp_and_sshd_session(self, auth):
        line = (
            "2026-11-18T10:15:01.482911+03:00 web1 sshd-session[4410]: Failed password for "
            "invalid user ubuntu from 2001:db8::1f port 61000 ssh2"
        )
        ev = auth.parse(line)
        assert ev.type == EventType.SSH_FAILED
        assert ev.src_ip == "2001:db8::1f"
        assert ev.ts == datetime(
            2026, 11, 18, 10, 15, 1, 482911, tzinfo=timezone(timedelta(hours=3))
        )

    def test_rfc3339_zulu(self, auth):
        ev = auth.parse(
            "2026-11-18T10:15:01Z web1 sshd[1]: Invalid user pi from 203.0.113.9 port 1"
        )
        assert ev.ts == datetime(2026, 11, 18, 10, 15, 1, tzinfo=UTC)

    def test_year_rollover(self):
        parser = AuthLogParser(tz=UTC, now=datetime(2027, 1, 1, 0, 5, tzinfo=UTC))
        ev = parser.parse("Dec 31 23:59:58 web1 sshd[1]: Invalid user a from 203.0.113.9 port 1")
        assert ev.ts.year == 2026

    @pytest.mark.parametrize(
        "line",
        [
            "Nov 18 10:17:01 web1 CRON[3000]: pam_unix(cron:session): session opened for user root",
            "Nov 18 10:17:01 web1 sudo:     emre : TTY=pts/0 ; PWD=/home/emre ; COMMAND=/bin/ls",
            "Nov 18 10:15:01 web1 sshd[2231]: Received disconnect from 203.0.113.7 port 1:11: Bye",
            "Nov 18 10:15:01 web1 notsshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "complete garbage",
            "",
        ],
    )
    def test_ignored_lines(self, auth, line):
        assert auth.parse(line) is None


class TestNginx:
    def test_combined_line(self):
        line = (
            '203.0.113.50 - - [18/Nov/2026:10:20:31 +0100] "GET /wp-login.php HTTP/1.1" 404 153 '
            '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )
        ev = NginxParser().parse(line)
        assert ev.type == EventType.HTTP_REQUEST
        assert ev.src_ip == "203.0.113.50"
        assert ev.fields["method"] == "GET"
        assert ev.fields["path"] == "/wp-login.php"
        assert ev.fields["status"] == 404
        assert ev.fields["bytes"] == 153
        assert ev.fields["referer"] is None
        assert ev.fields["user_agent"].startswith("Mozilla/5.0")
        assert ev.ts == datetime(2026, 11, 18, 9, 20, 31, tzinfo=UTC)

    def test_malformed_request_line(self):
        line = (
            '198.51.100.4 - - [18/Nov/2026:10:20:31 +0000] "\\x16\\x03\\x01\\x00\\xa5\\x01" '
            '400 157 "-" "-"'
        )
        ev = NginxParser().parse(line)
        assert ev.fields["status"] == 400
        assert ev.fields["method"] == ""
        assert ev.fields["path"].startswith("\\x16")
        assert ev.fields["user_agent"] == ""

    def test_ipv6_and_remote_user_and_escaped_quote(self):
        line = (
            '2001:db8::7 - alice [18/Nov/2026:10:20:31 +0000] "GET /a?q=\\"x\\" HTTP/2.0" 200 '
            '- "https://example.org/" "curl/8.5.0"'
        )
        ev = NginxParser().parse(line)
        assert ev.src_ip == "2001:db8::7"
        assert ev.user == "alice"
        assert ev.fields["bytes"] == 0
        assert ev.fields["referer"] == "https://example.org/"

    def test_trailing_custom_fields_ignored(self):
        line = '192.0.2.1 - - [18/Nov/2026:10:20:31 +0000] "GET / HTTP/1.1" 200 612 "-" "ua" 0.004'
        assert NginxParser().parse(line).fields["status"] == 200

    def test_garbage(self):
        assert NginxParser().parse("not an access log line") is None


class TestJournald:
    def record(self, **overrides):
        rec = {
            "__CURSOR": "s=abc;i=1",
            "__REALTIME_TIMESTAMP": "1795000000000000",
            "_HOSTNAME": "web1",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 203.0.113.7 port 52144 ssh2",
        }
        rec.update(overrides)
        return json.dumps(rec)

    def test_failed_password(self):
        ev = JournaldParser().parse(self.record())
        assert ev.type == EventType.SSH_FAILED
        assert ev.src_ip == "203.0.113.7"
        assert ev.host == "web1"
        assert ev.fields["cursor"] == "s=abc;i=1"
        assert ev.ts == datetime.fromtimestamp(1795000000, tz=UTC)

    def test_byte_array_message(self):
        msg = list(b"Invalid user \xff from 203.0.113.7 port 1")
        ev = JournaldParser().parse(self.record(MESSAGE=msg, SYSLOG_IDENTIFIER="sshd-session"))
        assert ev.type == EventType.SSH_INVALID_USER

    def test_other_identifier_ignored(self):
        assert JournaldParser().parse(self.record(SYSLOG_IDENTIFIER="systemd")) is None

    def test_bad_json(self):
        assert JournaldParser().parse("{not json") is None


def test_get_parser_unknown():
    with pytest.raises(ValueError):
        get_parser("apache")
