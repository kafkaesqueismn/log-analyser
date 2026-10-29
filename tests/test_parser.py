import unittest
from datetime import datetime

from log_analyser.parser import ACCEPTED, FAILED, INVALID_USER, parse_lines


def parse(*lines, year=2026):
    return list(parse_lines(lines, year=year))


class ParserTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        [ev] = parse("Oct 28 12:00:01 web01 sshd[123]: Failed password for root from 203.0.113.5 port 5000 ssh2")
        self.assertEqual(ev.kind, FAILED)
        self.assertEqual(ev.user, "root")
        self.assertEqual(ev.ip, "203.0.113.5")
        self.assertEqual(ev.method, "password")
        self.assertEqual(ev.timestamp, datetime(2026, 10, 28, 12, 0, 1))

    def test_failed_password_invalid_user(self):
        [ev] = parse("Oct 28 12:00:01 web01 sshd[123]: Failed password for invalid user admin "
                     "from 203.0.113.5 port 5000 ssh2")
        self.assertEqual((ev.kind, ev.user), (FAILED, "admin"))

    def test_failed_publickey(self):
        [ev] = parse("Oct 28 12:00:01 web01 sshd[1]: Failed publickey for bob from 10.0.0.1 port 22 ssh2: "
                     "RSA SHA256:abc")
        self.assertEqual((ev.kind, ev.method, ev.user), (FAILED, "publickey", "bob"))

    def test_empty_username(self):
        [ev] = parse("Oct 28 12:00:01 web01 sshd[1]: Failed password for invalid user  from 192.0.2.1 "
                     "port 22 ssh2")
        self.assertEqual((ev.kind, ev.user, ev.ip), (FAILED, "", "192.0.2.1"))

    def test_accepted(self):
        [ev] = parse("Oct  3 09:05:00 web01 sshd[9]: Accepted publickey for alice from 10.0.0.21 port 51234 "
                     "ssh2: ED25519 SHA256:xyz")
        self.assertEqual((ev.kind, ev.user, ev.method), (ACCEPTED, "alice", "publickey"))
        self.assertEqual(ev.timestamp, datetime(2026, 10, 3, 9, 5, 0))  # single-digit day, padded

    def test_invalid_user_line(self):
        [ev] = parse("Oct 28 12:00:00 web01 sshd[1]: Invalid user oracle from 198.51.100.7 port 40000")
        self.assertEqual((ev.kind, ev.user), (INVALID_USER, "oracle"))

    def test_ipv6_address(self):
        [ev] = parse("Oct 28 12:00:00 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2")
        self.assertEqual(ev.ip, "2001:db8::1")

    def test_iso_timestamp(self):
        [ev] = parse("2026-10-28T12:00:01.123456+00:00 web01 sshd[1]: Accepted password for bob "
                     "from 10.0.0.34 port 22 ssh2")
        self.assertEqual(ev.timestamp, datetime(2026, 10, 28, 12, 0, 1, 123456))
        self.assertIsNone(ev.timestamp.tzinfo)

    def test_ignores_irrelevant_lines(self):
        events = parse(
            "Oct 28 12:00:00 web01 CRON[5]: pam_unix(cron:session): session opened for user root",
            "Oct 28 12:00:00 web01 sshd[1]: Connection closed by 198.51.100.3 port 22 [preauth]",
            "Oct 28 12:00:00 web01 sshd[1]: pam_unix(sshd:session): session opened for user bob(uid=1001)",
            "Oct 28 12:00:00 web01 sudo:   bob : TTY=pts/0 ; COMMAND=/bin/ls",
            "garbage line",
            "",
        )
        self.assertEqual(events, [])

    def test_year_rollover(self):
        events = parse(
            "Dec 31 23:59:58 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "Jan  1 00:00:02 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            year=2025,
        )
        self.assertEqual([e.timestamp.year for e in events], [2025, 2026])

    def test_invalid_date_skipped(self):
        self.assertEqual(parse("Feb 30 12:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"), [])


if __name__ == "__main__":
    unittest.main()
