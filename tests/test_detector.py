import unittest
from datetime import timedelta

from log_analyser.detector import (
    detect_brute_force,
    detect_success_after_failures,
    successful_logins,
    summarise,
)
from log_analyser.parser import parse_lines

from .helpers import BASE, accepted, burst, failed

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)


def events(lines):
    return list(parse_lines(lines, year=2026))


class BruteForceTests(unittest.TestCase):
    def test_exactly_threshold_is_detected(self):
        incidents = detect_brute_force(events(burst(BASE, "1.1.1.1", 5, 10 * SEC)), threshold=5)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual((inc.ip, inc.attempts), ("1.1.1.1", 5))
        self.assertEqual(inc.first_seen, BASE)
        self.assertEqual(inc.last_seen, BASE + 40 * SEC)

    def test_below_threshold_not_detected(self):
        self.assertEqual(detect_brute_force(events(burst(BASE, "1.1.1.1", 4, SEC)), threshold=5), [])

    def test_failures_spread_beyond_window_not_detected(self):
        # 10 failures, one every 2 minutes -> never 5 inside a 5 minute window
        evs = events(burst(BASE, "1.1.1.1", 10, 2 * MIN))
        self.assertEqual(detect_brute_force(evs, threshold=5, window=5 * MIN), [])
        # ...but a wider window catches it
        self.assertEqual(len(detect_brute_force(evs, threshold=5, window=10 * MIN)), 1)

    def test_long_attack_is_merged_into_one_incident(self):
        incidents = detect_brute_force(events(burst(BASE, "1.1.1.1", 200, 3 * SEC)), threshold=5)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].attempts, 200)

    def test_separate_bursts_are_separate_incidents(self):
        lines = burst(BASE, "1.1.1.1", 6, SEC) + burst(BASE + 60 * MIN, "1.1.1.1", 7, SEC)
        incidents = detect_brute_force(events(lines), threshold=5)
        self.assertEqual([i.attempts for i in incidents], [6, 7])

    def test_ips_are_tracked_independently(self):
        # Interleave two IPs: 4 failures each -> neither reaches 5 on its own
        lines = []
        for i in range(4):
            lines += [failed(BASE + i * SEC, "1.1.1.1"), failed(BASE + i * SEC, "2.2.2.2")]
        self.assertEqual(detect_brute_force(events(lines), threshold=5), [])

    def test_usernames_counted(self):
        lines = [failed(BASE + i * SEC, "1.1.1.1", u) for i, u in enumerate(["root", "root", "admin", "pi", "root"])]
        [inc] = detect_brute_force(events(lines), threshold=5)
        self.assertEqual(inc.usernames["root"], 3)
        self.assertEqual(set(inc.usernames), {"root", "admin", "pi"})

    def test_input_order_does_not_matter(self):
        lines = burst(BASE, "1.1.1.1", 6, SEC)
        self.assertEqual(len(detect_brute_force(events(reversed(lines)), threshold=5)), 1)


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_login_after_many_failures_flagged_high(self):
        lines = burst(BASE, "6.6.6.6", 8, SEC, user="deploy") + [accepted(BASE + MIN, "6.6.6.6", "deploy")]
        [s] = detect_success_after_failures(events(lines), threshold=5)
        self.assertEqual((s.login.user, s.prior_failures, s.severity), ("deploy", 8, "HIGH"))

    def test_different_user_is_medium(self):
        lines = burst(BASE, "6.6.6.6", 8, SEC, user="root") + [accepted(BASE + MIN, "6.6.6.6", "bob")]
        [s] = detect_success_after_failures(events(lines), threshold=5)
        self.assertEqual(s.severity, "MEDIUM")

    def test_typo_then_success_not_flagged(self):
        lines = burst(BASE, "10.0.0.1", 2, SEC, user="bob") + [accepted(BASE + 10 * SEC, "10.0.0.1", "bob")]
        self.assertEqual(detect_success_after_failures(events(lines), threshold=5), [])

    def test_failures_from_other_ip_dont_count(self):
        lines = burst(BASE, "6.6.6.6", 10, SEC) + [accepted(BASE + MIN, "10.0.0.1", "root")]
        self.assertEqual(detect_success_after_failures(events(lines), threshold=5), [])

    def test_failures_outside_lookback_dont_count(self):
        lines = burst(BASE, "6.6.6.6", 10, SEC) + [accepted(BASE + 2 * 60 * MIN, "6.6.6.6", "root")]
        self.assertEqual(detect_success_after_failures(events(lines), threshold=5, lookback=60 * MIN), [])

    def test_count_resets_after_success(self):
        lines = (
            burst(BASE, "6.6.6.6", 6, SEC)
            + [accepted(BASE + MIN, "6.6.6.6"), accepted(BASE + 2 * MIN, "6.6.6.6")]
        )
        flagged = detect_success_after_failures(events(lines), threshold=5)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].login.timestamp, BASE + MIN)


class MiscTests(unittest.TestCase):
    def test_successful_logins_sorted(self):
        lines = [accepted(BASE + MIN, "1.1.1.1", "b"), accepted(BASE, "1.1.1.1", "a")]
        self.assertEqual([e.user for e in successful_logins(events(lines))], ["a", "b"])

    def test_summary(self):
        lines = burst(BASE, "1.1.1.1", 3, SEC) + [failed(BASE, "2.2.2.2"), accepted(BASE + MIN, "3.3.3.3")]
        s = summarise(events(lines))
        self.assertEqual((s.total_events, s.failed_attempts, s.successful_logins, s.unique_ips), (5, 4, 1, 3))
        self.assertEqual(s.top_failed_ips[0], ("1.1.1.1", 3))

    def test_empty_input(self):
        self.assertEqual(detect_brute_force([]), [])
        self.assertEqual(detect_success_after_failures([]), [])
        self.assertIsNone(summarise([]).first_event)


if __name__ == "__main__":
    unittest.main()
