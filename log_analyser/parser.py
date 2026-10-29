"""Parse Linux auth.log lines into structured SSH events.

Supports both timestamp styles seen in the wild:

* Traditional syslog:  ``Oct 29 10:15:32 host sshd[123]: ...``  (no year!)
* RFC 3339 / ISO 8601: ``2026-10-29T10:15:32.123456+00:00 host sshd[123]: ...``

Only sshd lines describing a login attempt are turned into events; anything
else is ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

# Event kinds
FAILED = "failed"            # wrong password / key for a user
INVALID_USER = "invalid_user"  # username that doesn't exist on the box
ACCEPTED = "accepted"        # successful login


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    kind: str
    user: str
    ip: str
    method: str | None = None  # e.g. "password", "publickey" (accepted/failed only)
    raw: str = ""


# --- Line prefix (timestamp + host + process) -------------------------------

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# --- Message bodies ---------------------------------------------------------

# "Failed password for root from 1.2.3.4 port 22 ssh2"
# "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
# "Failed publickey for bob from 1.2.3.4 port 22 ssh2: RSA SHA256:..."
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:(?P<invalid>invalid user) )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port \d+"
)
# "Accepted publickey for alice from 1.2.3.4 port 22 ssh2: ED25519 SHA256:..."
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)
# "Invalid user test from 1.2.3.4 port 5555"  (logged before the password try)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")


def _parse_syslog_time(month: str, day: str, time: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {month} {day} {time}", "%Y %b %d %H:%M:%S")


def _parse_iso_time(ts: str) -> datetime:
    # Normalise to naive local-looking time so it compares with syslog stamps.
    # fromisoformat handles "Z", offsets and fractional seconds on 3.11+.
    return datetime.fromisoformat(ts).replace(tzinfo=None)


def parse_message(msg: str) -> tuple[str, str, str, str | None] | None:
    """Classify an sshd message body. Returns (kind, user, ip, method) or None."""
    if m := _FAILED.match(msg):
        # "Failed password for invalid user X" is still a failed attempt;
        # we record it as FAILED so every password guess counts once.
        return FAILED, m["user"], m["ip"], m["method"]
    if m := _ACCEPTED.match(msg):
        return ACCEPTED, m["user"], m["ip"], m["method"]
    if m := _INVALID.match(msg):
        return INVALID_USER, m["user"], m["ip"], None
    return None


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    """Yield an AuthEvent for every relevant sshd line.

    ``year`` is used for syslog timestamps (which omit it). Defaults to the
    current year. If the month goes backwards (Dec -> Jan) we assume the log
    crossed a new year and bump it.
    """
    year = year if year is not None else datetime.now().year
    last_month: int | None = None

    for line in lines:
        line = line.rstrip("\n")
        if m := _SYSLOG_PREFIX.match(line):
            try:
                ts = _parse_syslog_time(m["month"], m["day"], m["time"], year)
            except ValueError:
                continue
            if last_month is not None and ts.month < last_month:
                year += 1
                ts = ts.replace(year=year)
            last_month = ts.month
        elif m := _ISO_PREFIX.match(line):
            try:
                ts = _parse_iso_time(m["ts"])
            except ValueError:
                continue
        else:
            continue

        parsed = parse_message(m["msg"])
        if parsed is None:
            continue
        kind, user, ip, method = parsed
        yield AuthEvent(timestamp=ts, kind=kind, user=user, ip=ip, method=method, raw=line)
