"""Detection logic over parsed AuthEvents.

Three analyses:

* ``detect_brute_force``      – many failures from one IP inside a time window
* ``successful_logins``       – every accepted login
* ``detect_success_after_failures`` – an accepted login preceded by many
  failures from the same IP (a likely successful brute force)
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from .parser import ACCEPTED, FAILED, INVALID_USER, AuthEvent


@dataclass
class BruteForceIncident:
    ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int
    usernames: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> timedelta:
        return self.last_seen - self.first_seen


@dataclass
class SuspiciousLogin:
    login: AuthEvent
    prior_failures: int
    first_failure: datetime
    targeted_usernames: Counter
    # True if the account that got in was itself one of the ones being guessed.
    same_user_targeted: bool

    @property
    def severity(self) -> str:
        return "HIGH" if self.same_user_targeted else "MEDIUM"


@dataclass
class Summary:
    total_events: int
    failed_attempts: int
    successful_logins: int
    unique_ips: int
    first_event: datetime | None
    last_event: datetime | None
    top_failed_ips: list[tuple[str, int]]
    top_failed_users: list[tuple[str, int]]
    invalid_usernames: int


def _failures_by_ip(events: Iterable[AuthEvent]) -> dict[str, list[AuthEvent]]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        if ev.kind == FAILED:
            by_ip[ev.ip].append(ev)
    return by_ip


def detect_brute_force(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[BruteForceIncident]:
    """Find bursts of >= ``threshold`` failures from one IP within ``window``.

    A sliding window walks each IP's failures in time order. Whenever the
    window holds ``threshold`` or more failures the IP is "under attack";
    consecutive qualifying windows that overlap are merged into one incident,
    so a long attack is reported once rather than once per failure.
    """
    events = sorted(events, key=lambda e: e.timestamp)
    incidents: list[BruteForceIncident] = []

    for ip, fails in _failures_by_ip(events).items():
        win: deque[int] = deque()  # indices into `fails`
        current: BruteForceIncident | None = None
        last_idx = -1  # last index already counted into `current`

        for i, ev in enumerate(fails):
            win.append(i)
            while ev.timestamp - fails[win[0]].timestamp > window:
                win.popleft()
            if len(win) < threshold:
                continue

            if current is not None and win[0] <= last_idx:
                # Window overlaps the ongoing incident: extend it.
                new = fails[last_idx + 1 : i + 1]
            else:
                # Fresh incident starting at the oldest failure in the window.
                new = [fails[j] for j in win]
                current = BruteForceIncident(ip, new[0].timestamp, ev.timestamp, 0)
                incidents.append(current)

            current.last_seen = ev.timestamp
            current.attempts += len(new)
            current.usernames.update(e.user for e in new)
            last_idx = i

    incidents.sort(key=lambda inc: inc.first_seen)
    return incidents


def successful_logins(events: Iterable[AuthEvent]) -> list[AuthEvent]:
    return sorted((e for e in events if e.kind == ACCEPTED), key=lambda e: e.timestamp)


def detect_success_after_failures(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    lookback: timedelta = timedelta(hours=1),
) -> list[SuspiciousLogin]:
    """Flag accepted logins preceded by >= ``threshold`` failures from that IP.

    Failures are counted within ``lookback`` before the login, and the count
    resets at the IP's previous successful login, so a legitimate user who
    fat-fingers their password and later logs in again isn't re-flagged.
    """
    events = sorted(events, key=lambda e: e.timestamp)
    recent_failures: dict[str, deque[AuthEvent]] = defaultdict(deque)
    flagged: list[SuspiciousLogin] = []

    for ev in events:
        if ev.kind == FAILED:
            recent_failures[ev.ip].append(ev)
        elif ev.kind == ACCEPTED:
            fails = recent_failures[ev.ip]
            while fails and ev.timestamp - fails[0].timestamp > lookback:
                fails.popleft()
            if len(fails) >= threshold:
                users = Counter(f.user for f in fails)
                flagged.append(
                    SuspiciousLogin(
                        login=ev,
                        prior_failures=len(fails),
                        first_failure=fails[0].timestamp,
                        targeted_usernames=users,
                        same_user_targeted=ev.user in users,
                    )
                )
            fails.clear()

    return flagged


def summarise(events: Iterable[AuthEvent], top: int = 5) -> Summary:
    events = list(events)
    failed = [e for e in events if e.kind == FAILED]
    times = [e.timestamp for e in events]
    return Summary(
        total_events=len(events),
        failed_attempts=len(failed),
        successful_logins=sum(e.kind == ACCEPTED for e in events),
        unique_ips=len({e.ip for e in events}),
        first_event=min(times, default=None),
        last_event=max(times, default=None),
        top_failed_ips=Counter(e.ip for e in failed).most_common(top),
        top_failed_users=Counter(e.user for e in failed).most_common(top),
        invalid_usernames=len({e.user for e in events if e.kind == INVALID_USER}),
    )
