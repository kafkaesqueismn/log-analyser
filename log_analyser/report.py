"""Render analysis results as a readable text report or as JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta

from .detector import BruteForceIncident, Summary, SuspiciousLogin
from .parser import AuthEvent

TS = "%Y-%m-%d %H:%M:%S"


@dataclass
class AnalysisResult:
    summary: Summary
    brute_force: list[BruteForceIncident]
    logins: list[AuthEvent]
    suspicious: list[SuspiciousLogin]
    threshold: int
    window: timedelta
    lookback: timedelta


def _fmt_ts(ts: datetime | None) -> str:
    return ts.strftime(TS) if ts else "-"


def _fmt_duration(d: timedelta) -> str:
    secs = int(d.total_seconds())
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _fmt_users(counter, limit: int = 4) -> str:
    items = [u or "<empty>" for u, _ in counter.most_common(limit)]
    extra = len(counter) - limit
    return ", ".join(items) + (f" (+{extra} more)" if extra > 0 else "")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows)]
    line = lambda cells: "  ".join(str(c).ljust(w) for c, w in zip(cells, widths)).rstrip()
    out = [line(headers), line(["-" * w for w in widths])]
    out.extend(line(r) for r in rows)
    return "\n".join("  " + l for l in out)


def _section(title: str) -> str:
    return f"\n{title}\n{'=' * len(title)}"


def render_text(r: AnalysisResult) -> str:
    s = r.summary
    out = ["SSH AUTH LOG ANALYSIS REPORT"]

    out.append(_section("Overview"))
    out.append(f"  Time range:         {_fmt_ts(s.first_event)}  ->  {_fmt_ts(s.last_event)}")
    out.append(f"  SSH events parsed:  {s.total_events}")
    out.append(f"  Failed attempts:    {s.failed_attempts}")
    out.append(f"  Successful logins:  {s.successful_logins}")
    out.append(f"  Unique source IPs:  {s.unique_ips}")
    out.append(f"  Invalid usernames:  {s.invalid_usernames}")

    if s.top_failed_ips:
        out.append("\n  Top failing IPs:    " + ", ".join(f"{ip} ({n})" for ip, n in s.top_failed_ips))
        out.append("  Top targeted users: " + ", ".join(f"{u or '<empty>'} ({n})" for u, n in s.top_failed_users))

    out.append(_section("[!] Logins after repeated failures"))
    out.append(
        f"  (>= {r.threshold} failures from the same IP within "
        f"{_fmt_duration(r.lookback)} before a successful login)"
    )
    if r.suspicious:
        rows = [
            [
                x.severity,
                _fmt_ts(x.login.timestamp),
                x.login.ip,
                x.login.user,
                x.login.method or "-",
                str(x.prior_failures),
                _fmt_users(x.targeted_usernames, 3),
            ]
            for x in r.suspicious
        ]
        out.append(_table(["SEV", "TIME", "IP", "USER", "METHOD", "FAILS", "USERS TRIED"], rows))
        out.append("\n  HIGH = the account that logged in was among those being guessed.")
    else:
        out.append("  None found.")

    out.append(_section("Brute-force attempts"))
    out.append(f"  (>= {r.threshold} failures from one IP within {_fmt_duration(r.window)})")
    if r.brute_force:
        rows = [
            [
                inc.ip,
                _fmt_ts(inc.first_seen),
                _fmt_ts(inc.last_seen),
                _fmt_duration(inc.duration),
                str(inc.attempts),
                _fmt_users(inc.usernames),
            ]
            for inc in r.brute_force
        ]
        out.append(_table(["IP", "FIRST SEEN", "LAST SEEN", "DURATION", "ATTEMPTS", "USERNAMES"], rows))
    else:
        out.append("  None found.")

    out.append(_section("Successful logins"))
    if r.logins:
        flagged = {id(x.login) for x in r.suspicious}
        rows = [
            [_fmt_ts(e.timestamp), e.user, e.ip, e.method or "-", "<-- suspicious" if id(e) in flagged else ""]
            for e in r.logins
        ]
        out.append(_table(["TIME", "USER", "IP", "METHOD", "NOTE"], rows))
    else:
        out.append("  None found.")

    return "\n".join(out) + "\n"


def render_json(r: AnalysisResult) -> str:
    s = r.summary
    data = {
        "settings": {
            "threshold": r.threshold,
            "window_seconds": int(r.window.total_seconds()),
            "lookback_seconds": int(r.lookback.total_seconds()),
        },
        "summary": {
            "first_event": _fmt_ts(s.first_event) if s.first_event else None,
            "last_event": _fmt_ts(s.last_event) if s.last_event else None,
            "total_events": s.total_events,
            "failed_attempts": s.failed_attempts,
            "successful_logins": s.successful_logins,
            "unique_ips": s.unique_ips,
            "invalid_usernames": s.invalid_usernames,
            "top_failed_ips": [{"ip": ip, "count": n} for ip, n in s.top_failed_ips],
            "top_failed_users": [{"user": u, "count": n} for u, n in s.top_failed_users],
        },
        "suspicious_logins": [
            {
                "severity": x.severity,
                "time": _fmt_ts(x.login.timestamp),
                "ip": x.login.ip,
                "user": x.login.user,
                "method": x.login.method,
                "prior_failures": x.prior_failures,
                "first_failure": _fmt_ts(x.first_failure),
                "targeted_usernames": dict(x.targeted_usernames),
            }
            for x in r.suspicious
        ],
        "brute_force": [
            {
                "ip": inc.ip,
                "first_seen": _fmt_ts(inc.first_seen),
                "last_seen": _fmt_ts(inc.last_seen),
                "duration_seconds": int(inc.duration.total_seconds()),
                "attempts": inc.attempts,
                "usernames": dict(inc.usernames),
            }
            for inc in r.brute_force
        ],
        "successful_logins": [
            {"time": _fmt_ts(e.timestamp), "user": e.user, "ip": e.ip, "method": e.method}
            for e in r.logins
        ],
    }
    return json.dumps(data, indent=2)
