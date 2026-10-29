"""Small builders for synthetic log lines used across tests."""

from datetime import datetime, timedelta

BASE = datetime(2026, 10, 28, 12, 0, 0)


def stamp(ts: datetime) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"


def failed(ts: datetime, ip: str, user: str = "root", invalid: bool = False) -> str:
    who = f"invalid user {user}" if invalid else user
    return f"{stamp(ts)} host sshd[100]: Failed password for {who} from {ip} port 4000 ssh2"


def accepted(ts: datetime, ip: str, user: str = "root", method: str = "password") -> str:
    return f"{stamp(ts)} host sshd[101]: Accepted {method} for {user} from {ip} port 4001 ssh2"


def burst(start: datetime, ip: str, n: int, every: timedelta, user: str = "root") -> list[str]:
    return [failed(start + every * i, ip, user) for i in range(n)]
