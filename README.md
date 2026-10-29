# log-analyser

A small, dependency-free Python CLI that analyses Linux SSH authentication logs
(`/var/log/auth.log`, `/var/log/secure`) and reports:

- **Brute-force attempts**: many failed logins from one IP within a short time window
- **Successful logins**: every accepted SSH login
- **Logins after repeated failures**: an IP that failed many times and then got in,
  which is the strongest sign of a successful brute force

It also includes a generator that produces a realistic **synthetic** `auth.log` with
simulated attacks, so you can try everything without touching real logs.

Requires Python 3.11+. No third-party packages.

## Quick start

```bash
# 1. Generate a sample log (ground truth of injected attacks is printed to stderr)
python3 scripts/generate_sample_log.py -o sample_auth.log

# 2. Analyse it
python3 -m log_analyser sample_auth.log

# Optional: install as a command
pip install -e .
log-analyser sample_auth.log
```

Example output (abridged):

```
[!] Logins after repeated failures
==================================
  (>= 5 failures from the same IP within 1h00m before a successful login)
  SEV   TIME                 IP            USER    METHOD    FAILS  USERS TRIED
  ----  -------------------  ------------  ------  --------  -----  -----------
  HIGH  2026-10-28 18:04:12  203.0.113.99  deploy  password  40     deploy

Brute-force attempts
====================
  (>= 5 failures from one IP within 5m00s)
  IP            FIRST SEEN           LAST SEEN            DURATION  ATTEMPTS  USERNAMES
  ------------  -------------------  -------------------  --------  --------  -----------------------------
  203.0.113.45  2026-10-28 02:52:50  2026-10-28 03:06:02  13m12s    150       jenkins, steam, ... (+19 more)
  203.0.113.99  2026-10-28 18:00:02  2026-10-28 18:04:09  4m07s     40        deploy
```

## Usage

```
log-analyser [options] LOGFILE [LOGFILE ...]

  -t, --threshold N     failures from one IP that count as brute force (default: 5)
  -w, --window SECONDS  time window for brute-force detection (default: 300)
  -l, --lookback SECONDS
                        how far before a login to count failures (default: 3600)
  -y, --year YEAR       year for syslog timestamps, which omit it (default: current year)
  --top N               entries in "top" lists (default: 5)
  --json                machine-readable JSON output
```

- Several files can be given at once, e.g. `log-analyser /var/log/auth.log*`.
  Rotated `.gz` files are read transparently.
- `-` reads from stdin: `journalctl -u ssh --no-pager | log-analyser -`
- Real logs are usually only readable by root: `sudo log-analyser /var/log/auth.log`
- `--json` output works well with `jq`, e.g.
  `log-analyser auth.log --json | jq '.suspicious_logins'`

### Sample generator

```
python3 scripts/generate_sample_log.py [-o FILE] [--start "2026-10-28 00:00"]
                                       [--hours 24] [--seed 42] [--iso] [-q]
```

The same `--seed` always produces the same log. `--iso` switches to ISO-8601
timestamps (the format newer rsyslog/journald setups use).

## How detection works

### Parsing (`log_analyser/parser.py`)

Each line is matched against two prefix patterns: classic syslog
(`Oct 28 12:00:01 host sshd[123]: …`) and ISO-8601
(`2026-10-28T12:00:01.123+00:00 host sshd[123]: …`). The message is then
classified:

| Message                                         | Event          |
|-------------------------------------------------|----------------|
| `Failed <method> for [invalid user] X from IP`  | `failed`       |
| `Accepted <method> for X from IP`               | `accepted`     |
| `Invalid user X from IP`                        | `invalid_user` |

All other lines (CRON, sudo, PAM session lines, disconnects) are ignored. One
guess at a non-existent account writes *both* an `Invalid user` and a
`Failed password for invalid user` line. Only the latter counts as a failure,
so every guess is counted exactly once.

Syslog timestamps have no year. The `--year` option supplies it (default: the
current year), and a December → January transition inside a file moves to the
next year.

### Brute force (`detect_brute_force`)

For each IP, a **sliding window** moves over its failures in time order. When
the window (default 5 minutes) holds at least `threshold` (default 5)
failures, an incident starts. Later qualifying windows that overlap it extend
the same incident, so a 2-hour attack is reported once, with its full duration
and attempt count. A pause longer than the window starts a new incident.

### Logins after failures (`detect_success_after_failures`)

For each accepted login, count failures from the **same IP** in the preceding
`lookback` (default 1 hour). The count resets at that IP's previous successful
login. If it reaches `threshold`, the login is flagged:

- **HIGH**: the account that logged in was one of the accounts being guessed
  (classic successful password brute force)
- **MEDIUM**: the IP failed on other accounts, then got in as a different one

A real user who mistypes their password once or twice falls well below the
threshold and isn't flagged.

## Tuning and known limitations

Detection is a trade-off between catching attacks and raising false alarms.
The sample log includes two attacks that **evade the default rules on
purpose**, to show this:

| Attack in sample log | Defaults | How to catch it |
|---|---|---|
| Slow attack, 1 guess every ~3–4 min (`198.51.100.200`) | missed | `-t 10 -w 3600` (10 failures/hour) |
| Distributed spray, 25 IPs × 2 guesses (`192.0.2.10–34`) | missed | Not possible per-IP. Needs aggregation by username or subnet |

Other limitations:

- Only `sshd` lines are analysed (not FTP, su, web logins, etc.).
- Timezones in ISO timestamps are dropped. Times are compared as written,
  so don't mix logs from servers in different timezones.
- IPs behind shared NAT (offices, mobile carriers) can merge several users
  into one "attacker". Allow-list known ranges when you review findings.
- This tool *reports*. It doesn't block anything. For active defence look at
  `fail2ban`, `sshguard`, key-only auth (`PasswordAuthentication no`), and
  `PermitRootLogin no`.

## Project layout

```
log_analyser/
  parser.py      raw lines -> AuthEvent objects
  detector.py    brute force / suspicious login / summary logic
  report.py      text and JSON rendering
  cli.py         argument parsing, file reading (plain, .gz, stdin)
scripts/
  generate_sample_log.py   synthetic auth.log with simulated attacks
tests/
  test_parser.py           line formats, noise filtering, year rollover
  test_detector.py         thresholds, windows, merging, false-positive cases
  test_end_to_end.py       generate -> analyse -> compare with ground truth
```

## Running the tests

```bash
python3 -m unittest discover -v
# or, if you have pytest installed:
pytest
```

## Safety note on the sample data

The generated logs are entirely fictional. Attacker addresses come from the
RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), which are reserved and never routed on the public internet.
