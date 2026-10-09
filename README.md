#  failed_login_monitor

**Real-time brute-force detection for Windows, straight from the Security event log.**
It watches failed logons (Event ID 4625), counts them per username and per source IP in sliding time windows, and fires an alert the moment a threshold is crossed.

---

## Why this exists

Every exposed RDP port, every domain account, every file share gets hammered with guessed passwords. A single failed login is noise. Five in five minutes against one account, or ten from one address, is an attack. `failed_login_monitor` turns the raw firehose of 4625 events into clear, thresholded alerts you can act on.

## Features

- **Reads Windows Security log failed logons** (Event ID 4625), only new events each poll
- **Two detection modes** running together:
  - **Per username**: many failures against one account (targeted guessing)
  - **Per source IP**: many failures from one address (spraying across accounts)
- **Sliding time windows** with configurable count and duration for each mode
- **Logon-type filtering**: focus on RDP only, network logons only, and so on
- **Built-in lookup tables** for logon types and failure status codes (wrong password, unknown user, account locked out, and more)
- **Whitelists** for usernames (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`) and IPs (`127.0.0.1`, `::1`)
- **Multiple alert outputs**: CSV reports, Windows Event Log, Microsoft Teams webhook
- **Dry-run mode**: see what would fire without sending anything
- **Single-shot mode** (`--once`) for testing and scheduled runs
- **Live window stats** logged every poll, so you can watch counts build toward a threshold
- **Graceful shutdown** on `Ctrl+C`, and a clear error if you forgot to run as Administrator

## How it works

```
 ┌───────────────────────┐   every poll_interval_seconds
 │ Windows Security log  │──────────────┐
 │ (Event ID 4625)       │              ▼
 └───────────────────────┘     read_failed_logins()
                               · whitelist users / IPs dropped
                               · capped at max_events_per_poll
                                        ▼
                               filter: --logon-type (optional)
                               filter: only events newer than last poll
                                        ▼
                              ┌──────────────────────┐
                              │ BruteForceDetector   │
                              │ · per-username window│
                              │ · per-source-IP window
                              └──────────┬───────────┘
                                         ▼  threshold crossed?
                         Alert → CSV · Event Log · Teams
```

Each poll:

1. **Read** failed-logon events from the Security log, minus whitelisted users and IPs.
2. **Filter** to the chosen logon type (if set) and to events newer than the last one seen, so nothing is counted twice.
3. **Feed** each new event to the detector, which updates the username and IP windows.
4. **Alert** for every threshold crossed, with the alert type, the offending key (username or IP), the count, and a severity.
5. **Log** current window counts so you can see activity building.

## Project structure

```
failed_login_monitor/
├── main.py               # CLI entry point and polling loop
├── config.json           # Thresholds, whitelists, lookups, destinations
├── modules/
│   ├── logger.py         # Logging setup
│   ├── event_reader.py   # Reads and parses failed-logon events (4625)
│   ├── threshold.py      # BruteForceDetector: sliding-window counting
│   └── alerter.py        # Dispatches alerts to CSV / Event Log / Teams
├── data/reports/         # CSV alert reports
└── logs/                 # Runtime logs (monitor.log)
```

## Requirements

- **Windows**
- **Python 3.7+**
- **Administrator privileges**. Reading the Security log requires them, and the monitor exits with a clear error without them.
- **Failed-logon auditing enabled** (Audit Logon → Failure), so the events exist to be read
- Windows Python bindings used to read the event log. Check the imports in `modules/event_reader.py` and install what they need.

## Getting started

```bash
git clone https://github.com/kevn-xo/failed_login_monitor.git
cd failed_login_monitor
```

Do a safe test run from an Administrator terminal. It reads the log once, prints what would alert, and sends nothing:

```bash
python main.py --dry-run --once
```

Then start monitoring:

```bash
python main.py
```

Stop anytime with `Ctrl+C`.

## Usage

```bash
python main.py                                    # Monitor with defaults
python main.py --threshold 3 --window 120         # 3 failures in 120s
python main.py --output csv                       # CSV alerts only
python main.py --output teams --webhook-url URL   # Teams alerts
python main.py --output all                       # CSV + Event Log + Teams
python main.py --logon-type 10                    # Watch RDP only
python main.py --dry-run                          # Detect, no alerts fired
python main.py --interval 60                      # Poll every 60 seconds
python main.py --once                             # One poll, then exit
python main.py --config custom.json               # Use a different config file
```

### CLI options

| Flag | Description |
|---|---|
| `--threshold N` | Failure count that triggers an alert. Applies to **both** username and IP detection |
| `--window N` | Time window in seconds. Applies to **both** username and IP detection |
| `--interval N` | Poll interval in seconds |
| `--output {csv,teams,eventlog,all}` | Override alert destinations. `all` = CSV + Event Log + Teams |
| `--webhook-url URL` | Teams incoming-webhook URL |
| `--logon-type TYPE` | Only watch one logon type (e.g. `10` for RDP) |
| `--dry-run` | Detect and log only. No alerts dispatched |
| `--once` | Run a single poll, then exit |
| `--config PATH` | Path to an alternate config file (default: `config.json`) |

## Configuration

### `config.json`

| Key | Default | Description |
|---|---|---|
| `log_file` | `logs/monitor.log` | Log file path |
| `report_dir` | `data/reports` | Where CSV alert reports are written |
| `poll_interval_seconds` | `30` | Seconds between polls |
| `max_events_per_poll` | `500` | Cap on events read per poll |
| `thresholds.per_username` | `5` in `300`s | Failures against one username before alerting |
| `thresholds.per_source_ip` | `10` in `300`s | Failures from one IP before alerting |
| `alert_destinations` | `csv`, `eventlog` | Default outputs |
| `teams_webhook_url` | `""` | Microsoft Teams incoming-webhook URL |
| `whitelist_usernames` | `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE` | Usernames to ignore |
| `whitelist_ips` | `127.0.0.1`, `::1` | Source IPs to ignore |
| `logon_types` | see below | Logon type code → description |
| `failure_reasons` | see below | Failure status code → description |

### Logon types

| Code | Meaning |
|---|---|
| `2` | Interactive (local keyboard) |
| `3` | Network (SMB / file share) |
| `4` | Batch (scheduled task) |
| `5` | Service |
| `7` | Unlock (screensaver) |
| `8` | NetworkCleartext |
| `9` | NewCredentials (RunAs) |
| `10` | RemoteInteractive (RDP) |
| `11` | CachedInteractive |

### Failure reasons

| Status code | Meaning |
|---|---|
| `0xC000006A` | Wrong password |
| `0xC0000064` | Username does not exist |
| `0xC000006D` | Generic logon failure |
| `0xC000006E` | Account restriction |
| `0xC000006F` | Outside logon hours |
| `0xC0000070` | Workstation restriction |
| `0xC0000071` | Password expired |
| `0xC0000072` | Account disabled |
| `0xC0000193` | Account expired |
| `0xC0000234` | Account locked out |

## Tuning

- **Internet-facing RDP host?** Watch RDP only with a tight window: `python main.py --logon-type 10 --threshold 3 --window 120`
- **Noisy environment?** Raise the thresholds, and add known scanners, jump hosts, or service accounts to the whitelists.
- **Busy domain controller?** Raise `max_events_per_poll` and lower `poll_interval_seconds` so bursts aren't missed between polls.
- **Per-IP vs per-username:** the IP threshold defaults higher, since one address legitimately fails a few times across users (shared NAT, for example).

## What it catches

Failed-logon bursts map to **MITRE ATT&CK [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)**: password guessing against one account (per-username window) and password spraying across many accounts (per-source-IP window).

## Sample dry-run output

```json
[DRY-RUN] Would alert:
{
  "alert_type": "...",
  "key": "<username or IP>",
  "count": 5,
  "severity": "..."
}
```

## Known limitations

- Alerts arrive at poll speed, so latency is up to `poll_interval_seconds`.
- Detection windows live in the running process, so restarting the monitor resets them.
- A single poll reads at most `max_events_per_poll` events.
- Windows only, and Administrator required.
