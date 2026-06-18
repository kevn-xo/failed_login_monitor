# -*- coding: utf-8 -*-
"""
alerter.py - Alert output module.
Supports three destinations: CSV file, Teams webhook, Windows Event Log.
Each destination is independently callable.
"""

import csv, json, os, logging
from datetime import datetime

log = logging.getLogger("monitor.alerter")

# CSV column headers - one row per alert
CSV_HEADERS = [
    "detected_at", "alert_type", "severity",
    "key_type",    "key",        "count",
    "threshold",   "window_secs",
    "username",    "ip_address", "logon_type",
    "workstation", "computer",   "timestamp",
]


def alert_csv(alert: dict, report_dir: str) -> str:
    """
    Append one alert row to a daily CSV file.
    File named: alerts_YYYYMMDD.csv
    Creates file + header row if it does not exist yet.
    Returns the filepath written to.
    """
    os.makedirs(report_dir, exist_ok=True)
    today  = datetime.now().strftime("%Y%m%d")
    fpath  = os.path.join(report_dir, f"alerts_{today}.csv")
    exists = os.path.exists(fpath)

    ev = alert.get("trigger_event", {})

    row = {
        "detected_at":  alert.get("detected_at", ""),
        "alert_type":   alert.get("alert_type", ""),
        "severity":     alert.get("severity", ""),
        "key_type":     alert.get("key_type", ""),
        "key":          alert.get("key", ""),
        "count":        alert.get("count", ""),
        "threshold":    alert.get("threshold", ""),
        "window_secs":  alert.get("window_secs", ""),
        "username":     ev.get("username", ""),
        "ip_address":   ev.get("ip_address", ""),
        "logon_type":   ev.get("logon_type", ""),
        "workstation":  ev.get("workstation", ""),
        "computer":     ev.get("computer", ""),
        "timestamp":    ev.get("timestamp_str", ""),
    }

    with open(fpath, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)

    log.debug(f"CSV alert written: {fpath}")
    return fpath


def alert_teams(alert: dict, webhook_url: str) -> bool:
    """
    Send an Adaptive Card to a Microsoft Teams channel via webhook.
    Requires: pip install requests
    Returns True on success, False on failure.
    """
    try:
        import requests
    except ImportError:
        log.error("requests not installed - pip install requests")
        return False

    if not webhook_url:
        log.warning("Teams webhook URL not configured.")
        return False

    ev       = alert.get("trigger_event", {})
    severity = alert.get("severity", "HIGH")
    color    = "FF0000" if severity == "CRITICAL" else "FF8C00"

    # Teams Adaptive Card payload
    payload = {
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "themeColor": color,
        "summary":    f"Brute Force Alert - {alert.get('key','')}",
        "sections": [{
            "activityTitle":    f"[{severity}] {alert.get('alert_type','')}",
            "activitySubtitle": f"Detected at {alert.get('detected_at','')}",
            "facts": [
                {"name": "Target",       "value": alert.get("key", "")},
                {"name": "Type",         "value": alert.get("key_type", "")},
                {"name": "Count",        "value": str(alert.get("count", ""))},
                {"name": "Threshold",    "value": str(alert.get("threshold", ""))},
                {"name": "Window",       "value": f"{alert.get('window_secs','')}s"},
                {"name": "Username",     "value": ev.get("username", "")},
                {"name": "Source IP",    "value": ev.get("ip_address", "")},
                {"name": "Logon Type",   "value": ev.get("logon_type", "")},
                {"name": "Workstation",  "value": ev.get("workstation", "")},
                {"name": "Computer",     "value": ev.get("computer", "")},
            ],
            "markdown": True
        }]
    }

    try:
        resp = requests.post(
            webhook_url,
            data    = json.dumps(payload),
            headers = {"Content-Type": "application/json"},
            timeout = 10,
        )
        if resp.status_code == 200:
            log.info(f"Teams alert sent for {alert.get('key','')}")
            return True
        else:
            log.error(f"Teams webhook returned {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        log.error(f"Teams webhook failed: {e}")
        return False


def alert_eventlog(alert: dict) -> bool:
    """
    Write alert to Windows Application event log via ReportEvent.
    This makes the detection itself auditable in Event Viewer.
    EventID 1000 = brute force detection from this tool.
    """
    try:
        import win32evtlogutil
        import win32evtlog

        ev  = alert.get("trigger_event", {})
        msg = (
            f"BRUTE FORCE ALERT\n"
            f"Type     : {alert.get('alert_type','')}\n"
            f"Target   : {alert.get('key','')}\n"
            f"Count    : {alert.get('count','')} in {alert.get('window_secs','')}s\n"
            f"Username : {ev.get('username','')}\n"
            f"Source IP: {ev.get('ip_address','')}\n"
            f"Logon Type: {ev.get('logon_type','')}\n"
            f"Detected : {alert.get('detected_at','')}"
        )

        severity = alert.get("severity", "HIGH")
        event_type = (win32evtlog.EVENTLOG_ERROR_TYPE   if severity == "CRITICAL"
                      else win32evtlog.EVENTLOG_WARNING_TYPE)

        win32evtlogutil.ReportEvent(
            "FailedLoginMonitor",
            eventID    = 1000,
            eventType  = event_type,
            strings    = [msg],
            data       = b"brute_force_detection",
        )
        log.info("Event log entry written.")
        return True

    except Exception as e:
        log.error(f"Event log write failed: {e}")
        return False


def dispatch_alert(alert: dict, destinations: list,
                   report_dir: str = "data/reports",
                   webhook_url: str = "") -> dict:
    """
    Route one alert to all configured destinations.
    destinations: list of strings - ["csv", "eventlog", "teams"]
    Returns dict of {destination: success_bool}
    """
    results = {}

    if "csv" in destinations:
        path = alert_csv(alert, report_dir)
        results["csv"] = path
        log.info(f"[CSV] Alert written to {path}")

    if "teams" in destinations and webhook_url:
        results["teams"] = alert_teams(alert, webhook_url)

    if "eventlog" in destinations:
        results["eventlog"] = alert_eventlog(alert)

    return results
