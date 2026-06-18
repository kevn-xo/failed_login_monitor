# -*- coding: utf-8 -*-
"""
event_reader.py - Reads and parses EventID 4625 from the Security log.
Returns clean dicts ready for threshold analysis.
"""

import win32evtlog
from datetime import datetime


# StringInserts field indices for EventID 4625
FIELD = {
    "username":     5,
    "domain":       6,
    "status":       7,
    "substatus":    9,
    "logon_type":   10,
    "workstation":  13,
    "ip_address":   19,
    "ip_port":      20,
}


def _safe_get(inserts, index, default=""):
    """Safely extract a StringInserts field by index."""
    try:
        val = inserts[index] if inserts else default
        return val.strip() if val else default
    except (IndexError, AttributeError):
        return default


def _parse_event(event) -> dict:
    """
    Parse a single win32evtlog event object into a clean dict.
    Only call this on EventID 4625 events.
    """
    inserts  = event.StringInserts or []

    # TimeGenerated is a pywintypes.datetime - convert to standard datetime
    try:
        ts = datetime(
            event.TimeGenerated.year,
            event.TimeGenerated.month,
            event.TimeGenerated.day,
            event.TimeGenerated.hour,
            event.TimeGenerated.minute,
            event.TimeGenerated.second,
        )
    except Exception:
        ts = datetime.now()

    username    = _safe_get(inserts, FIELD["username"])
    ip_address  = _safe_get(inserts, FIELD["ip_address"])
    logon_type  = _safe_get(inserts, FIELD["logon_type"])
    substatus   = _safe_get(inserts, FIELD["substatus"])
    workstation = _safe_get(inserts, FIELD["workstation"])

    # Normalize IP - sometimes comes as "-" meaning local
    if ip_address in ("-", "", None):
        ip_address = "local"

    return {
        "event_id":    4625,
        "timestamp":   ts,
        "timestamp_str": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "username":    username,
        "domain":      _safe_get(inserts, FIELD["domain"]),
        "ip_address":  ip_address,
        "ip_port":     _safe_get(inserts, FIELD["ip_port"]),
        "logon_type":  logon_type,
        "substatus":   substatus,
        "workstation": workstation,
        "computer":    event.ComputerName,
    }


def read_failed_logins(
    max_events: int = 500,
    whitelist_users: list = None,
    whitelist_ips:   list = None,
) -> list:
    """
    Read the Security event log and return parsed 4625 events.

    Args:
        max_events:      Max events to scan per call (controls speed)
        whitelist_users: Usernames to ignore (SYSTEM, LOCAL SERVICE etc)
        whitelist_ips:   Source IPs to ignore (localhost etc)

    Returns:
        List of parsed event dicts, newest first.

    Raises:
        PermissionError if not running as Administrator.
    """
    whitelist_users = [u.upper() for u in (whitelist_users or [])]
    whitelist_ips   = whitelist_ips or []
    results         = []
    handle          = None

    flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
             win32evtlog.EVENTLOG_SEQUENTIAL_READ)

    try:
        handle    = win32evtlog.OpenEventLog(None, "Security")
        scanned   = 0

        while scanned < max_events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break

            for event in events:
                if (event.EventID & 0xFFFF) != 4625:
                    scanned += 1
                    continue

                parsed = _parse_event(event)

                # Apply whitelists
                if parsed["username"].upper() in whitelist_users:
                    scanned += 1
                    continue
                if parsed["ip_address"] in whitelist_ips:
                    scanned += 1
                    continue

                results.append(parsed)
                scanned += 1

                if scanned >= max_events:
                    break

    finally:
        if handle:
            win32evtlog.CloseEventLog(handle)

    return results
