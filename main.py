# -*- coding: utf-8 -*-
"""
main.py - Failed Login Monitor
Usage:
  python main.py                                  # Monitor with defaults
  python main.py --threshold 3 --window 120       # Custom threshold
  python main.py --output csv                     # CSV alerts only
  python main.py --output teams --webhook-url URL # Teams alerts
  python main.py --output all                     # All destinations
  python main.py --logon-type 10                  # Watch RDP only
  python main.py --dry-run                        # Detect, no alerts fired
  python main.py --interval 60                    # Poll every 60s
"""

import argparse, json, os, sys, time, signal
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modules.logger       import get_logger
from modules.event_reader import read_failed_logins
from modules.threshold    import BruteForceDetector
from modules.alerter      import dispatch_alert


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Failed Login Monitor - real-time brute force detection."
    )
    p.add_argument("--threshold",    type=int, default=None,
                   help="Failed login count to trigger alert (overrides config)")
    p.add_argument("--window",       type=int, default=None,
                   help="Time window in seconds (overrides config)")
    p.add_argument("--interval",     type=int, default=None,
                   help="Poll interval in seconds (overrides config)")
    p.add_argument("--output",
                   choices=["csv", "teams", "eventlog", "all"],
                   default=None,
                   help="Alert destination (overrides config)")
    p.add_argument("--webhook-url",  default="",
                   help="Teams incoming webhook URL")
    p.add_argument("--logon-type",   type=str, default=None,
                   help="Only watch specific logon type (e.g. 10 for RDP)")
    p.add_argument("--dry-run",      action="store_true",
                   help="Detect and log - fire no alerts.")
    p.add_argument("--config",
                   default=os.path.join(BASE_DIR, "config.json"),
                   help="Path to config file.")
    p.add_argument("--once",         action="store_true",
                   help="Run one poll then exit (useful for testing).")
    return p


def run_monitor(args, cfg, log):
    # Apply CLI overrides to config
    if args.threshold:
        cfg["thresholds"]["per_username"]["count"] = args.threshold
        cfg["thresholds"]["per_source_ip"]["count"] = args.threshold
    if args.window:
        cfg["thresholds"]["per_username"]["window_seconds"] = args.window
        cfg["thresholds"]["per_source_ip"]["window_seconds"] = args.window

    interval    = args.interval or cfg["poll_interval_seconds"]
    report_dir  = os.path.join(BASE_DIR, cfg["report_dir"])
    webhook_url = args.webhook_url or cfg.get("teams_webhook_url", "")

    # Alert destinations
    if args.output == "all":
        destinations = ["csv", "eventlog", "teams"]
    elif args.output:
        destinations = [args.output]
    else:
        destinations = cfg["alert_destinations"]

    detector = BruteForceDetector(
        user_cfg = cfg["thresholds"]["per_username"],
        ip_cfg   = cfg["thresholds"]["per_source_ip"],
    )

    log.info("=" * 60)
    log.info("FAILED LOGIN MONITOR STARTED")
    log.info(f"User threshold : {cfg['thresholds']['per_username']['count']} "
             f"in {cfg['thresholds']['per_username']['window_seconds']}s")
    log.info(f"IP threshold   : {cfg['thresholds']['per_source_ip']['count']} "
             f"in {cfg['thresholds']['per_source_ip']['window_seconds']}s")
    log.info(f"Poll interval  : {interval}s")
    log.info(f"Destinations   : {destinations}")
    log.info(f"Dry-run        : {args.dry_run}")
    log.info("=" * 60)

    # Track last seen event timestamp to avoid reprocessing old events
    last_seen = datetime.min
    poll_num  = 0

    # Graceful shutdown on Ctrl+C
    running = [True]
    def _stop(sig, frame):
        log.info("Shutdown signal received.")
        running[0] = False
    signal.signal(signal.SIGINT, _stop)

    while running[0]:
        poll_num += 1
        log.info(f"Poll #{poll_num} starting...")

        try:
            events = read_failed_logins(
                max_events      = cfg["max_events_per_poll"],
                whitelist_users = cfg["whitelist_usernames"],
                whitelist_ips   = cfg["whitelist_ips"],
            )

            # Filter to only logon type if --logon-type specified
            if args.logon_type:
                events = [e for e in events
                          if e["logon_type"] == args.logon_type]

            # Only process events newer than what we saw last poll
            new_events = [e for e in events
                          if e["timestamp"] > last_seen]

            if new_events:
                last_seen = max(e["timestamp"] for e in new_events)

            log.info(f"  {len(events)} total 4625 events | "
                     f"{len(new_events)} new this poll")

            total_alerts = 0
            for event in new_events:
                alerts = detector.process_event(event)
                for alert in alerts:
                    total_alerts += 1
                    log.warning(
                        f"  ALERT: {alert['alert_type']} | "
                        f"{alert['key']} | count={alert['count']} | "
                        f"severity={alert['severity']}"
                    )

                    if args.dry_run:
                        log.info("  DRY-RUN: alert suppressed.")
                        print(f"\n[DRY-RUN] Would alert:")
                        print(json.dumps(alert, indent=2, default=str))
                    else:
                        results = dispatch_alert(
                            alert,
                            destinations,
                            report_dir  = report_dir,
                            webhook_url = webhook_url,
                        )
                        log.info(f"  Dispatch results: {results}")

            if total_alerts == 0:
                log.info("  No thresholds crossed this poll.")

            # Print live stats every poll
            stats = detector.get_stats()
            if any(stats["usernames"].values()) or any(stats["ips"].values()):
                log.info(f"  Window counts - users: {stats['usernames']} "
                         f"| IPs: {stats['ips']}")

        except PermissionError:
            log.error("PermissionError: Run as Administrator to read Security log.")
            break
        except Exception as e:
            log.error(f"Poll error: {e}", exc_info=True)

        if args.once:
            log.info("--once flag set. Exiting after first poll.")
            break

        log.info(f"Sleeping {interval}s until next poll...")
        time.sleep(interval)

    log.info("Monitor stopped.")


def main():
    parser = build_argparser()
    args   = parser.parse_args()
    cfg    = load_config(args.config)
    log    = get_logger(
        "monitor",
        os.path.join(BASE_DIR, cfg["log_file"])
    )
    run_monitor(args, cfg, log)


if __name__ == "__main__":
    main()
