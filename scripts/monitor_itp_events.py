#!/usr/bin/env python3
"""
monitor_itp_events.py

Real-time monitor for Okta Identity Threat Protection (ITP) events.
Polls the Okta System Log (/api/v1/logs) for ITP-related events and displays
them with color-coded severity indicators and contextual detail.

This is a key tool for ITP demos: run it in a terminal before triggering a
risk signal so stakeholders can watch Okta detect risk, evaluate entity risk
policy rules, and execute automated remediation (e.g., universal logout) in
real time.

Event types watched (see ITP_EVENT_TYPES):
  - user.risk.detect          A risk signal was received for a user (from SSF,
                               session hijacking detection, or admin API).
  - policy.entity_risk.evaluate  The entity risk policy engine evaluated rules
                               against the user's current risk level.
  - policy.entity_risk.action An automated action (e.g., UNIVERSAL_LOGOUT)
                               was triggered by an entity risk policy rule.
  - user.session.end          A user's session was terminated (often the result
                               of a UNIVERSAL_LOGOUT action).
  - user.authentication.universal_logout  Okta sent Universal Logout signals to
                               all integrated apps for this user.

Usage:
    python3 scripts/monitor_itp_events.py --duration 60
    python3 scripts/monitor_itp_events.py --user user@example.com --duration 120
    python3 scripts/monitor_itp_events.py --event-types user.risk.detect,policy.entity_risk.action
"""

import os
import sys
import time
import json
import requests
import argparse
from datetime import datetime, timezone, timedelta
from typing import List, Optional


# ITP event types to monitor by default.  These represent the full lifecycle of
# an ITP risk-detect-and-respond flow:
#   1. Risk detected  ->  2. Policy evaluated  ->  3. Action taken  ->
#   4/5. Sessions terminated / Universal Logout broadcast
ITP_EVENT_TYPES = [
    "user.risk.detect",                      # Risk signal ingested for a user
    "policy.entity_risk.evaluate",           # Policy engine evaluated rules
    "policy.entity_risk.action",             # Automated action was executed
    "user.session.end",                      # User session was terminated
    "user.authentication.universal_logout",  # UL signals sent to apps
]


class ITPEventMonitor:
    """Monitors Okta system log for ITP events in real-time"""

    def __init__(self, org_name: str, base_url: str, api_token: str):
        self.org_name = org_name
        self.base_url = f"https://{org_name}.{base_url}"
        self.api_base = f"{self.base_url}/api/v1"
        self.headers = {
            "Authorization": f"SSWS {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        # Reuse a single requests.Session for connection pooling across polls
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        # Track event UUIDs we have already displayed so we never print duplicates
        # when poll windows overlap.
        self.seen_events = set()

    def build_filter(self, event_types: List[str], user: Optional[str] = None) -> str:
        """Build system log filter expression.

        Note: For ITP events, the affected user is in the target array, not the
        actor. The actor is typically the admin/API token owner or system.
        """
        type_filters = [f'eventType eq "{et}"' for et in event_types]
        filter_expr = "(" + " or ".join(type_filters) + ")"

        if user:
            filter_expr += f' and target.alternateId eq "{user}"'

        return filter_expr

    def poll_events(self, since: str, event_types: List[str],
                    user: Optional[str] = None) -> List[dict]:
        """Poll the Okta System Log for new ITP events since the given timestamp.

        The System Log API is polled with ASCENDING sort order so that the
        caller can advance the ``since`` cursor to the timestamp of the last
        returned event, avoiding unbounded result growth over long monitoring
        sessions.
        """
        url = f"{self.api_base}/logs"
        filter_expr = self.build_filter(event_types, user)

        params = {
            "since": since,
            "filter": filter_expr,
            "sortOrder": "ASCENDING",  # Oldest first so we can advance the cursor
            "limit": 100,              # Max page size to reduce round-trips
        }

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()

            events = response.json()
            # De-duplicate: the poll window may overlap with the previous one,
            # so we track each event's UUID and skip any we have already shown.
            new_events = []
            for event in events:
                event_id = event.get("uuid")
                if event_id and event_id not in self.seen_events:
                    self.seen_events.add(event_id)
                    new_events.append(event)

            return new_events

        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            try:
                error_detail = e.response.json()
                error_msg = error_detail.get("errorSummary", error_msg)
            except Exception:
                pass
            print(f"  [error] Failed to poll events: {error_msg}")
            return []
        except Exception as e:
            print(f"  [error] Unexpected error: {e}")
            return []

    def format_event(self, event: dict) -> str:
        """Format a single ITP event for human-readable console output.

        Each event is prefixed with a two-character severity indicator:
          !!  risk detected (user.risk.detect)
          ??  policy evaluation (policy.entity_risk.evaluate)
          >>  automated action taken (policy.entity_risk.action)
          XX  session ended or universal logout sent
          --  any other event type
        """
        event_type = event.get("eventType", "unknown")
        published = event.get("published", "")
        actor = event.get("actor", {})
        actor_name = actor.get("displayName", actor.get("alternateId", "Unknown"))
        outcome = event.get("outcome", {})
        outcome_result = outcome.get("result", "")
        outcome_reason = outcome.get("reason", "")
        display_message = event.get("displayMessage", "")

        # Extract client/network context -- useful for demonstrating that Okta
        # captures the originating IP and geolocation of the risk signal.
        client = event.get("client", {})
        ip_address = client.get("ipAddress", "")
        geo = client.get("geographicalContext") or {}
        city = geo.get("city", "")
        country = geo.get("country", "")
        geo_str = f"{city}, {country}" if city else country

        # Extract target info -- for ITP events the target is typically the
        # affected user (not the actor, which is often the system/API token).
        targets = event.get("target", [])
        target_str = ""
        if targets:
            target_names = [t.get("displayName", t.get("alternateId", "")) for t in targets]
            target_str = ", ".join(filter(None, target_names))

        # debugContext.debugData carries risk-specific detail that is not in
        # the top-level event fields -- riskLevel and riskReasons are the most
        # interesting for demo narration.
        debug_data = event.get("debugContext", {}).get("debugData", {})
        risk_level = debug_data.get("riskLevel", "")
        risk_reasons = debug_data.get("riskReasons", "")

        # Two-character severity indicator shown at the start of each event
        # line so the audience can visually track the flow at a glance.
        severity_map = {
            "user.risk.detect": "!!",                       # Alert: risk signal
            "policy.entity_risk.action": ">>",              # Action executed
            "policy.entity_risk.evaluate": "??",            # Policy evaluated
            "user.session.end": "XX",                       # Session killed
            "user.authentication.universal_logout": "XX",   # UL broadcast
        }
        severity = severity_map.get(event_type, "--")

        # Format timestamp to local-ish display
        try:
            dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            time_str = dt.strftime("%H:%M:%S")
        except Exception:
            time_str = published[:19]

        lines = [f"[{severity}] {time_str}  {event_type}"]
        lines.append(f"    Actor: {actor_name}")
        if display_message:
            lines.append(f"    Message: {display_message}")
        if target_str:
            lines.append(f"    Target: {target_str}")
        if ip_address:
            geo_info = f" ({geo_str})" if geo_str else ""
            lines.append(f"    IP: {ip_address}{geo_info}")
        if risk_level:
            lines.append(f"    Risk Level: {risk_level}")
        if risk_reasons:
            lines.append(f"    Risk Reasons: {risk_reasons}")
        if outcome_result:
            reason_info = f" — {outcome_reason}" if outcome_reason else ""
            lines.append(f"    Outcome: {outcome_result}{reason_info}")

        return "\n".join(lines)

    def monitor(self, duration: int = 60, event_types: Optional[List[str]] = None,
                user: Optional[str] = None, poll_interval: int = 3) -> List[dict]:
        """
        Monitor ITP events for a specified duration.

        Args:
            duration: How long to monitor in seconds
            event_types: Which event types to watch (default: all ITP events)
            user: Optional user to filter by (alternateId/email)
            poll_interval: Seconds between polls (default: 3)

        Returns:
            List of all captured events
        """
        if event_types is None:
            event_types = ITP_EVENT_TYPES

        print("=" * 80)
        print("ITP EVENT MONITOR")
        print("=" * 80)
        print(f"  Duration: {duration}s")
        print(f"  Event types: {', '.join(event_types)}")
        if user:
            print(f"  User filter: {user}")
        print(f"  Poll interval: {poll_interval}s")
        print("=" * 80)
        print()

        # Start the query window 30 seconds in the past so that events fired
        # just before the monitor started (e.g., a trigger_itp_demo.py that
        # was kicked off moments earlier) are still captured.
        since = (datetime.now(timezone.utc) - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        start_time = time.time()
        all_events = []
        event_count = 0

        print(f"Monitoring... (press Ctrl+C to stop)\n")

        try:
            # Main polling loop: repeatedly query the System Log until the
            # requested duration elapses or the user presses Ctrl+C.
            while (time.time() - start_time) < duration:
                elapsed = int(time.time() - start_time)
                remaining = duration - elapsed

                new_events = self.poll_events(since, event_types, user)

                if new_events:
                    for event in new_events:
                        event_count += 1
                        formatted = self.format_event(event)
                        print(formatted)
                        print()
                        all_events.append(event)

                    # Advance the cursor to the latest event's timestamp so the
                    # next poll only fetches newer events.
                    latest = new_events[-1].get("published", since)
                    since = latest
                else:
                    # No new events this cycle -- show a progress line so the
                    # user knows the monitor is still running.
                    sys.stdout.write(f"\r  Waiting for events... ({remaining}s remaining, {event_count} captured)")
                    sys.stdout.flush()

                # Sleep between polls to avoid hammering the API and to respect
                # Okta rate limits (system log allows ~50 req/min).
                time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")

        # Summary
        print("\n" + "=" * 80)
        print("MONITORING SUMMARY")
        print("=" * 80)
        print(f"  Duration: {int(time.time() - start_time)}s")
        print(f"  Events captured: {event_count}")

        if all_events:
            # Count by type
            type_counts = {}
            for event in all_events:
                et = event.get("eventType", "unknown")
                type_counts[et] = type_counts.get(et, 0) + 1

            print("  By type:")
            for et, count in sorted(type_counts.items()):
                print(f"    {et}: {count}")

        print("=" * 80)

        return all_events


def main():
    parser = argparse.ArgumentParser(
        description="Monitor Okta ITP events in real-time"
    )
    parser.add_argument(
        "--org-name",
        default=os.environ.get("OKTA_ORG_NAME"),
        help="Okta organization name"
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OKTA_BASE_URL", "okta.com"),
        help="Okta base URL"
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("OKTA_API_TOKEN"),
        help="Okta API token"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Monitoring duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--user",
        help="Filter events by user email/alternateId"
    )
    parser.add_argument(
        "--event-types",
        help=f"Comma-separated event types to monitor (default: all ITP events)"
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=3,
        help="Seconds between polls (default: 3)"
    )
    parser.add_argument(
        "--output",
        help="Save captured events to JSON file"
    )

    args = parser.parse_args()

    if not args.org_name or not args.api_token:
        print("Error: OKTA_ORG_NAME and OKTA_API_TOKEN must be set")
        sys.exit(1)

    event_types = None
    if args.event_types:
        event_types = [et.strip() for et in args.event_types.split(",")]

    monitor = ITPEventMonitor(args.org_name, args.base_url, args.api_token)
    events = monitor.monitor(
        duration=args.duration,
        event_types=event_types,
        user=args.user,
        poll_interval=args.poll_interval
    )

    if args.output and events:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(events, f, indent=2)
        print(f"\nEvents saved to {args.output}")

    sys.exit(0)


if __name__ == "__main__":
    main()
