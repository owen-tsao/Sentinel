#!/usr/bin/env python3
"""Manually run one read-only communications metadata probe."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from sentinel.spikes.common import LiveSpikeError
from sentinel.spikes.google_workspace import GoogleWorkspaceProbe
from sentinel.spikes.http import BoundedJsonHttpClient
from sentinel.spikes.reporting import summary_payload, write_summary
from sentinel.spikes.slack import probe_slack_channel


SLACK_HOSTS = {"slack.com"}
GOOGLE_HOSTS = {
    "openidconnect.googleapis.com",
    "admin.googleapis.com",
    "www.googleapis.com",
    "gmail.googleapis.com",
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve read-only provider metadata. This spike never sends, "
            "shares, modifies, or grants Sentinel production authority."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for a sanitized JSON summary; existing files are refused.",
    )
    subparsers = parser.add_subparsers(dest="provider", required=True)

    slack = subparsers.add_parser("slack")
    slack.add_argument("--channel-id", required=True)
    slack.add_argument("--reply-broadcast", action="store_true")

    drive = subparsers.add_parser("google-drive")
    drive.add_argument("--file-id", required=True)

    gmail = subparsers.add_parser("gmail")
    gmail.add_argument("--draft-id", required=True)

    calendar = subparsers.add_parser("calendar")
    calendar.add_argument("--calendar-id", required=True)
    calendar.add_argument("--event-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.provider == "slack":
            client = BoundedJsonHttpClient(allowed_hosts=SLACK_HOSTS)
            result = probe_slack_channel(
                client,
                bearer_token=_required_env("SENTINEL_SPIKE_SLACK_TOKEN"),
                channel_id=args.channel_id,
                reply_broadcast=args.reply_broadcast,
            )
        else:
            client = BoundedJsonHttpClient(allowed_hosts=GOOGLE_HOSTS)
            probe = GoogleWorkspaceProbe(
                client,
                bearer_token=_required_env("SENTINEL_SPIKE_GOOGLE_TOKEN"),
            )
            if args.provider == "google-drive":
                result = probe.probe_drive_file(
                    file_id=args.file_id,
                    resource_key=os.environ.get(
                        "SENTINEL_SPIKE_GOOGLE_DRIVE_RESOURCE_KEY"
                    ),
                )
            elif args.provider == "gmail":
                result = probe.probe_gmail_draft(draft_id=args.draft_id)
            else:
                result = probe.probe_calendar_event(
                    calendar_id=args.calendar_id,
                    event_id=args.event_id,
                )
        if args.output is not None:
            write_summary(result.summary, args.output)
        print(json.dumps(summary_payload(result.summary), indent=2, sort_keys=True))
        return 0 if result.summary.status == "complete" else 3
    except (LiveSpikeError, FileExistsError, ValueError) as exc:
        reason = (
            exc.reason_code
            if isinstance(exc, LiveSpikeError)
            else exc.__class__.__name__
        )
        print(json.dumps({"status": "error", "reason": reason}), file=sys.stderr)
        return 2


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise LiveSpikeError(f"spike:missing_{name.lower()}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
