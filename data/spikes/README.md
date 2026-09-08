# Live communications metadata spike

This folder documents a manual, read-only validation of the metadata assumptions
behind Sentinel's communications policy. The probe does not send messages,
change sharing, update events, or act as a production enforcement adapter.

## Access boundary

Keep provider access tokens only in the current shell environment:

- `SENTINEL_SPIKE_SLACK_TOKEN`
- `SENTINEL_SPIKE_GOOGLE_TOKEN`
- `SENTINEL_SPIKE_GOOGLE_DRIVE_RESOURCE_KEY` when a directly link-shared
  Drive item requires one

Do not put tokens in this repository, command arguments, saved reports, or an
`.env` file. `data/spikes/local/` is gitignored and is the recommended location
for sanitized summaries.

The Slack test app needs read-only access sufficient for `auth.test`,
`team.info`, `conversations.info`, `conversations.members`, and `users.info`.
Typical bot scopes are `team:read`, `channels:read`, `groups:read`, and
`users:read`; the exact scopes depend on which test channels the app can see.

The Google test principal needs OpenID `email`, Directory user/group/member
read-only access, plus the read-only scope for the surface being tested:

- Drive metadata: `drive.metadata.readonly`
- Gmail drafts: `gmail.readonly`
- Calendar events: `calendar.readonly`

Directory calls require an authorized Workspace administrator or equivalent
domain-wide delegation in the test tenant. A consumer Gmail account cannot
prove Workspace tenant membership, so Sentinel deliberately treats that setup
as insufficient.

## Manual commands

Run from the repository root after exporting the relevant token:

```bash
PYTHONPATH=src python3 scripts/run_live_metadata_spike.py \
  --output data/spikes/local/slack-internal.json \
  slack --channel-id CHANNEL_ID

PYTHONPATH=src python3 scripts/run_live_metadata_spike.py \
  --output data/spikes/local/drive-public.json \
  google-drive --file-id FILE_ID

PYTHONPATH=src python3 scripts/run_live_metadata_spike.py \
  --output data/spikes/local/gmail-external.json \
  gmail --draft-id DRAFT_ID

PYTHONPATH=src python3 scripts/run_live_metadata_spike.py \
  --output data/spikes/local/calendar-recurring.json \
  calendar --calendar-id CALENDAR_ID --event-id EVENT_ID
```

The report contains counts, missing field names, limitations, and hashes of
resource IDs. It intentionally excludes raw provider payloads, names, email
addresses, channel IDs, file IDs, event IDs, and tokens.

## Seeded test matrix

Test at least:

1. Slack: private internal channel, public internal channel, guest member, and
   Slack Connect/external member.
2. Drive: internal user permission, external user permission, group permission,
   domain link, public link, inherited permission, and shortcut target.
3. Gmail: internal-only draft, external recipient, Bcc recipient, and an
   expandable Workspace group.
4. Calendar: internal event, external attendee, additional guests, recurring
   event, and event with a Drive attachment.

For this spike, a Calendar event must use explicit `private`, `public`, or
`confidential` visibility. The provider's `default` value inherits calendar ACL
rules that this narrow probe does not resolve, so Sentinel reports it as
incomplete instead of guessing.

Expected behavior is fail-closed: missing pagination, identity, sharing,
membership, expansion, inheritance, or recurrence facts produce an
`incomplete` result rather than a safe assumption.

## Current result

The framework and deterministic fixture tests are implemented. On 2026-09-07,
the minimum live Slack test passed against one public, internal test channel:
all 16 required fields were present, membership stayed stable across the
double-read, one audience with two recipients resolved, and no guest or
external recipients were reported. The probe completed in eight read-only API
calls and retained both documented limitations. This validates the basic live
Slack metadata path, not Slack Connect, guest, private-channel, scheduled-send,
or production enforcement behavior. Google Workspace live validation is
deferred.
