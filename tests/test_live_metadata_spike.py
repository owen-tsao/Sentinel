from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinel.actions import CanonicalAction, compute_action_evidence_binding
from sentinel.audit.redaction import REDACTED, redact
from sentinel.platforms import ResolvedActionEvidence
from sentinel.spikes.common import LiveSpikeError
from sentinel.spikes.google_workspace import GoogleWorkspaceProbe
from sentinel.spikes.http import BoundedJsonHttpClient
from sentinel.spikes.reporting import write_summary
from sentinel.spikes.slack import probe_slack_channel


NOW = datetime(2026, 9, 4, 23, 0, tzinfo=timezone.utc)
NOT_A_CREDENTIAL = "not-a-credential"


class QueueClient:
    def __init__(self, responses: list[dict[str, Any] | LiveSpikeError]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str | list[str]]]] = []

    def get_json(
        self,
        url: str,
        *,
        bearer_token: str,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        assert bearer_token == NOT_A_CREDENTIAL
        assert headers is None or set(headers) == {"X-Goog-Drive-Resource-Keys"}
        self.calls.append((url, query or {}))
        if not self.responses:
            raise AssertionError(f"unexpected API call: {url}")
        response = self.responses.pop(0)
        if isinstance(response, LiveSpikeError):
            raise response
        return response


def test_bounded_http_client_rejects_non_allowlisted_target_before_network() -> None:
    client = BoundedJsonHttpClient(allowed_hosts={"slack.com"})

    with pytest.raises(LiveSpikeError, match="spike:http_target_not_allowed"):
        client.get_json(
            "https://example.test/collect",
            bearer_token=NOT_A_CREDENTIAL,
        )


def test_redaction_catches_provider_token_shapes() -> None:
    slack_shape = "xox" + "b-" + ("A" * 30)
    slack_app_shape = "xapp-" + ("C" * 30)
    slack_rotating_shape = "xoxe.xoxp-" + ("D" * 30)
    google_shape = "ya29." + ("B" * 30)

    assert redact(slack_shape) == REDACTED
    assert redact(slack_app_shape) == REDACTED
    assert redact(slack_rotating_shape) == REDACTED
    assert redact(google_shape) == REDACTED


def test_slack_probe_resolves_external_and_guest_members(tmp_path: Path) -> None:
    client = QueueClient(
        [
            {"ok": True, "team_id": "T1", "user_id": "UACTOR"},
            {"ok": True, "team": {"id": "T1"}},
            {
                "ok": True,
                "channel": {
                    "id": "C1",
                    "context_team_id": "T1",
                    "is_private": True,
                    "is_archived": False,
                    "is_shared": True,
                    "is_ext_shared": True,
                    "is_org_shared": False,
                    "is_pending_ext_shared": False,
                    "num_members": 2,
                    "updated": 123,
                },
            },
            {
                "ok": True,
                "members": ["U1", "U2"],
                "response_metadata": {"next_cursor": ""},
            },
            {
                "ok": True,
                "user": {
                    "id": "U1",
                    "team_id": "T1",
                    "is_restricted": False,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                },
            },
            {
                "ok": True,
                "user": {
                    "id": "U2",
                    "team_id": "T2",
                    "is_restricted": True,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                    "is_stranger": True,
                },
            },
            {
                "ok": True,
                "channel": {
                    "id": "C1",
                    "context_team_id": "T1",
                    "is_private": True,
                    "is_archived": False,
                    "is_shared": True,
                    "is_ext_shared": True,
                    "is_org_shared": False,
                    "is_pending_ext_shared": False,
                    "num_members": 2,
                    "updated": 123,
                },
            },
            {
                "ok": True,
                "members": ["U1", "U2"],
                "response_metadata": {"next_cursor": ""},
            },
            {
                "ok": True,
                "user": {
                    "id": "U1",
                    "team_id": "T1",
                    "is_restricted": False,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                },
            },
            {
                "ok": True,
                "user": {
                    "id": "U2",
                    "team_id": "T2",
                    "is_restricted": True,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                    "is_stranger": True,
                },
            },
        ]
    )

    result = probe_slack_channel(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        channel_id="C1",
        retrieved_at=NOW,
    )

    assert result.summary.status == "complete"
    assert result.summary.external_recipient_count == 1
    assert result.summary.guest_recipient_count == 1
    assert result.summary.public_audience is False
    evidence = result.action.resolved_evidence
    assert evidence is not None
    assert evidence.action_binding_sha256 == compute_action_evidence_binding(
        result.action
    )
    action_payload = result.action.model_dump(mode="python")
    action_payload["dry_run"] = True
    mutated_action = CanonicalAction(**action_payload)
    assert evidence.action_binding_sha256 != compute_action_evidence_binding(
        mutated_action
    )
    evidence_payload = evidence.model_dump(mode="python")
    evidence_payload["audiences"][0]["resolution_complete"] = False
    with pytest.raises(ValidationError):
        ResolvedActionEvidence(**evidence_payload)
    assert evidence.audiences[0].is_external_shared is True
    assert set(evidence.provenance.source_fields) == set(
        result.summary.field_coverage.present
    )
    assert result.summary.production_enforcement is False
    assert not client.responses
    report = tmp_path / "summary.json"
    write_summary(result.summary, report)
    report_text = report.read_text(encoding="utf-8")
    assert "C1" not in report_text
    assert "U2" not in report_text
    assert json.loads(report_text)["provider"] == "slack"
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_summary(result.summary, report)


def test_slack_probe_marks_omitted_sharing_metadata_incomplete() -> None:
    client = QueueClient(
        [
            {"ok": True, "team_id": "T1", "user_id": "UACTOR"},
            {"ok": True, "team": {"id": "T1"}},
            {
                "ok": True,
                "channel": {
                    "id": "C1",
                    "context_team_id": "T1",
                    "is_private": False,
                    "is_archived": False,
                    "is_shared": False,
                    "is_ext_shared": None,
                    "is_org_shared": False,
                    "is_pending_ext_shared": False,
                    "num_members": 1,
                    "updated": 123,
                },
            },
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {
                "ok": True,
                "user": {
                    "id": "U1",
                    "team_id": "T1",
                    "is_restricted": False,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                },
            },
            {
                "ok": True,
                "channel": {
                    "id": "C1",
                    "context_team_id": "T1",
                    "is_private": False,
                    "is_archived": False,
                    "is_shared": False,
                    "is_ext_shared": None,
                    "is_org_shared": False,
                    "is_pending_ext_shared": False,
                    "num_members": 1,
                    "updated": 123,
                },
            },
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {
                "ok": True,
                "user": {
                    "id": "U1",
                    "team_id": "T1",
                    "is_restricted": False,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                },
            },
        ]
    )

    result = probe_slack_channel(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        channel_id="C1",
        retrieved_at=NOW,
    )

    assert result.summary.status == "incomplete"
    assert result.summary.field_coverage.missing == ["channel.is_ext_shared"]


def test_slack_probe_detects_same_count_membership_swap() -> None:
    channel = {
        "id": "C1",
        "context_team_id": "T1",
        "is_private": True,
        "is_archived": False,
        "is_shared": False,
        "is_ext_shared": False,
        "is_org_shared": False,
        "is_pending_ext_shared": False,
        "num_members": 1,
        "updated": 123,
    }
    client = QueueClient(
        [
            {"ok": True, "team_id": "T1", "user_id": "UACTOR"},
            {"ok": True, "team": {"id": "T1"}},
            {"ok": True, "channel": channel},
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {
                "ok": True,
                "user": {
                    "id": "U1",
                    "team_id": "T1",
                    "is_restricted": False,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                },
            },
            {"ok": True, "channel": channel},
            {
                "ok": True,
                "members": ["U2"],
                "response_metadata": {"next_cursor": ""},
            },
            {
                "ok": True,
                "user": {
                    "id": "U2",
                    "team_id": "T1",
                    "is_restricted": False,
                    "is_ultra_restricted": False,
                    "deleted": False,
                    "is_bot": False,
                },
            },
        ]
    )

    result = probe_slack_channel(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        channel_id="C1",
        retrieved_at=NOW,
    )

    assert result.summary.status == "incomplete"
    assert "channel.stable" in result.summary.field_coverage.missing


def test_slack_probe_fails_closed_when_user_classification_changes() -> None:
    channel = {
        "id": "C1",
        "context_team_id": "T1",
        "is_private": True,
        "is_archived": False,
        "is_shared": True,
        "is_ext_shared": True,
        "is_org_shared": False,
        "is_pending_ext_shared": False,
        "num_members": 1,
        "updated": 123,
    }
    internal_user = {
        "id": "U1",
        "team_id": "T1",
        "is_restricted": False,
        "is_ultra_restricted": False,
        "deleted": False,
        "is_bot": False,
    }
    external_user = {**internal_user, "team_id": "T2", "is_stranger": True}
    client = QueueClient(
        [
            {"ok": True, "team_id": "T1", "user_id": "UACTOR"},
            {"ok": True, "team": {"id": "T1"}},
            {"ok": True, "channel": channel},
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {"ok": True, "user": internal_user},
            {"ok": True, "channel": channel},
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {"ok": True, "user": external_user},
        ]
    )

    result = probe_slack_channel(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        channel_id="C1",
        retrieved_at=NOW,
    )

    assert result.summary.status == "incomplete"
    assert result.summary.external_recipient_count == 1
    assert "users.classified" in result.summary.field_coverage.missing
    assert any(
        "classification changed" in limitation
        for limitation in result.summary.limitations
    )


def test_slack_probe_fails_closed_when_second_classification_is_incomplete() -> None:
    channel = {
        "id": "C1",
        "context_team_id": "T1",
        "is_private": True,
        "is_archived": False,
        "is_shared": False,
        "is_ext_shared": False,
        "is_org_shared": False,
        "is_pending_ext_shared": False,
        "num_members": 1,
        "updated": 123,
    }
    complete_user = {
        "id": "U1",
        "team_id": "T1",
        "is_restricted": False,
        "is_ultra_restricted": False,
        "deleted": False,
        "is_bot": False,
    }
    client = QueueClient(
        [
            {"ok": True, "team_id": "T1", "user_id": "UACTOR"},
            {"ok": True, "team": {"id": "T1"}},
            {"ok": True, "channel": channel},
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {"ok": True, "user": complete_user},
            {"ok": True, "channel": channel},
            {
                "ok": True,
                "members": ["U1"],
                "response_metadata": {"next_cursor": ""},
            },
            {"ok": True, "user": {**complete_user, "is_bot": None}},
        ]
    )

    result = probe_slack_channel(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        channel_id="C1",
        retrieved_at=NOW,
    )

    assert result.summary.status == "incomplete"
    assert "users.classified" in result.summary.field_coverage.missing
    assert any(
        "during revalidation" in limitation
        for limitation in result.summary.limitations
    )


def test_google_drive_probe_fails_closed_for_public_unenumerable_audience() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"user": {"permissionId": "P-OWNER", "emailAddress": "owner@example.test"}},
            {
                "id": "F1",
                "mimeType": "application/pdf",
                "version": "4",
            },
            {
                "permissions": [
                    {
                        "id": "P-ANY",
                        "type": "anyone",
                        "role": "reader",
                        "allowFileDiscovery": True,
                    }
                ]
            },
            {"id": "F1", "version": "4"},
        ]
    )
    probe = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    )

    result = probe.probe_drive_file(file_id="F1")

    assert result.summary.status == "incomplete"
    assert result.summary.public_audience is True
    assert result.action.resolved_evidence is not None
    assert result.action.resolved_evidence.resolution_complete is False
    assert result.action.resolved_evidence.action_binding_sha256 == (
        compute_action_evidence_binding(result.action)
    )
    assert result.action.effects == {"share_read"}


def test_google_drive_probe_rejects_missing_revision_and_mime_type() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"user": {"permissionId": "P-OWNER"}},
            {"id": "F1", "mimeType": None, "version": None},
            {"permissions": []},
            {"id": "F1", "version": None},
        ]
    )

    result = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    ).probe_drive_file(file_id="F1")

    assert result.summary.status == "incomplete"
    assert {
        "drive_file.mimeType",
        "drive_file.version",
        "drive_file.stable",
    }.issubset(result.summary.field_coverage.missing)
    evidence = result.action.resolved_evidence
    assert evidence is not None
    assert set(evidence.provenance.source_fields) == set(
        result.summary.field_coverage.present
    )


def test_google_drive_probe_requires_shared_drive_inheritance_details() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"user": {"permissionId": "P-OWNER"}},
            {
                "id": "F1",
                "mimeType": "application/pdf",
                "version": "4",
                "driveId": "D1",
            },
            {
                "permissions": [
                    {
                        "id": "P1",
                        "type": "user",
                        "role": "reader",
                        "emailAddress": "owner@example.test",
                        "permissionDetails": [],
                    }
                ]
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"id": "F1", "version": "4"},
        ]
    )

    result = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    ).probe_drive_file(file_id="F1")

    assert result.summary.status == "incomplete"
    assert "drive_permissions.classified" in result.summary.field_coverage.missing


def test_google_drive_unknown_role_is_incomplete_and_conservatively_write_capable() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"user": {"permissionId": "P-OWNER"}},
            {
                "id": "F1",
                "mimeType": "application/pdf",
                "version": "4",
            },
            {
                "permissions": [
                    {
                        "id": "P1",
                        "type": "user",
                        "role": "futureRole",
                        "emailAddress": "owner@example.test",
                    }
                ]
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"id": "F1", "version": "4"},
        ]
    )

    result = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    ).probe_drive_file(file_id="F1")

    assert result.summary.status == "incomplete"
    assert result.action.effects == {"share_write"}
    assert "drive_permissions.classified" in result.summary.field_coverage.missing


def test_google_gmail_probe_parses_metadata_draft_headers() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"emailAddress": "owner@example.test", "historyId": "1"},
            {
                "id": "D1",
                "message": {"id": "M1"},
            },
            {
                "id": "M1",
                "payload": {
                    "headers": [
                        {"name": "To", "value": "teammate@example.test"},
                        {"name": "Cc", "value": "outsider@external.test"},
                    ]
                },
            },
            {
                "id": "U2",
                "customerId": "C1",
                "primaryEmail": "teammate@example.test",
            },
            LiveSpikeError("spike:http_status_404"),
            LiveSpikeError("spike:http_status_404"),
            {"id": "D1", "message": {"id": "M1"}},
        ]
    )
    probe = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    )

    result = probe.probe_gmail_draft(draft_id="D1")

    assert result.summary.status == "complete"
    assert result.summary.recipient_count == 2
    assert result.summary.external_recipient_count == 1
    assert result.action.resolved_evidence is not None
    assert result.action.resolved_evidence.audiences[0].is_external_shared is True
    assert client.calls[4][1]["metadataHeaders"] == ["To", "Cc", "Bcc"]
    assert client.calls[4][1]["fields"] == "id,payload(headers(name,value))"


def test_google_gmail_probe_rejects_malformed_recipient_header() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"emailAddress": "owner@example.test"},
            {
                "id": "D1",
                "message": {"id": "M1"},
            },
            {
                "id": "M1",
                "payload": {
                    "headers": [
                        {
                            "name": "To",
                            "value": "first@example.test second@example.test",
                        }
                    ]
                },
            },
            {"id": "D1", "message": {"id": "M1"}},
        ]
    )

    result = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    ).probe_gmail_draft(draft_id="D1")

    assert result.summary.status == "incomplete"
    assert "gmail_recipients.classified" in result.summary.field_coverage.missing
    evidence = result.action.resolved_evidence
    assert evidence is not None
    assert set(evidence.provenance.source_fields) == set(
        result.summary.field_coverage.present
    )


def test_google_gmail_probe_detects_group_membership_change() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"emailAddress": "owner@example.test"},
            {"id": "D1", "message": {"id": "M1"}},
            {
                "id": "M1",
                "payload": {
                    "headers": [
                        {"name": "To", "value": "team@example.test"},
                    ]
                },
            },
            LiveSpikeError("spike:http_status_404"),
            {"id": "G1", "email": "team@example.test"},
            {
                "etag": "members-v1",
                "members": [
                    {
                        "id": "U2",
                        "email": "member@example.test",
                        "type": "USER",
                    }
                ],
            },
            {
                "id": "U2",
                "customerId": "C1",
                "primaryEmail": "member@example.test",
            },
            {
                "etag": "members-v2",
                "members": [
                    {
                        "id": "U3",
                        "email": "replacement@example.test",
                        "type": "USER",
                    }
                ],
            },
            {"id": "D1", "message": {"id": "M1"}},
        ]
    )

    result = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    ).probe_gmail_draft(draft_id="D1")

    assert result.summary.status == "incomplete"
    assert any(
        "group membership changed" in limitation
        for limitation in result.summary.limitations
    )


def test_google_calendar_marks_unnamed_guests_and_recurrence_incomplete() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"id": "owner@example.test"},
            {
                "id": "E1",
                "status": "confirmed",
                "attendees": [
                    {
                        "email": "owner@example.test",
                        "additionalGuests": 2,
                    },
                    "malformed-attendee",
                ],
                "recurringEventId": "PARENT1",
                "attendeesOmitted": "false",
                "guestsCanInviteOthers": False,
                "visibility": "private",
                "etag": "v1",
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"id": "E1", "etag": "v1"},
        ]
    )
    probe = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    )

    result = probe.probe_calendar_event(
        calendar_id="owner@example.test",
        event_id="E1",
    )

    assert result.summary.status == "incomplete"
    audience = result.action.resolved_evidence.audiences[0]  # type: ignore[union-attr]
    assert audience.recipient_count == 3
    assert audience.allows_recipient_expansion is True
    assert "calendar_recipients.classified" in (
        result.summary.field_coverage.missing
    )
    assert "event.attendeesOmitted" in result.summary.field_coverage.missing
    evidence = result.action.resolved_evidence
    assert evidence is not None
    assert set(evidence.provenance.source_fields) == set(
        result.summary.field_coverage.present
    )


def test_google_calendar_completes_for_explicit_private_internal_event() -> None:
    client = QueueClient(
        [
            {
                "sub": "SUB1",
                "email": "owner@example.test",
                "email_verified": True,
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"id": "owner@example.test"},
            {
                "id": "E1",
                "status": "confirmed",
                "attendees": [
                    {
                        "email": "owner@example.test",
                        "resource": False,
                        "additionalGuests": 0,
                    }
                ],
                "attendeesOmitted": False,
                "guestsCanInviteOthers": False,
                "visibility": "private",
                "etag": "v1",
            },
            {
                "id": "U1",
                "customerId": "C1",
                "primaryEmail": "owner@example.test",
            },
            {"id": "E1", "etag": "v1"},
        ]
    )

    result = GoogleWorkspaceProbe(
        client,
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    ).probe_calendar_event(
        calendar_id="owner@example.test",
        event_id="E1",
    )

    assert result.summary.status == "complete"
    assert result.summary.external_recipient_count == 0
    assert result.summary.public_audience is False
    assert result.action.effects == {"calendar_invite"}


def test_google_identity_requires_verified_email_claim() -> None:
    probe = GoogleWorkspaceProbe(
        QueueClient(
            [
                {
                    "sub": "SUB1",
                    "email": "owner@example.test",
                    "email_verified": False,
                }
            ]
        ),
        bearer_token=NOT_A_CREDENTIAL,
        retrieved_at=NOW,
    )

    with pytest.raises(LiveSpikeError, match="spike:google_email_unverified"):
        probe.probe_drive_file(file_id="F1")
