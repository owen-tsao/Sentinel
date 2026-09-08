"""Read-only Google Workspace metadata probes for Drive, Gmail, and Calendar.

The probes report current provider state for policy experiments. That state is
evidence about an audience, not permission to send, invite, share, or enforce a
production action.
"""

from __future__ import annotations

from datetime import datetime
from email.utils import getaddresses
import re
from typing import Any
from urllib.parse import quote

from sentinel.actions import CanonicalAction
from sentinel.platforms import AudienceSnapshot, ProviderContext
from sentinel.platforms import EvidencePhase
from sentinel.spikes.common import (
    LiveSpikeError,
    attach_evidence,
    canonical_sha256,
    make_provenance,
    utc_now,
)
from sentinel.spikes.http import JsonHttpClientProtocol
from sentinel.spikes.models import ProbeResult, SpikeProvider, build_probe_result


GOOGLE_ADAPTER_ID = "sentinel:google-workspace:spike-v0"
OPENID_BASE = "https://openidconnect.googleapis.com/v1"
DIRECTORY_BASE = "https://admin.googleapis.com/admin/directory/v1"
DRIVE_BASE = "https://www.googleapis.com/drive/v3"
GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
CALENDAR_BASE = "https://www.googleapis.com/calendar/v3"
MAX_PAGES = 50
MAX_RECIPIENTS = 10_000
MAX_API_CALLS = 500
MAX_GROUP_DEPTH = 10
DRIVE_READ_ROLES = {"reader"}
DRIVE_WRITE_ROLES = {
    "commenter",
    "fileOrganizer",
    "organizer",
    "owner",
    "writer",
}

IDENTITY_REQUIRED = {
    "userinfo.sub",
    "userinfo.email",
    "userinfo.email_verified",
    "directory_user.id",
    "directory_user.customerId",
    "directory_user.primaryEmail",
}
DRIVE_REQUIRED = IDENTITY_REQUIRED | {
    "drive_about.user.permissionId",
    "drive_file.id",
    "drive_file.mimeType",
    "drive_file.version",
    "drive_file.stable",
    "drive_permissions.complete",
    "drive_permissions.classified",
}
GMAIL_REQUIRED = IDENTITY_REQUIRED | {
    "gmail_profile.emailAddress",
    "gmail_draft.id",
    "gmail_draft.message.id",
    "gmail_message.payload.headers",
    "gmail_draft.stable",
    "gmail_recipients.classified",
}
CALENDAR_REQUIRED = IDENTITY_REQUIRED | {
    "calendar.id",
    "event.id",
    "event.status",
    "event.attendees",
    "event.attendeesOmitted",
    "event.guestsCanInviteOthers",
    "event.visibility",
    "event.stateVersion",
    "event.stable",
    "calendar_recipients.classified",
}


class GoogleWorkspaceProbe:
    """Resolve current-state facts using caller-supplied, read-only OAuth access."""

    def __init__(
        self,
        client: JsonHttpClientProtocol,
        *,
        bearer_token: str,
        retrieved_at: datetime | None = None,
    ) -> None:
        if not bearer_token:
            raise LiveSpikeError("spike:missing_bearer_token")
        self._client = client
        self._token = bearer_token
        self._now = retrieved_at or utc_now()
        self._calls = 0
        self._identity_cache: tuple[str, str, str] | None = None
        self._recipient_cache: dict[str, _ResolvedRecipients] = {}
        self._group_snapshots: dict[str, str] = {}

    def probe_drive_file(
        self,
        *,
        file_id: str,
        resource_key: str | None = None,
    ) -> ProbeResult:
        self._begin_probe()
        start_calls = self._calls
        present: set[str] = set()
        limitations = [
            "Link audiences such as anyone or domain cannot be fully enumerated.",
            "Permission changes after this snapshot require a fresh preflight.",
            "Observed sharing state does not authorize changing Drive permissions.",
        ]
        subject_id, account_email, customer_id = self._identity(present)
        about = self._get(
            f"{DRIVE_BASE}/about",
            query={"fields": "user(permissionId,emailAddress)"},
        )
        about_user = about.get("user")
        if not isinstance(about_user, dict):
            raise LiveSpikeError("spike:google_drive_identity_incomplete")
        resource_account_id = _required_text(
            about_user,
            "permissionId",
            "spike:google_drive_identity_incomplete",
        )
        present.add("drive_about.user.permissionId")
        resource_key_entries = (
            [f"{file_id}/{resource_key}"] if resource_key else []
        )
        drive_headers = (
            {"X-Goog-Drive-Resource-Keys": ",".join(resource_key_entries)}
            if resource_key_entries
            else None
        )
        requested_file = self._get(
            f"{DRIVE_BASE}/files/{_path(file_id)}",
            query={
                "fields": (
                    "id,mimeType,version,driveId,resourceKey,"
                    "shortcutDetails(targetId,targetMimeType,targetResourceKey)"
                ),
                "supportsAllDrives": "true",
            },
            headers=drive_headers,
        )
        resolved_file = requested_file
        shortcut = requested_file.get("shortcutDetails")
        if isinstance(shortcut, dict) and shortcut.get("targetId"):
            limitations.append("A Drive shortcut was resolved to its target file.")
            target_id = str(shortcut["targetId"])
            target_resource_key = shortcut.get("targetResourceKey")
            if isinstance(target_resource_key, str) and target_resource_key:
                resource_key_entries.append(
                    f"{target_id}/{target_resource_key}"
                )
                drive_headers = {
                    "X-Goog-Drive-Resource-Keys": ",".join(resource_key_entries)
                }
            resolved_file = self._get(
                f"{DRIVE_BASE}/files/{_path(target_id)}",
                query={
                    "fields": "id,mimeType,version,driveId,resourceKey",
                    "supportsAllDrives": "true",
                },
                headers=drive_headers,
            )
        resolved_file_id = _required_text(
            resolved_file,
            "id",
            "spike:google_drive_file_incomplete",
        )
        present.update({"drive_file.id"})
        mime_type = resolved_file.get("mimeType")
        version = resolved_file.get("version")
        file_metadata_complete = True
        if isinstance(mime_type, str) and mime_type.strip():
            present.add("drive_file.mimeType")
        else:
            file_metadata_complete = False
            limitations.append("Drive omitted a valid file MIME type.")
        if isinstance(version, str) and version.strip():
            present.add("drive_file.version")
        else:
            file_metadata_complete = False
            limitations.append("Drive omitted a valid file revision.")

        permissions, pages_complete, _ = self._google_pages(
            f"{DRIVE_BASE}/files/{_path(resolved_file_id)}/permissions",
            items_key="permissions",
            page_token_key="pageToken",
            next_token_key="nextPageToken",
            query={
                "fields": (
                    "nextPageToken,permissions("
                    "id,type,role,emailAddress,domain,allowFileDiscovery,"
                    "deleted,permissionDetails(inherited,inheritedFrom))"
                ),
                "supportsAllDrives": "true",
                "pageSize": "100",
            },
            headers=drive_headers,
        )
        if pages_complete:
            present.add("drive_permissions.complete")
        else:
            limitations.append("Drive permission pagination exceeded the probe limit.")

        recipients: set[str] = set()
        external: set[str] = set()
        expansion = False
        public = False
        complete = pages_complete and file_metadata_complete
        classified = True
        share_effects: set[str] = set()
        shared_drive = bool(resolved_file.get("driveId"))
        for permission_item in permissions:
            permission_id = str(permission_item.get("id") or "").strip()
            permission_type = str(permission_item.get("type") or "").lower()
            role = permission_item.get("role")
            if (
                not permission_id
                or permission_type not in {"user", "group", "domain", "anyone"}
                or not isinstance(role, str)
                or not role.strip()
                or (
                    "deleted" in permission_item
                    and type(permission_item.get("deleted")) is not bool
                )
            ):
                classified = False
                complete = False
                continue
            normalized_role = role.strip()
            if normalized_role in DRIVE_READ_ROLES:
                share_effects.add("share_read")
            elif normalized_role in DRIVE_WRITE_ROLES:
                share_effects.add("share_write")
            else:
                # Unknown roles could carry mutation authority. Preserve the
                # conservative effect while marking the evidence incomplete.
                share_effects.add("share_write")
                classified = False
                complete = False
                limitations.append(
                    "A Drive permission used an unknown role and was treated as write-capable."
                )
            if permission_item.get("deleted") is True:
                classified = False
                complete = False
                continue
            permission_details = permission_item.get("permissionDetails")
            details_valid = (
                isinstance(permission_details, list)
                and bool(permission_details)
                and all(
                    isinstance(detail, dict)
                    and type(detail.get("inherited")) is bool
                    and (
                        detail.get("inherited") is False
                        or bool(detail.get("inheritedFrom"))
                    )
                    for detail in permission_details
                )
            )
            if shared_drive and not details_valid:
                complete = False
                classified = False
                limitations.append(
                    "A shared-drive permission lacked valid inheritance details."
                )
            canonical_permission = f"google:permission:{permission_id}"
            if permission_type in {"anyone", "domain"}:
                recipients.add(canonical_permission)
                expansion = True
                complete = False
                if permission_type == "anyone":
                    public = True
                else:
                    domain = str(permission_item.get("domain") or "").lower()
                    if not domain:
                        classified = False
                    elif not account_email.lower().endswith(f"@{domain}"):
                        external.add(canonical_permission)
                continue
            email_address = str(permission_item.get("emailAddress") or "").strip()
            if not email_address:
                classified = False
                complete = False
                recipients.add(canonical_permission)
                continue
            resolved = self._resolve_email(
                email_address,
                customer_id=customer_id,
                seen_groups=set(),
                depth=0,
            )
            recipients.update(resolved.recipient_ids)
            external.update(resolved.external_ids)
            expansion = expansion or resolved.expands
            complete = complete and resolved.complete
            limitations.extend(resolved.limitations)
        if classified:
            present.add("drive_permissions.classified")
        if not self._groups_stable():
            complete = False
            limitations.append(
                "A Google group membership changed during Drive audience resolution."
            )

        final_file = self._get(
            f"{DRIVE_BASE}/files/{_path(resolved_file_id)}",
            query={
                "fields": "id,version",
                "supportsAllDrives": "true",
            },
            headers=drive_headers,
        )
        file_stable = (
            final_file.get("id") == resolved_file_id
            and isinstance(final_file.get("version"), str)
            and final_file.get("version") == version
        )
        if file_stable:
            present.add("drive_file.stable")
        else:
            complete = False
            limitations.append("Drive file revision changed during permission resolution.")

        canonical_target = f"drive:file:{resolved_file_id}"
        audience = AudienceSnapshot(
            resource_id=resolved_file_id,
            canonical_target=canonical_target,
            kind="file",
            tenant_id=customer_id,
            recipient_ids=sorted(recipients),
            external_recipient_ids=sorted(external),
            guest_recipient_ids=[],
            recipient_count=len(recipients),
            is_public=public,
            is_external_shared=bool(external) or public,
            is_broadcast=False,
            allows_recipient_expansion=expansion,
            resolution_complete=complete,
            state_version=version if isinstance(version, str) and version else None,
        )
        action = self._action_with_evidence(
            provider="google_drive",
            operation="write",
            effects=share_effects,
            tool="google_drive",
            target=canonical_target,
            audience=audience,
            subject_id=subject_id,
            resource_account_id=resource_account_id,
            source_fields=present,
            documentation_url="https://developers.google.com/drive/api/reference/rest/v3/permissions",
            resolution_complete=complete,
            phase="current_state",
        )
        return build_probe_result(
            provider="google_drive",
            action=action,
            adapter_id=GOOGLE_ADAPTER_ID,
            api_call_count=self._calls - start_calls,
            required_fields=DRIVE_REQUIRED,
            present_fields=present,
            limitations=_unique(limitations),
        )

    def probe_gmail_draft(self, *, draft_id: str) -> ProbeResult:
        self._begin_probe()
        start_calls = self._calls
        present: set[str] = set()
        limitations = [
            "The spike inspects an existing draft; it does not send or modify it.",
            "A group that cannot be expanded makes the result incomplete.",
        ]
        subject_id, account_email, customer_id = self._identity(present)
        profile = self._get(f"{GMAIL_BASE}/users/me/profile")
        profile_email = _required_text(
            profile,
            "emailAddress",
            "spike:gmail_profile_incomplete",
        )
        if profile_email.lower() != account_email.lower():
            raise LiveSpikeError("spike:gmail_account_mismatch")
        present.add("gmail_profile.emailAddress")
        draft = self._get(
            f"{GMAIL_BASE}/users/me/drafts/{_path(draft_id)}",
            query={"format": "minimal"},
        )
        if _required_text(draft, "id", "spike:gmail_draft_incomplete") != draft_id:
            raise LiveSpikeError("spike:gmail_draft_mismatch")
        present.add("gmail_draft.id")
        message = draft.get("message")
        if not isinstance(message, dict):
            raise LiveSpikeError("spike:gmail_message_incomplete")
        message_id = _required_text(
            message,
            "id",
            "spike:gmail_message_incomplete",
        )
        message_metadata = self._get(
            f"{GMAIL_BASE}/users/me/messages/{_path(message_id)}",
            query={
                "format": "metadata",
                "metadataHeaders": ["To", "Cc", "Bcc"],
                "fields": "id,payload(headers(name,value))",
            },
        )
        if message_metadata.get("id") != message_id:
            raise LiveSpikeError("spike:gmail_message_mismatch")
        payload = message_metadata.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("headers"), list):
            raise LiveSpikeError("spike:gmail_headers_incomplete")
        header_values: list[str] = []
        headers_valid = True
        for header in payload["headers"]:
            if not isinstance(header, dict):
                headers_valid = False
                continue
            name = header.get("name")
            value = header.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                headers_valid = False
                continue
            if name.lower() in {"to", "cc", "bcc"}:
                header_values.append(value)
        addresses, address_headers_valid = _strict_addresses(header_values)
        headers_valid = headers_valid and address_headers_valid
        if not headers_valid:
            addresses = set()
        present.update(
            {
                "gmail_draft.message.id",
                "gmail_message.payload.headers",
            }
        )
        recipients, external, complete, expansion, recipient_limitations = (
            self._resolve_addresses(addresses, customer_id=customer_id)
        )
        limitations.extend(recipient_limitations)
        if not self._groups_stable():
            complete = False
            limitations.append(
                "A Google group membership changed during Gmail audience resolution."
            )
        if addresses and headers_valid:
            present.add("gmail_recipients.classified")
        else:
            complete = False
            limitations.append(
                "The draft has missing or malformed To, Cc, or Bcc recipients."
            )
        final_draft = self._get(
            f"{GMAIL_BASE}/users/me/drafts/{_path(draft_id)}",
            query={"format": "minimal"},
        )
        final_message = final_draft.get("message")
        draft_stable = (
            final_draft.get("id") == draft_id
            and isinstance(final_message, dict)
            and final_message.get("id") == message_id
        )
        if draft_stable:
            present.add("gmail_draft.stable")
        else:
            complete = False
            limitations.append("Gmail draft changed during recipient resolution.")
        target = f"gmail:draft:{draft_id}"
        audience = AudienceSnapshot(
            resource_id=draft_id,
            canonical_target=target,
            kind="email",
            tenant_id=customer_id,
            recipient_ids=sorted(recipients),
            external_recipient_ids=sorted(external),
            guest_recipient_ids=[],
            recipient_count=len(recipients),
            is_public=False,
            is_external_shared=bool(external),
            is_broadcast=False,
            allows_recipient_expansion=expansion,
            resolution_complete=complete,
            state_version=message_id,
        )
        action = self._action_with_evidence(
            provider="gmail",
            operation="external_communication",
            effects={"external_send"},
            tool="gmail",
            target=target,
            audience=audience,
            subject_id=subject_id,
            resource_account_id=account_email,
            source_fields=present,
            documentation_url="https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.drafts/get",
            resolution_complete=complete,
        )
        return build_probe_result(
            provider="gmail",
            action=action,
            adapter_id=GOOGLE_ADAPTER_ID,
            api_call_count=self._calls - start_calls,
            required_fields=GMAIL_REQUIRED,
            present_fields=present,
            limitations=_unique(limitations),
        )

    def probe_calendar_event(
        self,
        *,
        calendar_id: str,
        event_id: str,
    ) -> ProbeResult:
        self._begin_probe()
        start_calls = self._calls
        present: set[str] = set()
        limitations = [
            "The spike inspects an existing event; it does not update or invite attendees.",
            "Recurring events require an explicit occurrence horizon before enforcement.",
        ]
        subject_id, account_email, customer_id = self._identity(present)
        calendar = self._get(
            f"{CALENDAR_BASE}/users/me/calendarList/{_path(calendar_id)}",
            query={"fields": "id"},
        )
        resolved_calendar_id = _required_text(
            calendar,
            "id",
            "spike:calendar_identity_incomplete",
        )
        present.add("calendar.id")
        event = self._get(
            f"{CALENDAR_BASE}/calendars/{_path(resolved_calendar_id)}/events/{_path(event_id)}",
            query={
                "maxAttendees": "250",
                "fields": (
                    "id,status,etag,updated,visibility,attendeesOmitted,"
                    "attendees(email,resource,additionalGuests),recurrence,"
                    "recurringEventId,attachments(fileId),guestsCanInviteOthers"
                ),
            },
        )
        if _required_text(event, "id", "spike:calendar_event_incomplete") != event_id:
            raise LiveSpikeError("spike:calendar_event_mismatch")
        present.add("event.id")
        status_valid = event.get("status") in {"confirmed", "tentative", "cancelled"}
        if status_valid:
            present.add("event.status")
        attendees_omitted = event.get("attendeesOmitted")
        guests_can_invite = event.get("guestsCanInviteOthers")
        visibility = event.get("visibility")
        attendees_omitted_valid = type(attendees_omitted) is bool
        guests_can_invite_valid = type(guests_can_invite) is bool
        visibility_valid = visibility in {"private", "public", "confidential"}
        if attendees_omitted_valid:
            present.add("event.attendeesOmitted")
        if guests_can_invite_valid:
            present.add("event.guestsCanInviteOthers")
        if visibility_valid:
            present.add("event.visibility")
        attendees = event.get("attendees")
        if not isinstance(attendees, list):
            raise LiveSpikeError("spike:calendar_attendees_incomplete")
        present.add("event.attendees")
        addresses: set[str] = set()
        resource_recipients: set[str] = set()
        attendees_valid = True
        additional_guests = 0
        for attendee in attendees:
            if not isinstance(attendee, dict):
                attendees_valid = False
                continue
            attendee_email = attendee.get("email")
            resource = attendee.get("resource", False)
            additional = attendee.get("additionalGuests", 0)
            if (
                not isinstance(attendee_email, str)
                or not attendee_email.strip()
                or type(resource) is not bool
                or type(additional) is not int
                or additional < 0
            ):
                attendees_valid = False
                continue
            if resource:
                resource_recipients.add(
                    f"google:calendar-resource:{attendee_email.strip().lower()}"
                )
                attendees_valid = False
            else:
                addresses.add(attendee_email.strip().lower())
            additional_guests += additional
        recipients, external, complete, expansion, recipient_limitations = (
            self._resolve_addresses(addresses, customer_id=customer_id)
        )
        recipients.update(resource_recipients)
        limitations.extend(recipient_limitations)
        if not self._groups_stable():
            complete = False
            limitations.append(
                "A Google group membership changed during Calendar audience resolution."
            )
        control_fields_valid = (
            status_valid
            and attendees_omitted_valid
            and guests_can_invite_valid
            and visibility_valid
        )
        complete = complete and attendees_valid and control_fields_valid
        if not attendees_valid:
            limitations.append(
                "One or more Calendar attendees were malformed or a resource audience."
            )
        if not control_fields_valid:
            limitations.append("Calendar omitted or malformed audience control fields.")
        if additional_guests:
            complete = False
            expansion = True
            limitations.append("Calendar reports unnamed additional guests.")
        if attendees_omitted is True:
            complete = False
            limitations.append("Calendar omitted attendees from the response.")
        if event.get("recurrence") or event.get("recurringEventId"):
            complete = False
            expansion = True
            limitations.append("Recurring event scope was not expanded in this spike.")
        attachments_value = event.get("attachments", [])
        attachments_valid = isinstance(attachments_value, list) and all(
            isinstance(attachment, dict)
            and isinstance(attachment.get("fileId"), str)
            and bool(attachment.get("fileId"))
            for attachment in attachments_value
        )
        attachments = attachments_value if isinstance(attachments_value, list) else []
        if not attachments_valid:
            complete = False
            limitations.append("Calendar attachment metadata was malformed.")
        if attachments:
            complete = False
            limitations.append(
                "Event attachments require a separate Drive permission preflight."
            )
        state_version = event.get("etag") or event.get("updated")
        if isinstance(state_version, str) and state_version:
            present.add("event.stateVersion")
        else:
            complete = False
            state_version = None
            limitations.append("Calendar event lacked a stable revision identifier.")
        if attendees_valid and control_fields_valid:
            present.add("calendar_recipients.classified")
        final_event = self._get(
            f"{CALENDAR_BASE}/calendars/{_path(resolved_calendar_id)}/events/{_path(event_id)}",
            query={"fields": "id,etag,updated"},
        )
        final_state_version = final_event.get("etag") or final_event.get("updated")
        event_stable = (
            final_event.get("id") == event_id
            and state_version is not None
            and final_state_version == state_version
        )
        if event_stable:
            present.add("event.stable")
        else:
            complete = False
            limitations.append("Calendar event changed during attendee resolution.")
        target = f"calendar:event:{resolved_calendar_id}:{event_id}"
        audience = AudienceSnapshot(
            resource_id=f"{resolved_calendar_id}:{event_id}",
            canonical_target=target,
            kind="calendar_event",
            tenant_id=customer_id,
            recipient_ids=sorted(recipients),
            external_recipient_ids=sorted(external),
            guest_recipient_ids=[],
            recipient_count=len(recipients) + additional_guests,
            is_public=visibility == "public",
            is_external_shared=bool(external),
            is_broadcast=False,
            allows_recipient_expansion=expansion
            or guests_can_invite is True,
            resolution_complete=complete,
            state_version=state_version,
        )
        action = self._action_with_evidence(
            provider="google_calendar",
            operation="external_communication",
            effects={"calendar_invite"},
            tool="google_calendar",
            target=target,
            audience=audience,
            subject_id=subject_id,
            resource_account_id=account_email,
            source_fields=present,
            documentation_url="https://developers.google.com/calendar/api/v3/reference/events/get",
            resolution_complete=complete,
        )
        return build_probe_result(
            provider="google_calendar",
            action=action,
            adapter_id=GOOGLE_ADAPTER_ID,
            api_call_count=self._calls - start_calls,
            required_fields=CALENDAR_REQUIRED,
            present_fields=present,
            limitations=_unique(limitations),
        )

    def _identity(self, present: set[str]) -> tuple[str, str, str]:
        if self._identity_cache is not None:
            present.update(IDENTITY_REQUIRED)
            return self._identity_cache
        userinfo = self._get(f"{OPENID_BASE}/userinfo")
        subject_id = _required_text(
            userinfo,
            "sub",
            "spike:google_identity_incomplete",
        )
        email_address = _required_text(
            userinfo,
            "email",
            "spike:google_identity_incomplete",
        ).lower()
        if userinfo.get("email_verified") is not True:
            raise LiveSpikeError("spike:google_email_unverified")
        present.update(
            {"userinfo.sub", "userinfo.email", "userinfo.email_verified"}
        )
        directory_user = self._get(
            f"{DIRECTORY_BASE}/users/{_path(email_address)}",
            query={"projection": "basic"},
        )
        directory_id = _required_text(
            directory_user,
            "id",
            "spike:google_directory_identity_incomplete",
        )
        customer_id = _required_text(
            directory_user,
            "customerId",
            "spike:google_directory_identity_incomplete",
        )
        primary_email = _required_text(
            directory_user,
            "primaryEmail",
            "spike:google_directory_identity_incomplete",
        ).lower()
        if primary_email != email_address:
            raise LiveSpikeError("spike:google_identity_mismatch")
        present.update(
            {
                "directory_user.id",
                "directory_user.customerId",
                "directory_user.primaryEmail",
            }
        )
        self._identity_cache = (subject_id, primary_email, customer_id)
        del directory_id
        return self._identity_cache

    def _resolve_addresses(
        self,
        addresses: set[str],
        *,
        customer_id: str,
    ) -> tuple[set[str], set[str], bool, bool, list[str]]:
        recipients: set[str] = set()
        external: set[str] = set()
        complete = True
        expansion = False
        limitations: list[str] = []
        for address in sorted(addresses):
            resolved = self._resolve_email(
                address,
                customer_id=customer_id,
                seen_groups=set(),
                depth=0,
            )
            recipients.update(resolved.recipient_ids)
            external.update(resolved.external_ids)
            complete = complete and resolved.complete
            expansion = expansion or resolved.expands
            limitations.extend(resolved.limitations)
            if len(recipients) > MAX_RECIPIENTS:
                raise LiveSpikeError("spike:google_recipient_limit_exceeded")
        return recipients, external, complete, expansion, limitations

    def _begin_probe(self) -> None:
        self._recipient_cache.clear()
        self._group_snapshots.clear()

    def _groups_stable(self) -> bool:
        for group_key, expected_revision in list(self._group_snapshots.items()):
            _, complete, actual_revision = self._google_pages(
                f"{DIRECTORY_BASE}/groups/{_path(group_key)}/members",
                items_key="members",
                page_token_key="pageToken",
                next_token_key="nextPageToken",
                query={"maxResults": "200"},
            )
            if not complete or actual_revision != expected_revision:
                return False
        return True

    def _resolve_email(
        self,
        email_address: str,
        *,
        customer_id: str,
        seen_groups: set[str],
        depth: int,
    ) -> "_ResolvedRecipients":
        normalized_email = email_address.strip().lower()
        cache_key = f"{customer_id}:{normalized_email}"
        if not seen_groups and cache_key in self._recipient_cache:
            return self._recipient_cache[cache_key]
        if depth >= MAX_GROUP_DEPTH:
            return _ResolvedRecipients(
                recipient_ids={f"google:unexpanded:{normalized_email}"},
                external_ids=set(),
                complete=False,
                expands=True,
                limitations=["Google group nesting exceeded the probe depth limit."],
            )
        user = self._try_get(
            f"{DIRECTORY_BASE}/users/{_path(normalized_email)}",
            query={"projection": "basic"},
        )
        if user is not None:
            user_id = _required_text(
                user,
                "id",
                "spike:google_directory_user_incomplete",
            )
            user_customer = _required_text(
                user,
                "customerId",
                "spike:google_directory_user_incomplete",
            )
            principal = f"google:user:{user_id}"
            result = _ResolvedRecipients(
                recipient_ids={principal},
                external_ids={principal} if user_customer != customer_id else set(),
                complete=True,
                expands=False,
                limitations=[],
            )
            self._recipient_cache[cache_key] = result
            return result
        group = self._try_get(
            f"{DIRECTORY_BASE}/groups/{_path(normalized_email)}"
        )
        if group is None:
            principal = f"google:external-email:{normalized_email}"
            result = _ResolvedRecipients(
                recipient_ids={principal},
                external_ids={principal},
                complete=True,
                expands=False,
                limitations=[],
            )
            self._recipient_cache[cache_key] = result
            return result
        group_key = _required_text(
            group,
            "id",
            "spike:google_group_incomplete",
        )
        if group_key in seen_groups:
            return _ResolvedRecipients(
                recipient_ids={f"google:group:{group_key}"},
                external_ids=set(),
                complete=False,
                expands=True,
                limitations=["A nested Google group cycle prevented full expansion."],
            )
        next_seen = {*seen_groups, group_key}
        members, pages_complete, membership_revision = self._google_pages(
            f"{DIRECTORY_BASE}/groups/{_path(group_key)}/members",
            items_key="members",
            page_token_key="pageToken",
            next_token_key="nextPageToken",
            query={"maxResults": "200"},
        )
        recipients: set[str] = set()
        external: set[str] = set()
        complete = pages_complete
        limitations: list[str] = []
        for member in members:
            member_type = str(member.get("type") or "").upper()
            member_email = str(member.get("email") or "").strip().lower()
            if member_type in {"USER", "GROUP"} and member_email:
                nested = self._resolve_email(
                    member_email,
                    customer_id=customer_id,
                    seen_groups=next_seen,
                    depth=depth + 1,
                )
                recipients.update(nested.recipient_ids)
                external.update(nested.external_ids)
                complete = complete and nested.complete
                limitations.extend(nested.limitations)
            else:
                principal = f"google:group-member:{member.get('id') or 'unknown'}"
                recipients.add(principal)
                complete = False
                limitations.append(
                    "A Google group member could not be classified or expanded."
                )
        result = _ResolvedRecipients(
            recipient_ids=recipients,
            external_ids=external,
            complete=complete,
            expands=True,
            limitations=limitations,
        )
        if not seen_groups:
            self._recipient_cache[cache_key] = result
        self._group_snapshots[group_key] = membership_revision
        return result

    def _google_pages(
        self,
        url: str,
        *,
        items_key: str,
        page_token_key: str,
        next_token_key: str,
        query: dict[str, str | list[str]],
        headers: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], bool, str]:
        items: list[dict[str, Any]] = []
        page_revisions: list[dict[str, Any]] = []
        token = ""
        for _ in range(MAX_PAGES):
            response = self._get(
                url,
                query={
                    **query,
                    **({page_token_key: token} if token else {}),
                },
                headers=headers,
            )
            page_items = response.get(items_key) or []
            if not isinstance(page_items, list) or not all(
                isinstance(item, dict) for item in page_items
            ):
                raise LiveSpikeError("spike:google_pagination_invalid")
            items.extend(page_items)
            page_revisions.append(
                {
                    "etag": response.get("etag"),
                    "items": page_items,
                }
            )
            if len(items) > MAX_RECIPIENTS:
                raise LiveSpikeError("spike:google_recipient_limit_exceeded")
            token = str(response.get(next_token_key) or "").strip()
            if not token:
                return items, True, canonical_sha256(page_revisions)
        return items, False, canonical_sha256(page_revisions)

    def _action_with_evidence(
        self,
        *,
        provider: SpikeProvider,
        operation: str,
        effects: set[str],
        tool: str,
        target: str,
        audience: AudienceSnapshot,
        subject_id: str,
        resource_account_id: str,
        source_fields: set[str],
        documentation_url: str,
        resolution_complete: bool,
        phase: EvidencePhase = "projected_effect",
    ) -> CanonicalAction:
        context = ProviderContext(
            provider=provider,
            tenant_id=audience.tenant_id,
            resource_account_id=resource_account_id,
            credential_principal_id=subject_id,
            actor_id=subject_id,
            adapter_id=GOOGLE_ADAPTER_ID,
        )
        action = CanonicalAction(
            family="mcp",
            tool=tool,
            operation=operation,
            targets=[target],
            audience_targets=[target],
            effects=effects,
            environment="dev",
        )
        provenance = make_provenance(
            source_endpoint=f"{OPENID_BASE} + {DIRECTORY_BASE} + provider resource APIs",
            source_fields=source_fields,
            documentation_url=documentation_url,
            retrieved_at=self._now,
        )
        return attach_evidence(
            action,
            provider_context=context,
            audiences=[audience],
            provenance=provenance,
            resolution_complete=resolution_complete,
            phase=phase,
        )

    def _get(
        self,
        url: str,
        *,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if self._calls >= MAX_API_CALLS:
            raise LiveSpikeError("spike:google_call_budget_exceeded")
        self._calls += 1
        return self._client.get_json(
            url,
            bearer_token=self._token,
            query=query,
            headers=headers,
        )

    def _try_get(
        self,
        url: str,
        *,
        query: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any] | None:
        try:
            return self._get(url, query=query)
        except LiveSpikeError as exc:
            if exc.reason_code == "spike:http_status_404":
                return None
            raise


class _ResolvedRecipients:
    def __init__(
        self,
        *,
        recipient_ids: set[str],
        external_ids: set[str],
        complete: bool,
        expands: bool,
        limitations: list[str],
    ) -> None:
        self.recipient_ids = recipient_ids
        self.external_ids = external_ids
        self.complete = complete
        self.expands = expands
        self.limitations = limitations


def _path(value: str) -> str:
    if not value.strip():
        raise ValueError("provider resource ID is required")
    return quote(value, safe="")


def _required_text(value: dict[str, Any], key: str, reason: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise LiveSpikeError(reason)
    return item


def _strict_addresses(header_values: list[str]) -> tuple[set[str], bool]:
    if not header_values:
        return set(), False
    parsed = [
        address.strip().lower()
        for _, address in getaddresses(header_values)
        if address.strip()
    ]
    valid = (
        sum(value.count("@") for value in header_values) == len(parsed)
        and all(
            re.fullmatch(r"[^@\s,<>]+@[^@\s,<>]+", address) is not None
            for address in parsed
        )
    )
    return set(parsed), valid


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
