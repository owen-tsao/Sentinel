"""Read-only Slack audience metadata probe.

This spike reports current membership facts only. It does not grant permission
to post, and it is not a production enforcement adapter.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from sentinel.actions import CanonicalAction
from sentinel.platforms import AudienceSnapshot, ProviderContext
from sentinel.spikes.common import (
    LiveSpikeError,
    attach_evidence,
    make_provenance,
    utc_now,
)
from sentinel.spikes.http import JsonHttpClientProtocol
from sentinel.spikes.models import ProbeResult, build_probe_result


SLACK_API = "https://slack.com/api"
SLACK_ADAPTER_ID = "sentinel:slack:spike-v0"
SLACK_DOCUMENTATION = "https://docs.slack.dev/reference/objects/conversation-object"
MAX_PAGES = 50
# Two users.info passes plus up to MAX_PAGES membership pages per pass must fit
# within MAX_API_CALLS: 2 identity + 2 channel + 100 pages + 2 * 198 users = 500.
MAX_MEMBERS = 198
MAX_API_CALLS = 500
REQUIRED_FIELDS = {
    "auth.team_id",
    "auth.user_id",
    "team.id",
    "channel.id",
    "channel.context_team_id",
    "channel.is_private",
    "channel.is_archived",
    "channel.is_shared",
    "channel.is_ext_shared",
    "channel.is_org_shared",
    "channel.is_pending_ext_shared",
    "channel.num_members",
    "channel.updated",
    "channel.stable",
    "members.complete",
    "users.classified",
}


def probe_slack_channel(
    client: JsonHttpClientProtocol,
    *,
    bearer_token: str,
    channel_id: str,
    reply_broadcast: bool = False,
    retrieved_at: datetime | None = None,
) -> ProbeResult:
    """Resolve one visible Slack channel without sending a message."""

    if not channel_id.strip():
        raise ValueError("channel_id is required")
    now = retrieved_at or utc_now()
    budgeted_client = _BudgetedSlackClient(client)
    present: set[str] = set()
    limitations = [
        "Private channels invisible to this credential cannot be distinguished from nonexistent channels.",
        "Slack cannot guarantee that scheduled delivery remains authorized later.",
        "Observed channel membership does not authorize sending a message.",
    ]

    auth = _slack_call(budgeted_client, bearer_token, "auth.test")
    team_id = _required_text(auth, "team_id", "spike:slack_identity_incomplete")
    user_id = _required_text(auth, "user_id", "spike:slack_identity_incomplete")
    present.update({"auth.team_id", "auth.user_id"})

    team_response = _slack_call(budgeted_client, bearer_token, "team.info")
    team = _required_object(
        team_response,
        "team",
        "spike:slack_team_incomplete",
    )
    if _required_text(team, "id", "spike:slack_team_incomplete") != team_id:
        raise LiveSpikeError("spike:slack_workspace_mismatch")
    present.add("team.id")

    conversation_response = _slack_call(
        budgeted_client,
        bearer_token,
        "conversations.info",
        query={"channel": channel_id, "include_num_members": "true"},
    )
    channel = _required_object(
        conversation_response,
        "channel",
        "spike:slack_channel_incomplete",
    )
    if _required_text(channel, "id", "spike:slack_channel_incomplete") != channel_id:
        raise LiveSpikeError("spike:slack_channel_mismatch")
    present.add("channel.id")

    sharing_fields = {
        "context_team_id",
        "is_private",
        "is_archived",
        "is_shared",
        "is_ext_shared",
        "is_org_shared",
        "is_pending_ext_shared",
        "num_members",
    }
    boolean_sharing_fields = sharing_fields - {"context_team_id", "num_members"}
    for field in boolean_sharing_fields:
        if type(channel.get(field)) is bool:
            present.add(f"channel.{field}")
    if isinstance(channel.get("context_team_id"), str) and channel.get(
        "context_team_id"
    ):
        present.add("channel.context_team_id")
    declared_member_count = channel.get("num_members")
    if type(declared_member_count) is int and declared_member_count >= 0:
        present.add("channel.num_members")
    updated = channel.get("updated")
    if type(updated) is int and updated >= 0:
        present.add("channel.updated")
    sharing_complete = (
        all(type(channel.get(field)) is bool for field in boolean_sharing_fields)
        and isinstance(channel.get("context_team_id"), str)
        and bool(channel.get("context_team_id"))
        and type(declared_member_count) is int
        and declared_member_count >= 0
        and type(updated) is int
        and updated >= 0
    )
    if not sharing_complete:
        limitations.append("Slack omitted one or more audience or sharing fields.")
    if channel.get("context_team_id") != team_id:
        limitations.append("Channel context workspace differs from token workspace.")
        sharing_complete = False

    member_ids, pagination_complete = _slack_member_ids(
        budgeted_client,
        bearer_token,
        channel_id,
    )
    if pagination_complete:
        present.add("members.complete")
    if not pagination_complete:
        limitations.append("Slack membership pagination exceeded the probe limit.")

    (
        recipients,
        external,
        guests,
        initial_classifications,
        initial_users_complete,
    ) = _classify_slack_users(
        budgeted_client,
        bearer_token,
        member_ids,
        team_id=team_id,
    )

    final_conversation_response = _slack_call(
        budgeted_client,
        bearer_token,
        "conversations.info",
        query={"channel": channel_id, "include_num_members": "true"},
    )
    final_channel = _required_object(
        final_conversation_response,
        "channel",
        "spike:slack_channel_incomplete",
    )
    stable_fields = sharing_fields | {"updated"}
    state_stable = (
        final_channel.get("id") == channel_id
        and all(final_channel.get(field) == channel.get(field) for field in stable_fields)
    )
    final_member_ids, final_members_complete = _slack_member_ids(
        budgeted_client,
        bearer_token,
        channel_id,
    )
    membership_stable = (
        final_members_complete
        and set(final_member_ids) == set(member_ids)
        and len(final_member_ids) == len(member_ids)
    )
    (
        final_recipients,
        final_external,
        final_guests,
        final_classifications,
        final_users_complete,
    ) = _classify_slack_users(
        budgeted_client,
        bearer_token,
        final_member_ids,
        team_id=team_id,
    )
    recipients.update(final_recipients)
    external.update(final_external)
    guests.update(final_guests)
    classifications_stable = (
        initial_users_complete
        and final_users_complete
        and initial_classifications == final_classifications
    )
    users_complete = classifications_stable and membership_stable
    if users_complete:
        present.add("users.classified")
    elif not initial_users_complete or not final_users_complete:
        limitations.append(
            "One or more Slack users lacked classification fields during revalidation."
        )
    else:
        limitations.append(
            "Slack user classification changed during audience resolution."
        )
    state_stable = state_stable and membership_stable
    if state_stable:
        present.add("channel.stable")
    else:
        limitations.append("Slack channel metadata changed during audience resolution.")

    count_complete = (
        type(declared_member_count) is int
        and declared_member_count == len(recipients)
    )
    if not count_complete:
        limitations.append("Channel member count did not match enumerated members.")
    resolution_complete = (
        sharing_complete
        and pagination_complete
        and users_complete
        and count_complete
        and state_stable
    )
    canonical_target = f"slack:channel:{channel_id}"
    audience = AudienceSnapshot(
        resource_id=channel_id,
        canonical_target=canonical_target,
        kind="channel",
        tenant_id=team_id,
        recipient_ids=sorted(recipients),
        external_recipient_ids=sorted(external),
        guest_recipient_ids=sorted(guests),
        recipient_count=max(
            len(recipients),
            declared_member_count if type(declared_member_count) is int else 0,
        ),
        is_public=channel.get("is_private") is False,
        is_external_shared=bool(
            channel.get("is_ext_shared")
            or channel.get("is_pending_ext_shared")
            or external
        ),
        is_broadcast=reply_broadcast,
        allows_recipient_expansion=False,
        resolution_complete=resolution_complete,
        state_version=(
            str(channel["updated"]) if channel.get("updated") is not None else None
        ),
    )
    provider_context = ProviderContext(
        provider="slack",
        tenant_id=team_id,
        resource_account_id=team_id,
        credential_principal_id=user_id,
        actor_id=user_id,
        adapter_id=SLACK_ADAPTER_ID,
    )
    action = CanonicalAction(
        family="mcp",
        tool="slack",
        operation="external_communication",
        targets=[canonical_target],
        audience_targets=[canonical_target],
        effects={"external_send"},
        environment="dev",
    )
    provenance = make_provenance(
        source_endpoint=f"{SLACK_API}/auth.test + conversations.info/members + users.info",
        source_fields=present,
        documentation_url=SLACK_DOCUMENTATION,
        retrieved_at=now,
    )
    bound_action = attach_evidence(
        action,
        provider_context=provider_context,
        audiences=[audience],
        provenance=provenance,
        resolution_complete=resolution_complete,
    )
    return build_probe_result(
        provider="slack",
        action=bound_action,
        adapter_id=SLACK_ADAPTER_ID,
        api_call_count=budgeted_client.calls,
        required_fields=REQUIRED_FIELDS,
        present_fields=present,
        limitations=limitations,
    )


def _slack_member_ids(
    client: JsonHttpClientProtocol,
    token: str,
    channel_id: str,
) -> tuple[list[str], bool]:
    member_ids: list[str] = []
    cursor = ""
    for _ in range(MAX_PAGES):
        response = _slack_call(
            client,
            token,
            "conversations.members",
            query={
                "channel": channel_id,
                "limit": "200",
                **({"cursor": cursor} if cursor else {}),
            },
        )
        page_members = response.get("members")
        if not isinstance(page_members, list) or not all(
            isinstance(member, str) and member for member in page_members
        ):
            raise LiveSpikeError("spike:slack_members_incomplete")
        member_ids.extend(page_members)
        if len(member_ids) > MAX_MEMBERS:
            raise LiveSpikeError("spike:slack_member_limit_exceeded")
        metadata = response.get("response_metadata") or {}
        if not isinstance(metadata, dict):
            raise LiveSpikeError("spike:slack_pagination_invalid")
        cursor = str(metadata.get("next_cursor") or "").strip()
        if not cursor:
            return member_ids, True
    return member_ids, False


def _classify_slack_users(
    client: JsonHttpClientProtocol,
    token: str,
    member_ids: list[str],
    *,
    team_id: str,
) -> tuple[
    set[str],
    set[str],
    set[str],
    dict[str, tuple[object, ...]],
    bool,
]:
    recipients: set[str] = set()
    external: set[str] = set()
    guests: set[str] = set()
    classifications: dict[str, tuple[object, ...]] = {}
    complete = True
    required_fields = {
        "id",
        "team_id",
        "is_restricted",
        "is_ultra_restricted",
        "deleted",
        "is_bot",
    }
    for member_id in sorted(set(member_ids)):
        user_response = _slack_call(
            client,
            token,
            "users.info",
            query={"user": member_id},
        )
        user = _required_object(
            user_response,
            "user",
            "spike:slack_user_incomplete",
        )
        if user.get("id") != member_id:
            raise LiveSpikeError("spike:slack_user_mismatch")
        if (
            not required_fields.issubset(user)
            or not isinstance(user.get("team_id"), str)
            or not user.get("team_id")
            or any(
                type(user.get(field)) is not bool
                for field in required_fields - {"id", "team_id"}
            )
            or any(
                field in user and type(user.get(field)) is not bool
                for field in {"is_stranger", "is_external"}
            )
        ):
            complete = False
        classifications[member_id] = (
            user.get("team_id"),
            user.get("is_restricted"),
            user.get("is_ultra_restricted"),
            user.get("deleted"),
            user.get("is_bot"),
            user.get("is_stranger"),
            user.get("is_external"),
        )
        canonical_id = f"slack:user:{member_id}"
        recipients.add(canonical_id)
        if (
            user.get("team_id") != team_id
            or user.get("is_stranger") is True
            or user.get("is_external") is True
        ):
            external.add(canonical_id)
        if user.get("is_restricted") is True or user.get(
            "is_ultra_restricted"
        ) is True:
            guests.add(canonical_id)
    return recipients, external, guests, classifications, complete


class _BudgetedSlackClient:
    def __init__(self, client: JsonHttpClientProtocol) -> None:
        self._client = client
        self.calls = 0

    def get_json(
        self,
        url: str,
        *,
        bearer_token: str,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if self.calls >= MAX_API_CALLS:
            raise LiveSpikeError("spike:slack_call_budget_exceeded")
        self.calls += 1
        return self._client.get_json(
            url,
            bearer_token=bearer_token,
            query=query,
            headers=headers,
        )


def _slack_call(
    client: JsonHttpClientProtocol,
    token: str,
    method: str,
    *,
    query: dict[str, str | list[str]] | None = None,
) -> dict[str, Any]:
    response = client.get_json(
        f"{SLACK_API}/{method}",
        bearer_token=token,
        query=query,
    )
    if response.get("ok") is not True:
        error = re.sub(r"[^a-z0-9_]+", "_", str(response.get("error") or "api_error"))
        raise LiveSpikeError(f"spike:slack_{error[:100]}")
    return response


def _required_text(value: dict[str, Any], key: str, reason: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise LiveSpikeError(reason)
    return item


def _required_object(
    value: dict[str, Any],
    key: str,
    reason: str,
) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise LiveSpikeError(reason)
    return item
