"""Test-only stand-in for the protected local approval UI."""

from __future__ import annotations

from sentinel.approval import InMemoryApprovalService


class ApproverHarness:
    def __init__(self, service: InMemoryApprovalService) -> None:
        self._service = service

    def approve(
        self,
        approval_id: str,
        *,
        approver_id: str = "test-human",
        approver_channel: str = "isolated-test-harness",
    ) -> str:
        token = self._service.issue(
            approval_id,
            approver_id=approver_id,
            approver_channel=approver_channel,
        )
        if token is None:
            raise AssertionError(f"approval request is unavailable: {approval_id}")
        return token.token
