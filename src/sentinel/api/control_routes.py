"""Protected HTTP routes for the Phase 0 browser-control spike."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Callable, Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request, Response

from sentinel.api.control_schemas import (
    ActiveAuthorityResponse,
    ApprovalActionResponse,
    ApprovalDecisionRequest,
    ApprovalListResponse,
    AuditListResponse,
    ContractActivationRequest,
    ContractActivationResponse,
    ContractDraftRequest,
    ContractDraftResponse,
    ControlRuntimeStatus,
    ControlStatusResponse,
    ControlWorkspaceResponse,
    IntegrationStatusResponse,
    LogoutResponse,
    PairExchangeRequest,
    PairExchangeResponse,
    PendingApprovalResponse,
    PendingProposalResponse,
    ProposalAdjustResponse,
    ProposalConfirmRequest,
    ProposalConfirmResponse,
    ProposalDismissResponse,
    TargetSuggestionsResponse,
)
from sentinel.api.schemas import EvaluateResponse
from sentinel.approval import PendingApproval
from sentinel.control.approvals import (
    ApprovalCoordinatorError,
    ApprovalExecutionEnvelope,
    InMemoryApprovalCoordinator,
)
from sentinel.control.config import ControlConfig
from sentinel.control.pairing import PairingError, PairingService
from sentinel.control.workspace import SupervisionBinding


def build_control_router(
    *,
    config: ControlConfig,
    pairing: PairingService,
    binding: SupervisionBinding,
    approvals: InMemoryApprovalCoordinator,
    retry_approval: Callable[[ApprovalExecutionEnvelope, str], EvaluateResponse],
    denial_observer: Callable[[PendingApproval], None],
    draft_contract: Callable[[ContractDraftRequest], ContractDraftResponse],
    activate_contract: Callable[
        [ContractActivationRequest],
        ContractActivationResponse,
    ],
    active_authority: Callable[[], ActiveAuthorityResponse],
    approval_is_current: Callable[[ApprovalExecutionEnvelope], bool],
    query_audit: Callable[..., AuditListResponse],
    runtime_status: Callable[[], ControlRuntimeStatus],
    integration_status: Callable[[], Optional[IntegrationStatusResponse]] = lambda: None,
    pending_proposal: Callable[[], PendingProposalResponse] = PendingProposalResponse,
    confirm_proposal: Optional[
        Callable[[str, ProposalConfirmRequest], ProposalConfirmResponse]
    ] = None,
    dismiss_proposal: Optional[Callable[[str], ProposalDismissResponse]] = None,
    adjust_proposal: Optional[Callable[[str], ProposalAdjustResponse]] = None,
    target_suggestions: Optional[Callable[[], TargetSuggestionsResponse]] = None,
) -> APIRouter:
    router = APIRouter(prefix="/control", tags=["control"])

    @router.post("/pair/exchange", response_model=PairExchangeResponse)
    def exchange_pairing(
        payload: PairExchangeRequest,
        response: Response,
    ) -> PairExchangeResponse:
        try:
            issued = pairing.exchange(payload.capability)
        except PairingError as exc:
            raise HTTPException(
                status_code=401,
                detail="Pairing capability is invalid or expired.",
            ) from exc
        response.set_cookie(
            key=config.session_cookie_name,
            value=issued.token,
            expires=issued.absolute_expires_at,
            httponly=True,
            secure=False,
            samesite="strict",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return PairExchangeResponse(
            absolute_expires_at=issued.absolute_expires_at
        )

    @router.get("/status", response_model=ControlStatusResponse)
    def status(request: Request, response: Response) -> ControlStatusResponse:
        session = _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        integration = integration_status()
        connected = integration is not None and integration.agent.status == "connected"
        return ControlStatusResponse(
            supervision_session_id=binding.session_id,
            session_absolute_expires_at=session.absolute_expires_at,
            workspace=ControlWorkspaceResponse(
                name=binding.workspace.display_name,
                canonical_path=str(binding.workspace.path),
                identity_sha256=binding.workspace.identity_sha256,
            ),
            runtime=runtime_status(),
            mandatory_agent_connected=connected,
            connection_message=_connection_message(integration),
            integration=integration,
        )

    @router.post("/contracts/draft", response_model=ContractDraftResponse)
    def draft(
        payload: ContractDraftRequest,
        request: Request,
        response: Response,
    ) -> ContractDraftResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        return draft_contract(payload)

    @router.post(
        "/contracts/activate",
        response_model=ContractActivationResponse,
    )
    def activate(
        payload: ContractActivationRequest,
        request: Request,
        response: Response,
    ) -> ContractActivationResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        return activate_contract(payload)

    @router.get("/authority/active", response_model=ActiveAuthorityResponse)
    def get_active_authority(
        request: Request,
        response: Response,
    ) -> ActiveAuthorityResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        return active_authority()

    @router.get("/targets", response_model=TargetSuggestionsResponse)
    def get_target_suggestions(
        request: Request,
        response: Response,
    ) -> TargetSuggestionsResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        if target_suggestions is None:
            return TargetSuggestionsResponse(workspace_root="/workspace", paths=[])
        return target_suggestions()

    @router.get("/proposals/pending", response_model=PendingProposalResponse)
    def get_pending_proposal(
        request: Request,
        response: Response,
    ) -> PendingProposalResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        return pending_proposal()

    @router.post(
        "/proposals/{draft_id}/confirm",
        response_model=ProposalConfirmResponse,
    )
    def confirm_task_proposal(
        draft_id: str,
        request: Request,
        response: Response,
        payload: Optional[ProposalConfirmRequest] = None,
    ) -> ProposalConfirmResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        if confirm_proposal is None:
            raise HTTPException(status_code=404, detail="Task proposals are not enabled.")
        return confirm_proposal(draft_id, payload or ProposalConfirmRequest())

    @router.post(
        "/proposals/{draft_id}/dismiss",
        response_model=ProposalDismissResponse,
    )
    def dismiss_task_proposal(
        draft_id: str,
        request: Request,
        response: Response,
    ) -> ProposalDismissResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        if dismiss_proposal is None:
            raise HTTPException(status_code=404, detail="Task proposals are not enabled.")
        return dismiss_proposal(draft_id)

    @router.post(
        "/proposals/{draft_id}/adjust",
        response_model=ProposalAdjustResponse,
    )
    def adjust_task_proposal(
        draft_id: str,
        request: Request,
        response: Response,
    ) -> ProposalAdjustResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        if adjust_proposal is None:
            raise HTTPException(status_code=404, detail="Task proposals are not enabled.")
        return adjust_proposal(draft_id)

    @router.get("/approvals", response_model=ApprovalListResponse)
    def list_approvals(
        request: Request,
        response: Response,
    ) -> ApprovalListResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        current = []
        for envelope in approvals.list_pending():
            if approval_is_current(envelope):
                current.append(envelope)
            else:
                approvals.invalidate(envelope.approval_id)
        return ApprovalListResponse(
            approvals=[
                _pending_approval_response(envelope)
                for envelope in current
            ]
        )

    @router.post(
        "/approvals/{approval_id}/approve",
        response_model=ApprovalActionResponse,
    )
    def approve(
        approval_id: str,
        request: Request,
        response: Response,
        payload: Optional[ApprovalDecisionRequest] = None,
    ) -> ApprovalActionResponse:
        _authenticate(request, config, pairing)
        envelope = approvals.get_pending(approval_id)
        if envelope is None or not approval_is_current(envelope):
            if envelope is not None:
                approvals.invalidate(approval_id)
            raise HTTPException(
                status_code=409,
                detail="Approval request is unavailable.",
            )
        requires_typed_target = (
            envelope.operation == "delete"
            or envelope.binding.environment == "production"
        )
        if requires_typed_target and (
            payload is None
            or len(envelope.targets) != 1
            or payload.typed_target != envelope.targets[0]
        ):
            raise HTTPException(
                status_code=409,
                detail="Exact target confirmation is required.",
            )
        try:
            result = approvals.approve(
                approval_id,
                retry=retry_approval,
                approver_id="local-human",
                approver_channel="protected_local_ui",
            )
        except ApprovalCoordinatorError as exc:
            raise HTTPException(
                status_code=409,
                detail="Approval request is unavailable.",
            ) from exc
        response.headers["Cache-Control"] = "no-store"
        return ApprovalActionResponse(
            approval_id=approval_id,
            status="approved",
            retry=result.retry_result,
        )

    @router.post(
        "/approvals/{approval_id}/deny",
        response_model=ApprovalActionResponse,
    )
    def deny(
        approval_id: str,
        request: Request,
        response: Response,
    ) -> ApprovalActionResponse:
        _authenticate(request, config, pairing)
        envelope = approvals.get_pending(approval_id)
        if envelope is None or not approval_is_current(envelope):
            if envelope is not None:
                approvals.invalidate(approval_id)
            raise HTTPException(
                status_code=409,
                detail="Approval request is unavailable.",
            )
        try:
            approvals.deny(
                approval_id,
                denial_observer=denial_observer,
            )
        except ApprovalCoordinatorError as exc:
            raise HTTPException(
                status_code=409,
                detail="Approval request is unavailable.",
            ) from exc
        response.headers["Cache-Control"] = "no-store"
        return ApprovalActionResponse(
            approval_id=approval_id,
            status="denied",
        )

    @router.get("/audit", response_model=AuditListResponse)
    def audit(
        request: Request,
        response: Response,
        task_id: Optional[str] = Query(default=None, min_length=1, max_length=500),
        event_type: Optional[str] = Query(
            default=None,
            min_length=1,
            max_length=200,
        ),
        verdict: Optional[
            Literal["allow", "warn", "confirm_required", "block"]
        ] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> AuditListResponse:
        _authenticate(request, config, pairing)
        response.headers["Cache-Control"] = "no-store"
        return query_audit(
            task_id=task_id,
            event_type=event_type,
            verdict=verdict,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )

    @router.post("/logout", response_model=LogoutResponse)
    def logout(request: Request, response: Response) -> LogoutResponse:
        raw_session = request.cookies.get(config.session_cookie_name)
        _authenticate(request, config, pairing)
        if not pairing.logout(raw_session):
            raise HTTPException(
                status_code=401,
                detail="Control session is invalid or expired.",
            )
        response.delete_cookie(
            key=config.session_cookie_name,
            path="/",
            secure=False,
            httponly=True,
            samesite="strict",
        )
        response.headers["Cache-Control"] = "no-store"
        return LogoutResponse()

    return router


def validate_control_transport(request: Request, config: ControlConfig) -> None:
    """Require the one canonical API Host and exact local UI Origin."""

    if request.headers.get("host") != config.api_host:
        raise HTTPException(
            status_code=400,
            detail="Unexpected control API host.",
        )
    if request.headers.get("origin") != config.ui_origin:
        raise HTTPException(
            status_code=403,
            detail="Control request origin is not allowed.",
        )


def _authenticate(
    request: Request,
    config: ControlConfig,
    pairing: PairingService,
):
    try:
        return pairing.authenticate(
            request.cookies.get(config.session_cookie_name)
        )
    except PairingError as exc:
        raise HTTPException(
            status_code=401,
            detail="Control session is invalid or expired.",
        ) from exc


def _connection_message(integration: Optional[IntegrationStatusResponse]) -> str:
    if integration is None:
        return "No mandatory agent connected."
    agent = integration.agent
    if agent.status == "connected":
        return "Cursor MCP shim connected. Only the fixture tool family is mandatory."
    if agent.status == "disconnected":
        return "Cursor MCP shim capability was revoked or rotated; reconnect."
    return "Sentinel MCP shim is configured but has not called yet."


def _pending_approval_response(
    envelope: ApprovalExecutionEnvelope,
) -> PendingApprovalResponse:
    return PendingApprovalResponse(
        approval_id=envelope.approval_id,
        attempt_id=envelope.attempt_id,
        operation=envelope.operation,
        raw_command=envelope.raw_command,
        targets=list(envelope.targets),
        effects=list(envelope.effects),
        workspace=envelope.workspace,
        task_id=envelope.binding.task_id,
        contract_id=envelope.binding.contract_id,
        contract_version=envelope.binding.contract_version,
        authority_epoch=envelope.binding.authority_epoch,
        environment=envelope.binding.environment,
        reasons=list(envelope.reasons),
        expires_at=envelope.expires_at,
        family=envelope.family,
        tool=envelope.tool,
        arguments=json.loads(envelope.arguments_json),
    )
