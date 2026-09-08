"""Audited coordinator for every protected contract lifecycle transition."""

from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Any, Callable, TypeVar, Union

from sentinel.audit import AuditEvent, AuditStore
from sentinel.contracts import (
    ActionContract,
    AuthorizationSource,
    ConsumedTrustedEvent,
    ContractRecord,
    InMemoryContractStore,
    PreflightStatus,
    SQLiteContractStore,
)

ContractStore = Union[InMemoryContractStore, SQLiteContractStore]
ResultT = TypeVar("ResultT")


class ContractAuthorityService:
    """Keep lifecycle mutations behind ordered audit evidence."""

    def __init__(self, contract_store: ContractStore, audit_store: AuditStore) -> None:
        self._contracts = contract_store
        self._audit = audit_store
        self._lock = RLock()

    def create_proposed(
        self,
        contract: ActionContract,
        *,
        session_id: str,
        authorization_source: AuthorizationSource,
        created_at: datetime,
        task_id: str | None = None,
        contract_id: str | None = None,
        preflight_status: PreflightStatus = "complete",
    ) -> ContractRecord:
        return self._transition(
            "proposed",
            lambda: self._contracts.create(
                contract,
                session_id=session_id,
                authorization_source=authorization_source,
                created_at=created_at,
                task_id=task_id,
                contract_id=contract_id,
                status="proposed",
                preflight_status=preflight_status,
            ),
            session_id=session_id,
            contract_id=contract_id,
        )

    def activate_proposed(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_active_task_id: str | None,
        trusted_event: ConsumedTrustedEvent,
        activated_at: datetime,
    ) -> ContractRecord:
        return self._transition(
            "active",
            lambda: self._contracts.activate_proposed(
                contract_id,
                expected_version=expected_version,
                expected_active_task_id=expected_active_task_id,
                trusted_event=trusted_event,
                activated_at=activated_at,
            ),
            session_id=trusted_event.session_id,
            contract_id=contract_id,
            contract_version=expected_version,
            trusted_event=trusted_event,
            detect_task_switch=True,
        )

    def amend(
        self,
        contract_id: str,
        contract: ActionContract,
        *,
        expected_version: int,
        authorization_source: AuthorizationSource,
        created_at: datetime,
        sensitive: bool | None = None,
        preflight_status: PreflightStatus = "complete",
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> ContractRecord:
        existing = self._contracts.get(contract_id, expected_version)
        return self._transition(
            "amended",
            lambda: self._contracts.amend(
                contract_id,
                contract,
                expected_version=expected_version,
                authorization_source=authorization_source,
                created_at=created_at,
                sensitive=sensitive,
                preflight_status=preflight_status,
                trusted_event=trusted_event,
            ),
            session_id=existing.session_id if existing else None,
            contract_id=contract_id,
            contract_version=expected_version + 1,
            trusted_event=trusted_event,
        )

    def decide_pending(
        self,
        contract_id: str,
        version: int,
        *,
        approve: bool,
        expected_active_version: int,
        decided_at: datetime,
        trusted_event: ConsumedTrustedEvent,
    ) -> ContractRecord:
        return self._transition(
            "pending_approved" if approve else "pending_rejected",
            lambda: self._contracts.decide_pending(
                contract_id,
                version,
                approve=approve,
                expected_active_version=expected_active_version,
                decided_at=decided_at,
                trusted_event=trusted_event,
            ),
            session_id=trusted_event.session_id,
            contract_id=contract_id,
            contract_version=version,
            trusted_event=trusted_event,
        )

    def suspend(
        self,
        contract_id: str,
        *,
        expected_version: int,
        suspended_at: datetime,
    ) -> ContractRecord:
        return self._simple_transition(
            "suspended",
            contract_id,
            expected_version,
            lambda: self._contracts.suspend(
                contract_id,
                expected_version=expected_version,
                suspended_at=suspended_at,
            ),
        )

    def revoke(
        self,
        contract_id: str,
        *,
        expected_version: int,
        revoked_at: datetime,
    ) -> ContractRecord:
        return self._simple_transition(
            "revoked",
            contract_id,
            expected_version,
            lambda: self._contracts.revoke(
                contract_id,
                expected_version=expected_version,
                revoked_at=revoked_at,
            ),
        )

    def expire(
        self,
        contract_id: str,
        *,
        expected_version: int,
        now: datetime,
    ) -> ContractRecord:
        return self._simple_transition(
            "expired",
            contract_id,
            expected_version,
            lambda: self._contracts.expire(
                contract_id,
                expected_version=expected_version,
                now=now,
            ),
        )

    def reactivate(
        self,
        contract_id: str,
        *,
        expected_version: int,
        expected_active_task_id: str | None,
        trusted_event: ConsumedTrustedEvent,
        reactivated_at: datetime,
    ) -> ContractRecord:
        return self._transition(
            "reactivated",
            lambda: self._contracts.reactivate(
                contract_id,
                expected_version=expected_version,
                expected_active_task_id=expected_active_task_id,
                trusted_event=trusted_event,
                reactivated_at=reactivated_at,
            ),
            session_id=trusted_event.session_id,
            contract_id=contract_id,
            contract_version=expected_version,
            trusted_event=trusted_event,
            detect_task_switch=True,
        )

    def _simple_transition(
        self,
        transition: str,
        contract_id: str,
        expected_version: int,
        operation: Callable[[], ContractRecord],
    ) -> ContractRecord:
        existing = self._contracts.get(contract_id, expected_version)
        return self._transition(
            transition,
            operation,
            session_id=existing.session_id if existing else None,
            contract_id=contract_id,
            contract_version=expected_version,
        )

    def _transition(
        self,
        transition: str,
        operation: Callable[[], ResultT],
        *,
        session_id: str | None,
        contract_id: str | None,
        contract_version: int | None = None,
        trusted_event: ConsumedTrustedEvent | None = None,
        detect_task_switch: bool = False,
    ) -> ResultT:
        with self._lock:
            return self._transition_locked(
                transition,
                operation,
                session_id=session_id,
                contract_id=contract_id,
                contract_version=contract_version,
                trusted_event=trusted_event,
                detect_task_switch=detect_task_switch,
            )

    def _transition_locked(
        self,
        transition: str,
        operation: Callable[[], ResultT],
        *,
        session_id: str | None,
        contract_id: str | None,
        contract_version: int | None,
        trusted_event: ConsumedTrustedEvent | None,
        detect_task_switch: bool,
    ) -> ResultT:
        previous_active = (
            self._contracts.get_active(
                session_id,
                now=(
                    trusted_event.consumed_at
                    if trusted_event is not None
                    else None
                ),
            )
            if detect_task_switch and session_id is not None
            else None
        )
        self._write_event(
            "authority_transition_prepared",
            transition,
            session_id=session_id,
            contract_id=contract_id,
            contract_version=contract_version,
            trusted_event=trusted_event,
        )
        result = operation()
        if isinstance(result, ContractRecord):
            try:
                if (
                    previous_active is not None
                    and previous_active.contract_id != result.contract_id
                ):
                    displaced = self._contracts.get(
                        previous_active.contract_id,
                        previous_active.version,
                    )
                    if displaced is not None and displaced.status != previous_active.status:
                        self._write_event(
                            "authority_transition_completed",
                            "suspended_for_task_switch",
                            session_id=displaced.session_id,
                            contract_id=displaced.contract_id,
                            contract_version=displaced.version,
                            record=displaced,
                            trusted_event=trusted_event,
                        )
                self._write_event(
                    "authority_transition_completed",
                    transition,
                    session_id=result.session_id,
                    contract_id=result.contract_id,
                    contract_version=result.version,
                    record=result,
                    trusted_event=trusted_event,
                )
            except Exception:
                if result.status == "active":
                    self._contracts.suspend(
                        result.contract_id,
                        expected_version=result.version,
                        suspended_at=result.updated_at,
                    )
                raise
        return result

    def _write_event(
        self,
        event_type: str,
        transition: str,
        *,
        session_id: str | None,
        contract_id: str | None,
        contract_version: int | None,
        record: ContractRecord | None = None,
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> None:
        details: dict[str, Any] = {"transition": transition}
        if record is not None:
            details.update(
                {
                    "status": record.status,
                    "task_id": record.task_id,
                    "authority_epoch": record.authority_epoch,
                    "authorization_source": record.authorization_source,
                }
            )
        if trusted_event is not None:
            details["trusted_event"] = {
                "event_id": trusted_event.event_id,
                "host_id": trusted_event.host_id,
                "channel": trusted_event.channel,
                "purpose": trusted_event.purpose,
                "decision": trusted_event.decision,
            }
        self._audit.write_required(
            AuditEvent(
                event_type=event_type,
                session_id=session_id,
                task_id=record.task_id if record else None,
                contract_id=contract_id,
                contract_version=contract_version,
                environment=record.contract.environment if record else None,
                reason_codes=[f"authority:{transition}"],
                details=details,
            )
        )
