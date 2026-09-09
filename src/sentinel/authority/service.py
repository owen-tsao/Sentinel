"""Audited coordinator for every protected contract lifecycle transition."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable, TypeVar, Union
from uuid import uuid4

from sentinel.audit import AuditEvent, AuditStore
from sentinel.contracts import (
    ActionContract,
    AuthorityQuarantine,
    AuthorizationSource,
    ConsumedTrustedEvent,
    ContractRecord,
    InMemoryContractStore,
    PreflightStatus,
    SQLiteContractStore,
)

ContractStore = Union[InMemoryContractStore, SQLiteContractStore]
ResultT = TypeVar("ResultT")
AuthorityChangeObserver = Callable[[ContractRecord], None]
_QUARANTINED_TRANSITIONS = {
    "active",
    "amended",
    "expired",
    "pending_approved",
    "pending_rejected",
    "proposed",
    "reactivated",
    "revoked",
    "suspended",
}


class ContractAuthorityService:
    """Keep lifecycle mutations behind ordered audit evidence."""

    def __init__(self, contract_store: ContractStore, audit_store: AuditStore) -> None:
        self._contracts = contract_store
        self._audit = audit_store
        self._lock = RLock()
        self._authority_available = True
        self._authority_change_observer: AuthorityChangeObserver | None = None
        self._reconcile_quarantine_locked()

    @property
    def authority_available(self) -> bool:
        """Return whether contract authority is safe to use."""

        with self._lock:
            return self._authority_available

    def set_authority_change_observer(
        self,
        observer: AuthorityChangeObserver,
    ) -> None:
        """Attach process-local cleanup after durable authority transitions."""

        with self._lock:
            self._authority_change_observer = observer

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
        resolved_task_id = task_id or str(uuid4())
        resolved_contract_id = contract_id or str(uuid4())
        return self._transition(
            "proposed",
            lambda: self._contracts.create(
                contract,
                session_id=session_id,
                authorization_source=authorization_source,
                created_at=created_at,
                task_id=resolved_task_id,
                contract_id=resolved_contract_id,
                status="proposed",
                preflight_status=preflight_status,
            ),
            session_id=session_id,
            task_id=resolved_task_id,
            contract_id=resolved_contract_id,
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
        task_id: str | None = None,
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
                task_id=task_id,
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
        task_id: str | None,
        contract_id: str | None,
        contract_version: int | None,
        trusted_event: ConsumedTrustedEvent | None,
        detect_task_switch: bool,
    ) -> ResultT:
        if not self._authority_available:
            raise RuntimeError("authority is unavailable pending recovery")
        previous_active = (
            self._contracts.peek_active(session_id)
            if detect_task_switch and session_id is not None
            else None
        )
        existing = (
            self._contracts.get(contract_id, contract_version)
            if contract_id is not None and contract_version is not None
            else None
        )
        previous_statuses = (
            {
                record.version: record.status
                for record in self._contracts.list_versions(contract_id)
            }
            if contract_id is not None
            else {}
        )
        prepared_task_id = task_id or (existing.task_id if existing else None)
        self._write_event(
            "authority_transition_prepared",
            transition,
            session_id=session_id,
            task_id=prepared_task_id,
            contract_id=contract_id,
            contract_version=contract_version,
            trusted_event=trusted_event,
        )
        quarantine_previous_active = (
            self._contracts.peek_active(session_id)
            if transition in _QUARANTINED_TRANSITIONS and session_id is not None
            else None
        )
        quarantine = self._new_quarantine(
            transition=transition,
            session_id=session_id,
            task_id=prepared_task_id,
            contract_id=contract_id,
            contract_version=contract_version,
            trusted_event=trusted_event,
            previous_active=quarantine_previous_active,
        )
        guard = (
            self._contracts.authority_quarantine_guard(quarantine)
            if quarantine is not None
            else nullcontext()
        )
        with guard:
            try:
                result = operation()
            except Exception:
                try:
                    self._write_new_expiry_events(
                        transition=transition,
                        contract_id=contract_id,
                        previous_statuses=previous_statuses,
                        trusted_event=trusted_event,
                    )
                except Exception as audit_error:
                    self._authority_available = False
                    raise RuntimeError(
                        "authority mutation produced an unaudited expiry; "
                        "execution remains disabled"
                    ) from audit_error
                if quarantine is not None:
                    try:
                        self._contracts.clear_authority_quarantine(
                            quarantine.quarantine_id
                        )
                    except Exception as clear_error:
                        self._authority_available = False
                        raise RuntimeError(
                            "authority mutation failed and quarantine could not be "
                            "cleared; execution remains disabled"
                        ) from clear_error
                raise
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
                        if (
                            displaced is not None
                            and displaced.status != previous_active.status
                        ):
                            self._write_event(
                                "authority_transition_completed",
                                (
                                    "expired_before_task_switch"
                                    if displaced.status == "expired"
                                    else "suspended_for_task_switch"
                                ),
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
                    if quarantine is not None:
                        self._contracts.clear_authority_quarantine(
                            quarantine.quarantine_id
                        )
                except Exception:
                    self._authority_available = False
                    if result.status == "active":
                        try:
                            self._contracts.suspend(
                                result.contract_id,
                                expected_version=result.version,
                                suspended_at=result.updated_at,
                            )
                        except Exception as compensation_error:
                            raise RuntimeError(
                                "authority completion audit and compensation failed; "
                                "execution remains disabled"
                            ) from compensation_error
                    raise
                if self._authority_change_observer is not None:
                    self._notify_authority_change(result)
            elif quarantine is not None:
                self._contracts.clear_authority_quarantine(
                    quarantine.quarantine_id
                )
            return result

    def _new_quarantine(
        self,
        *,
        transition: str,
        session_id: str | None,
        task_id: str | None,
        contract_id: str | None,
        contract_version: int | None,
        trusted_event: ConsumedTrustedEvent | None,
        previous_active: ContractRecord | None,
    ) -> AuthorityQuarantine | None:
        if transition not in _QUARANTINED_TRANSITIONS:
            return None
        return AuthorityQuarantine(
            quarantine_id=str(uuid4()),
            reason="authority_transition_completion_unverified",
            transition=transition,
            session_id=session_id,
            task_id=task_id,
            contract_id=contract_id,
            contract_version=contract_version,
            previous_contract_id=(
                previous_active.contract_id if previous_active is not None else None
            ),
            previous_contract_version=(
                previous_active.version if previous_active is not None else None
            ),
            previous_authority_epoch=(
                previous_active.authority_epoch
                if previous_active is not None
                else None
            ),
            created_at=(
                trusted_event.consumed_at
                if trusted_event is not None
                else datetime.now(timezone.utc)
            ),
        )

    def _reconcile_quarantine_locked(self) -> None:
        quarantine = self._contracts.get_authority_quarantine()
        if quarantine is None:
            return
        self._authority_available = False
        try:
            with self._contracts.authority_quarantine_recovery_guard(
                quarantine.quarantine_id
            ):
                recovery_time = datetime.now(timezone.utc)
                active = (
                    self._contracts.get_active(
                        quarantine.session_id,
                        now=recovery_time,
                    )
                    if quarantine.session_id is not None
                    else None
                )
                suspended: ContractRecord | None = None
                if (
                    active is not None
                    and active.contract_id == quarantine.contract_id
                    and active.version == quarantine.contract_version
                ):
                    suspended = self._contracts.suspend(
                        active.contract_id,
                        expected_version=active.version,
                        suspended_at=recovery_time,
                    )
                elif active is not None and not (
                    active.contract_id == quarantine.previous_contract_id
                    and active.version == quarantine.previous_contract_version
                    and active.authority_epoch
                    == quarantine.previous_authority_epoch
                ):
                    raise RuntimeError(
                        "authority quarantine does not match current or previous "
                        "authority"
                    )
                target = (
                    self._contracts.get(
                        quarantine.contract_id,
                        quarantine.contract_version,
                    )
                    if quarantine.contract_id is not None
                    and quarantine.contract_version is not None
                    else None
                )
                self._audit.write_required(
                    AuditEvent(
                        event_type="authority_quarantine_reconciled",
                        session_id=quarantine.session_id,
                        task_id=quarantine.task_id,
                        contract_id=quarantine.contract_id,
                        contract_version=quarantine.contract_version,
                        environment=(
                            suspended.contract.environment
                            if suspended is not None
                            else target.contract.environment if target else None
                        ),
                        reason_codes=["authority:quarantine_reconciled"],
                        details={
                            "quarantine_id": quarantine.quarantine_id,
                            "reason": quarantine.reason,
                            "transition": quarantine.transition,
                            "target_status": target.status if target else None,
                            "recovery": (
                                "suspended_active_authority"
                                if suspended is not None
                                else (
                                    "previous_authority_unchanged"
                                    if active is not None
                                    else "no_active_authority"
                                )
                            ),
                        },
                    )
                )
                self._contracts.clear_authority_quarantine(
                    quarantine.quarantine_id
                )
        except Exception:
            return
        self._authority_available = True

    def _write_new_expiry_events(
        self,
        *,
        transition: str,
        contract_id: str | None,
        previous_statuses: dict[int, str],
        trusted_event: ConsumedTrustedEvent | None,
    ) -> None:
        if contract_id is None:
            return
        for record in self._contracts.list_versions(contract_id):
            if (
                record.status == "expired"
                and previous_statuses.get(record.version) != "expired"
            ):
                self._write_event(
                    "authority_transition_completed",
                    f"expired_during_{transition}",
                    session_id=record.session_id,
                    task_id=record.task_id,
                    contract_id=record.contract_id,
                    contract_version=record.version,
                    record=record,
                    trusted_event=trusted_event,
                )

    def _notify_authority_change(self, record: ContractRecord) -> None:
        observer = self._authority_change_observer
        if observer is None:
            return
        try:
            observer(record)
        except Exception as exc:
            # Approval invalidation is an eager cleanup only; execution retries
            # revalidate the active authority binding before consuming approval.
            try:
                self._audit.write(
                    AuditEvent(
                        event_type="authority_change_observer_failed",
                        session_id=record.session_id,
                        task_id=record.task_id,
                        contract_id=record.contract_id,
                        contract_version=record.version,
                        environment=record.contract.environment,
                        reason_codes=["authority:observer_failed"],
                        details={"error_type": type(exc).__name__},
                    )
                )
            except Exception:
                return

    def _write_event(
        self,
        event_type: str,
        transition: str,
        *,
        session_id: str | None,
        task_id: str | None = None,
        contract_id: str | None,
        contract_version: int | None,
        record: ContractRecord | None = None,
        trusted_event: ConsumedTrustedEvent | None = None,
    ) -> None:
        details: dict[str, Any] = {"transition": transition}
        if event_type == "authority_transition_prepared" and transition in {
            "active",
            "pending_approved",
            "reactivated",
        }:
            details["completion_failure_compensation"] = (
                "suspend_new_active_authority"
            )
        if record is not None:
            details.update(
                {
                    "status": record.status,
                    "task_id": record.task_id,
                    "authority_epoch": record.authority_epoch,
                    "authorization_source": record.authorization_source,
                }
            )
        elif task_id is not None:
            details["task_id"] = task_id
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
                task_id=record.task_id if record else task_id,
                contract_id=contract_id,
                contract_version=contract_version,
                environment=record.contract.environment if record else None,
                reason_codes=[f"authority:{transition}"],
                details=details,
            )
        )
