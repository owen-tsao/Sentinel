"""Protected local control-plane primitives."""

from .approvals import (
    ApprovalCoordinatorError,
    ApprovalExecutionEnvelope,
    ApprovalRetryResult,
    InMemoryApprovalCoordinator,
)
from .config import ControlConfig
from .drafts import (
    CompiledDraftPreview,
    DraftCompilationError,
    DraftQuestion,
    DraftSuggestion,
    compile_task_prompt,
)
from .pairing import (
    AuthenticatedControlSession,
    IssuedControlSession,
    PairingError,
    PairingService,
    generate_pairing_capability,
)
from .workspace import (
    InMemoryWorkspaceBindingStore,
    ReviewedWorkspace,
    SQLiteWorkspaceBindingStore,
    SupervisionBinding,
    WorkspaceBindingError,
    WorkspaceBindingStore,
    resolve_workspace_target,
    review_workspace,
)

__all__ = [
    "AuthenticatedControlSession",
    "ApprovalCoordinatorError",
    "ApprovalExecutionEnvelope",
    "ApprovalRetryResult",
    "ControlConfig",
    "CompiledDraftPreview",
    "DraftCompilationError",
    "DraftQuestion",
    "DraftSuggestion",
    "InMemoryApprovalCoordinator",
    "InMemoryWorkspaceBindingStore",
    "IssuedControlSession",
    "PairingError",
    "PairingService",
    "ReviewedWorkspace",
    "SQLiteWorkspaceBindingStore",
    "SupervisionBinding",
    "WorkspaceBindingError",
    "WorkspaceBindingStore",
    "generate_pairing_capability",
    "resolve_workspace_target",
    "review_workspace",
    "compile_task_prompt",
]
