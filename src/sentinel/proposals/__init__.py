"""Agent task proposals: structured drafts that never grant authority."""

from .models import (
    MAX_PROPOSAL_TARGETS,
    MAX_TASK_DURATION_MINUTES,
    ProposalError,
    ProposalFacts,
    ProposalResolution,
    ProposalState,
    ProposalStateError,
    ProposalValidationError,
    TaskProposal,
    derive_objective,
)
from .service import (
    DEFAULT_PROPOSAL_TTL,
    InMemoryTaskProposalStore,
    TaskProposalService,
    facts_from_arguments,
)

__all__ = [
    "DEFAULT_PROPOSAL_TTL",
    "InMemoryTaskProposalStore",
    "MAX_PROPOSAL_TARGETS",
    "MAX_TASK_DURATION_MINUTES",
    "ProposalError",
    "ProposalFacts",
    "ProposalResolution",
    "ProposalState",
    "ProposalStateError",
    "ProposalValidationError",
    "TaskProposal",
    "TaskProposalService",
    "derive_objective",
    "facts_from_arguments",
]
