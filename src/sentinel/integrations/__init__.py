"""Adapters that translate external agent actions into Sentinel decisions."""

from sentinel.integrations.cursor import (
    CURSOR_CAPABILITY_MATRIX,
    CursorCapability,
    cursor_authority_boundary_passes,
)

__all__ = [
    "CURSOR_CAPABILITY_MATRIX",
    "CursorCapability",
    "cursor_authority_boundary_passes",
]
