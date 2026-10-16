"""Claude Code hook adapter (docs/Week 16 Plan.md)."""

from sentinel.hosts.claude_code.routes import build_claude_code_router
from sentinel.hosts.claude_code.service import ClaudeCodeHookService
from sentinel.hosts.claude_code.session import SessionRegistry

__all__ = ["ClaudeCodeHookService", "SessionRegistry", "build_claude_code_router"]
