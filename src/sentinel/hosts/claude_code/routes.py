"""HTTP surface for Claude Code's hooks.

Rules the host imposes (docs/Week 16 Plan.md §3.2): a non-2xx, a connection
failure, or a non-JSON body is a *non-blocking error* unless the managed
settings set `onFailure: "block"`. So every route here answers 200 with a
JSON object, and every failure on the PreToolUse route is a `deny` body.
Bodies are read raw: a Pydantic 422 would be a non-2xx.

Only the loopback host may call these routes, and never a browser.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from sentinel.hosts.claude_code import schemas
from sentinel.hosts.claude_code.service import ClaudeCodeHookService

log = logging.getLogger("sentinel.hosts.claude_code.routes")
PREFIX = "/hooks/claude-code"
MAX_HOOK_BODY_BYTES = 8 * 1024 * 1024
UNREADABLE_GUIDANCE = (
    "Sentinel could not read the hook request, so this tool call cannot be checked and is not allowed. "
    "Tell the user; this is a Sentinel or host problem."
)


def _transport_problem(request: Request, api_host: str) -> str | None:
    if request.headers.get("host") != api_host:
        return "host"
    if "origin" in request.headers or "referer" in request.headers:
        return "browser"
    return None


def build_claude_code_router(*, service: ClaudeCodeHookService, api_host: str) -> APIRouter:
    router = APIRouter(prefix=PREFIX, tags=["claude-code-hooks"])

    def guarded(handler: Callable[[Any], dict[str, Any]], *, deny_on_failure: bool) -> Callable[[Request], Any]:
        async def route(request: Request) -> JSONResponse:
            problem = _transport_problem(request, api_host)
            if problem is not None:
                # A wrong Host is a misconfiguration (see `doctor`); a browser is
                # an attack. Neither is allowed to produce a non-deny on PreToolUse.
                status = 421 if problem == "host" else 403
                return JSONResponse(status_code=status, content={"detail": f"hook route rejected: {problem}"})
            try:
                raw = await request.body()
                if len(raw) > MAX_HOOK_BODY_BYTES:
                    raise ValueError("body too large")
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception as exc:  # noqa: BLE001 - unreadable body
                log.warning("hook body unreadable: %s", type(exc).__name__)
                return JSONResponse(status_code=200, content=schemas.deny_response(UNREADABLE_GUIDANCE) if deny_on_failure else {})
            try:
                body = await run_in_threadpool(handler, payload)
            except Exception as exc:  # noqa: BLE001 - last line of defence
                log.exception("hook handler failed: %s", type(exc).__name__)
                body = schemas.deny_response(
                    f"Sentinel failed while checking this call ({type(exc).__name__}); it is not allowed. Tell the user."
                ) if deny_on_failure else {}
            if deny_on_failure and not schemas.forbids_allow(body):
                # Belt and braces: no code path may grant authority.
                log.error("a response tried to return permissionDecision=allow; replaced with an empty body")
                body = schemas.allow_response()
            return JSONResponse(status_code=200, content=body)

        return route

    router.add_api_route("/pre-tool-use", guarded(service.pre_tool_use, deny_on_failure=True), methods=["POST"])
    router.add_api_route("/post-tool-use", guarded(service.post_tool_use, deny_on_failure=False), methods=["POST"])
    # Week 17 advisory routes: a failure here must never stop a prompt or a tool call.
    router.add_api_route("/post-tool-use-failure", guarded(service.post_tool_use_failure, deny_on_failure=False), methods=["POST"])
    router.add_api_route("/user-prompt-submit", guarded(service.user_prompt_submit, deny_on_failure=False), methods=["POST"])
    router.add_api_route("/permission-request", guarded(service.permission_request, deny_on_failure=False), methods=["POST"])
    router.add_api_route("/permission-denied", guarded(service.permission_denied, deny_on_failure=False), methods=["POST"])
    router.add_api_route("/config-change", guarded(service.config_change, deny_on_failure=False), methods=["POST"])
    router.add_api_route("/session", guarded(service.session_start, deny_on_failure=False), methods=["POST"])
    return router


__all__ = ["MAX_HOOK_BODY_BYTES", "PREFIX", "build_claude_code_router"]
