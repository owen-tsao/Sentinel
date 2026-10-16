"""HTTP surface for the Cursor forwarder.

One route per Cursor event under `/hooks/cursor/<event>`. The forwarder is
the only intended caller: a loopback process with no cookie. The same
transport guards as the Claude Code routes apply (exact `Host`, no browser
`Origin`/`Referer`), and every answer is 200 with a JSON object so the
forwarder never has to interpret a status code: a gating event that cannot
be served is a `deny` body; a non-gating one is its pass-through body.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from sentinel.hosts.cursor.schemas import EVENTS, GATING_EVENTS
from sentinel.hosts.cursor.service import CursorHookService

log = logging.getLogger("sentinel.hosts.cursor.routes")
PREFIX = "/hooks/cursor"
MAX_HOOK_BODY_BYTES = 8 * 1024 * 1024
UNREADABLE = ("Sentinel could not read the hook request, so this tool call cannot be checked and is not allowed. "
              "Tell the user; this is a Sentinel or Cursor problem.")


def _deny(reason: str) -> dict[str, Any]:
    return {"permission": "deny", "user_message": reason, "agent_message": reason}


def _pass(event: str) -> dict[str, Any]:
    return {"continue": True} if event == "beforeSubmitPrompt" else {}


def _transport_problem(request: Request, api_host: str) -> str | None:
    if request.headers.get("host") != api_host:
        return "host"
    if "origin" in request.headers or "referer" in request.headers:
        return "browser"
    return None


def build_cursor_router(*, service: CursorHookService, api_host: str) -> APIRouter:
    router = APIRouter(prefix=PREFIX, tags=["cursor-hooks"])

    def route_for(event: str):
        gating = event in GATING_EVENTS

        async def route(request: Request) -> JSONResponse:
            problem = _transport_problem(request, api_host)
            if problem is not None:
                status = 421 if problem == "host" else 403
                return JSONResponse(status_code=status, content={"detail": f"hook route rejected: {problem}"})
            try:
                raw = await request.body()
                if len(raw) > MAX_HOOK_BODY_BYTES:
                    raise ValueError("body too large")
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception as exc:  # noqa: BLE001 - unreadable body; never log it
                log.warning("cursor %s body unreadable: %s", event, type(exc).__name__)
                return JSONResponse(status_code=200, content=_deny(UNREADABLE) if gating else _pass(event))
            try:
                body = await run_in_threadpool(service.handle, event, payload)
            except Exception as exc:  # noqa: BLE001 - last line of defence
                log.exception("cursor %s handler failed: %s", event, type(exc).__name__)
                body = _deny(f"Sentinel failed while checking this call ({type(exc).__name__}); it is not allowed. "
                             "Tell the user.") if gating else _pass(event)
            if gating and body.get("permission") == "allow":
                log.error("a cursor response tried to return permission=allow; field removed")
                body = {k: v for k, v in body.items() if k != "permission"}
            return JSONResponse(status_code=200, content=body)

        return route

    for event in sorted(EVENTS):
        router.add_api_route(f"/{event}", route_for(event), methods=["POST"], name=f"cursor_{event}")
    return router


__all__ = ["MAX_HOOK_BODY_BYTES", "PREFIX", "build_cursor_router"]
