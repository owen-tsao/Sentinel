"""Adapter-facing HTTP route for mediated MCP fixture calls.

Only the MCP shim (or anything holding its adapter capability) calls this
route. Possession authenticates the adapter session only; FastAPI still
resolves the supervision session, ceiling, active contract, and approval
state for every call. Browser-originated requests are rejected outright.
"""

from __future__ import annotations

from typing import Callable, Optional

from fastapi import APIRouter, HTTPException, Request

from sentinel.api.integration_schemas import McpCallRequest, McpCallResponse
from sentinel.control.config import ControlConfig

Mediator = Callable[[Optional[str], McpCallRequest], McpCallResponse]


def build_integration_router(*, config: ControlConfig, mediate: Mediator) -> APIRouter:
    router = APIRouter(prefix="/integration", tags=["integration"])

    @router.post("/mcp/call", response_model=McpCallResponse)
    def mcp_call(payload: McpCallRequest, request: Request) -> McpCallResponse:
        if request.headers.get("host") != config.api_host:
            raise HTTPException(status_code=421, detail="Integration route requires the exact loopback host.")
        if "origin" in request.headers or "referer" in request.headers:
            raise HTTPException(status_code=403, detail="Integration route is not available to browsers.")
        authorization = request.headers.get("authorization", "")
        bearer = authorization[7:].strip() if authorization.startswith("Bearer ") else None
        return mediate(bearer, payload)

    return router
