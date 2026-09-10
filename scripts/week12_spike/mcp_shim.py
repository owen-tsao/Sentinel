#!/usr/bin/env python3
"""Disposable Week 12 Phase 0 MCP shim.

A stdio JSON-RPC server that exposes exactly two tools to Cursor and forwards
every call to the fixture gateway with a session-scoped bearer. The shim holds
no fixture state, makes no decision, and never claims success unless the
gateway returned an explicit verdict. Any transport failure is reported as an
error result so the agent cannot mistake "Sentinel unreachable" for "done".

Stdlib only so Phase 0 can run before any MCP SDK is approved.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
TOOLS = [
    {
        "name": "sentinel_issue_read",
        "description": "Read one issue from the disposable Sentinel fixture tracker. Mediated by Sentinel.",
        "inputSchema": {
            "type": "object",
            "properties": {"issue_id": {"type": "string", "description": "Issue ID such as SPIKE-1"}},
            "required": ["issue_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sentinel_issue_add_note",
        "description": (
            "Add one internal note to a fixture issue. Requires human approval in the protected "
            "Sentinel surface. Pass the returned attempt_id again to retry the same approved action."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_id": {"type": "string"},
                "body": {"type": "string"},
                "attempt_id": {"type": "string", "description": "Optional. Reuse to retry an approved attempt."},
            },
            "required": ["issue_id", "body"],
            "additionalProperties": False,
        },
    },
]


def _load_capability() -> str | None:
    path = os.environ.get("SENTINEL_SPIKE_ADAPTER_CAPABILITY_FILE")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def _gateway_call(tool: str, arguments: dict[str, Any], attempt_id: str) -> tuple[bool, dict[str, Any] | str]:
    gateway = os.environ.get("SENTINEL_SPIKE_GATEWAY_URL", "http://127.0.0.1:8765")
    timeout = float(os.environ.get("SENTINEL_SPIKE_TIMEOUT_SECONDS", "5"))
    capability = _load_capability()
    if capability is None:
        return False, "adapter capability unavailable"
    body = json.dumps({"tool": tool, "arguments": arguments, "attempt_id": attempt_id}).encode("utf-8")
    request = urllib.request.Request(
        f"{gateway}/integration/mcp/call",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {capability}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            return True, json.loads(exc.read())
        except (json.JSONDecodeError, ValueError):
            return False, f"gateway returned HTTP {exc.code} without a verdict"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"gateway unreachable or timed out: {exc.__class__.__name__}"
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return False, "gateway returned a malformed response"
    if not isinstance(payload, dict) or "verdict" not in payload:
        return False, "gateway response lacked a verdict"
    return True, payload


def _tool_result(text: str, *, is_error: bool, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name not in {tool["name"] for tool in TOOLS} or not isinstance(arguments, dict):
        return _tool_result("Sentinel does not mediate this tool; nothing was performed.", is_error=True)
    attempt_id = arguments.pop("attempt_id", None) or str(uuid.uuid4())
    ok, outcome = _gateway_call(str(name), arguments, str(attempt_id))
    if not ok:
        return _tool_result(
            f"Sentinel failed closed: {outcome}. The action was NOT performed. Do not retry through "
            "another path; ask the user to check that Sentinel is running.",
            is_error=True,
        )
    assert isinstance(outcome, dict)
    verdict = outcome.get("verdict")
    summary = {"verdict": verdict, "reason_code": outcome.get("reason_code"), "attempt_id": attempt_id}
    if verdict == "allow":
        summary["result"] = outcome.get("result")
        return _tool_result(json.dumps(summary, sort_keys=True), is_error=False, structured=summary)
    if verdict == "confirm_required":
        summary["approval_id"] = outcome.get("approval_id")
        return _tool_result(
            "Sentinel requires human approval for this exact action. Nothing was performed. "
            f"Ask the user to review approval {outcome.get('approval_id')} in the protected Sentinel "
            f"surface, then retry with attempt_id={attempt_id} unchanged.",
            is_error=True,
            structured=summary,
        )
    return _tool_result(
        f"Sentinel blocked this action ({outcome.get('reason_code')}): {outcome.get('reason')} "
        "Nothing was performed.",
        is_error=True,
        structured=summary,
    )


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return _ok(request_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "sentinel-spike-shim", "version": "0.0.1"},
        })
    if method == "ping":
        return _ok(request_id, {})
    if method == "tools/list":
        return _ok(request_id, {"tools": TOOLS})
    if method == "tools/call":
        return _ok(request_id, handle_tools_call(params))
    if method in {"resources/list", "resources/templates/list"}:
        return _ok(request_id, {"resources": [], "resourceTemplates": []})
    if method == "prompts/list":
        return _ok(request_id, {"prompts": []})
    if request_id is None:
        return None  # notifications such as notifications/initialized need no reply
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def _ok(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response: dict[str, Any] | None = {
                "jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"},
            }
        else:
            response = handle_request(message) if isinstance(message, dict) else None
        if response is not None:
            stdout.write(json.dumps(response).encode("utf-8") + b"\n")
            stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
