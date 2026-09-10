"""Stdio MCP server that forwards fixture tool calls to Sentinel's integration route.

The shim holds no state and makes no decision. It reads its adapter capability
from a file at call time (so launcher rotation takes effect without a restart),
sends raw tool arguments to FastAPI, and only ever reports what FastAPI said.
Transport failures are reported as errors so the agent cannot mistake
"Sentinel unreachable" for "done". Stdlib only; no MCP SDK is required.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any

SERVER_NAME = "sentinel"
SERVER_VERSION = "0.12.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
INTEGRATION_PATH = "/integration/mcp/call"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "sentinel_issue_read",
        "description": "Read one issue from the local Sentinel fixture tracker. Every call is mediated by Sentinel.",
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
            "Add one internal note to a fixture issue. Sentinel holds the write until a human approves "
            "this exact note in the protected control center. To retry after approval, pass the same "
            "attempt_id with the identical issue_id and body."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_id": {"type": "string"},
                "body": {"type": "string"},
                "attempt_id": {"type": "string", "description": "Optional. Reuse to retry an approved attempt unchanged."},
            },
            "required": ["issue_id", "body"],
            "additionalProperties": False,
        },
    },
]
TOOL_NAMES = {tool["name"] for tool in TOOLS}


def _setting(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _capability() -> str | None:
    path = _setting("SENTINEL_ADAPTER_CAPABILITY_FILE", "")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def call_gateway(tool: str, arguments: dict[str, Any], attempt_id: str) -> tuple[bool, dict[str, Any] | str]:
    """Return (has_verdict, payload_or_reason). Never raises."""

    base = _setting("SENTINEL_API_URL", "http://127.0.0.1:8000").rstrip("/")
    timeout = float(_setting("SENTINEL_ADAPTER_TIMEOUT_SECONDS", "5"))
    capability = _capability()
    if capability is None:
        return False, "adapter capability unavailable"
    body = json.dumps({"tool": tool, "arguments": arguments, "attempt_id": attempt_id}).encode("utf-8")
    request = urllib.request.Request(
        base + INTEGRATION_PATH,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {capability}",
            "Host": base.split("://", 1)[-1],
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except (json.JSONDecodeError, ValueError):
            return False, f"Sentinel returned HTTP {exc.code} without a verdict"
        if isinstance(payload, dict) and "verdict" in payload:
            return True, payload
        detail = payload.get("detail") if isinstance(payload, dict) else None
        return False, f"Sentinel rejected the call (HTTP {exc.code}): {detail or 'no detail'}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"Sentinel unreachable or timed out ({exc.__class__.__name__})"
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return False, "Sentinel returned a malformed response"
    if not isinstance(payload, dict) or "verdict" not in payload:
        return False, "Sentinel response lacked a verdict"
    return True, payload


def _tool_result(text: str, *, is_error: bool, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name not in TOOL_NAMES or not isinstance(arguments, dict):
        return _tool_result("Sentinel does not mediate this tool; nothing was performed.", is_error=True)
    arguments = dict(arguments)
    attempt_id = str(arguments.pop("attempt_id", None) or uuid.uuid4())
    has_verdict, outcome = call_gateway(str(name), arguments, attempt_id)
    if not has_verdict:
        return _tool_result(
            f"Sentinel failed closed: {outcome}. The action was NOT performed. Do not retry through "
            "another path; ask the user to check that Sentinel is running and connected.",
            is_error=True,
        )
    assert isinstance(outcome, dict)
    verdict = outcome.get("verdict")
    summary = {
        "verdict": verdict,
        "reason_code": outcome.get("reason_code"),
        "attempt_id": attempt_id,
        "request_id": outcome.get("request_id"),
    }
    if verdict == "allow":
        summary["result"] = outcome.get("result")
        return _tool_result(json.dumps(summary, sort_keys=True), is_error=False, structured=summary)
    if verdict == "confirm_required":
        summary["approval_id"] = outcome.get("approval_id")
        return _tool_result(
            "Sentinel requires human approval for this exact action; nothing was performed. "
            f"Ask the user to review it in the Sentinel control center (approval {outcome.get('approval_id')}), "
            f"then retry with attempt_id={attempt_id} and the identical arguments.",
            is_error=True,
            structured=summary,
        )
    return _tool_result(
        f"Sentinel blocked this action ({outcome.get('reason_code')}): {outcome.get('reason')} "
        f"{outcome.get('guidance') or ''}".strip() + " Nothing was performed.",
        is_error=True,
        structured=summary,
    )


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return _ok(request_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
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
        return None
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def _ok(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve_stdio() -> int:
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
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
            response = handle_message(message) if isinstance(message, dict) else None
        if response is not None:
            stdout.write(json.dumps(response).encode("utf-8") + b"\n")
            stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve_stdio())
