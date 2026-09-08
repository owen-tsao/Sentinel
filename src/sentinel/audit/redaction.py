"""Conservative secret redaction applied before audit persistence."""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PARTS = {
    "accesskey",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "sessiontoken",
    "token",
}
_ENV_CONTENT_KEYS = {"content", "raw", "text", "value"}
_SAFE_STRUCTURED_KEYS = {"authorizationsource"}
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_BASIC_AUTH_URL_RE = re.compile(r"(://[^:/@\s]+:)[^@\s]+(@)")
_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|xapp-[A-Za-z0-9._-]{10,}|"
    r"xox[a-z0-9.]*-[A-Za-z0-9._-]{10,}|"
    r"ya29\.[A-Za-z0-9._-]{10,})\b"
)
_ASSIGNMENT_RE = re.compile(
    r"(?m)^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*)([^\r\n]*)$"
)


def redact(value: Any, *, force_env_content: bool = False) -> Any:
    """Return a deep-redacted JSON-like value without mutating the input."""

    if isinstance(value, dict):
        env_mapping = _mentions_env_file(value)
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = REDACTED
            else:
                redact_as_env = env_mapping and _normalize_key(key_text) in _ENV_CONTENT_KEYS
                redacted[key_text] = redact(item, force_env_content=redact_as_env)
        return redacted
    if isinstance(value, list):
        return [redact(item, force_env_content=force_env_content) for item in value]
    if isinstance(value, tuple):
        return [redact(item, force_env_content=force_env_content) for item in value]
    if isinstance(value, str):
        return _redact_text(value, force_env_content=force_env_content)
    return value


def _redact_text(value: str, *, force_env_content: bool) -> str:
    value = _PRIVATE_KEY_RE.sub(REDACTED, value)
    value = _BEARER_RE.sub(r"\1" + REDACTED, value)
    value = _BASIC_AUTH_URL_RE.sub(r"\1" + REDACTED + r"\2", value)
    value = _KNOWN_TOKEN_RE.sub(REDACTED, value)

    def replace_assignment(match: re.Match[str]) -> str:
        key = match.group(2)
        if force_env_content or _is_sensitive_key(key):
            return f"{match.group(1)}{REDACTED}"
        return match.group(0)

    return _ASSIGNMENT_RE.sub(replace_assignment, value)


def _mentions_env_file(value: dict[Any, Any]) -> bool:
    for key, item in value.items():
        if _normalize_key(str(key)) not in {"file", "filename", "name", "path", "source"}:
            continue
        if isinstance(item, str) and re.search(r"(?:^|[/\\])\.env(?:[./\\]|$)", item, re.IGNORECASE):
            return True
    return False


def _is_sensitive_key(key: str) -> bool:
    normalized = _normalize_key(key)
    if normalized in _SAFE_STRUCTURED_KEYS:
        return False
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())
