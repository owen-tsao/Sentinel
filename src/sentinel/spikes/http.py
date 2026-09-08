"""Bounded HTTPS JSON client used only by manual read-only probes."""

from __future__ import annotations

import json
import socket
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sentinel.spikes.common import LiveSpikeError


class JsonHttpClientProtocol(Protocol):
    def get_json(
        self,
        url: str,
        *,
        bearer_token: str,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        ...


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class BoundedJsonHttpClient:
    """GET-only client with exact hosts, no redirects, and bounded responses."""

    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        timeout_seconds: float = 10.0,
        maximum_response_bytes: int = 2_000_000,
        maximum_total_response_bytes: int = 20_000_000,
        maximum_calls: int = 500,
        maximum_elapsed_seconds: float = 120.0,
    ) -> None:
        if not allowed_hosts:
            raise ValueError("at least one allowed host is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if maximum_response_bytes <= 0:
            raise ValueError("maximum_response_bytes must be positive")
        if maximum_total_response_bytes < maximum_response_bytes:
            raise ValueError("maximum_total_response_bytes is too small")
        if maximum_calls <= 0 or maximum_elapsed_seconds <= 0:
            raise ValueError("HTTP call and elapsed limits must be positive")
        self._allowed_hosts = {host.lower() for host in allowed_hosts}
        self._timeout_seconds = timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes
        self._maximum_total_response_bytes = maximum_total_response_bytes
        self._maximum_calls = maximum_calls
        self._maximum_elapsed_seconds = maximum_elapsed_seconds
        self._call_count = 0
        self._total_response_bytes = 0
        self._started_at = time.monotonic()
        self._opener = build_opener(_RejectRedirects())

    def get_json(
        self,
        url: str,
        *,
        bearer_token: str,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if not bearer_token:
            raise LiveSpikeError("spike:missing_bearer_token")
        parsed = urlparse(url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise LiveSpikeError("spike:http_target_not_allowed") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() not in self._allowed_hosts
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.fragment)
        ):
            raise LiveSpikeError("spike:http_target_not_allowed")
        if self._call_count >= self._maximum_calls:
            raise LiveSpikeError("spike:http_call_budget_exceeded")
        if time.monotonic() - self._started_at > self._maximum_elapsed_seconds:
            raise LiveSpikeError("spike:http_deadline_exceeded")
        query_string = urlencode(query or {}, doseq=True)
        request_url = url + (
            ("&" if parsed.query else "?") + query_string if query_string else ""
        )
        request = Request(
            request_url,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json",
                "User-Agent": "sentinel-live-metadata-spike/0",
                **self._safe_extra_headers(headers),
            },
            method="GET",
        )
        try:
            self._call_count += 1
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                payload = response.read(self._maximum_response_bytes + 1)
        except HTTPError as exc:
            raise LiveSpikeError(f"spike:http_status_{exc.code}") from exc
        except (URLError, TimeoutError, socket.timeout) as exc:
            raise LiveSpikeError("spike:http_unavailable") from exc
        if len(payload) > self._maximum_response_bytes:
            raise LiveSpikeError("spike:http_response_too_large")
        self._total_response_bytes += len(payload)
        if self._total_response_bytes > self._maximum_total_response_bytes:
            raise LiveSpikeError("spike:http_total_response_budget_exceeded")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LiveSpikeError("spike:invalid_json_response") from exc
        if not isinstance(decoded, dict):
            raise LiveSpikeError("spike:json_object_required")
        return decoded

    @staticmethod
    def _safe_extra_headers(headers: dict[str, str] | None) -> dict[str, str]:
        if not headers:
            return {}
        allowed = {"x-goog-drive-resource-keys"}
        if any(key.lower() not in allowed for key in headers):
            raise LiveSpikeError("spike:http_header_not_allowed")
        if not all(
            isinstance(value, str)
            and value
            and "\r" not in value
            and "\n" not in value
            for value in headers.values()
        ):
            raise LiveSpikeError("spike:http_header_invalid")
        return headers
