"""Validated startup configuration for the local control boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ControlConfig:
    """Values fixed before startup; none can be selected by an HTTP request."""

    workspace: Path
    pairing_capability: str
    api_host: str = "127.0.0.1:8000"
    ui_origin: str = "http://127.0.0.1:3000"
    session_cookie_name: str = "sentinel_control_session"
    demo_mode: bool = False

    def __post_init__(self) -> None:
        api = urlsplit(f"http://{self.api_host}")
        ui = urlsplit(self.ui_origin)
        if (
            api.hostname != "127.0.0.1"
            or api.port is None
            or api.path
            or api.query
            or api.fragment
            or api.username is not None
            or api.password is not None
        ):
            raise ValueError("control API host must be exact 127.0.0.1:<port>")
        if (
            ui.scheme != "http"
            or ui.hostname != "127.0.0.1"
            or ui.port is None
            or ui.path
            or ui.query
            or ui.fragment
            or ui.username is not None
            or ui.password is not None
            or ui.geturl() != f"http://{ui.netloc}"
        ):
            raise ValueError("control UI origin must be exact http://127.0.0.1:<port>")
        if not self.session_cookie_name or any(
            character in self.session_cookie_name
            for character in '()<>@,;:\\"/[]?={} \t'
        ):
            raise ValueError("control session cookie name is invalid")
