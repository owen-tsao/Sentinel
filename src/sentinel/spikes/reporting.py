"""Persistence helpers for sanitized spike summaries."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sentinel.audit.redaction import redact
from sentinel.spikes.models import ProbeSummary


def summary_payload(summary: ProbeSummary) -> dict[str, Any]:
    if hasattr(summary, "model_dump"):
        payload = summary.model_dump(mode="json", warnings=False)
    else:
        payload = json.loads(summary.json())
    return redact(payload)


def write_summary(summary: ProbeSummary, output: Path) -> None:
    """Write only the redacted summary and refuse accidental replacement."""

    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing report: {output}")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = summary_payload(summary)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
