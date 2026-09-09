from __future__ import annotations

import importlib.util
from pathlib import Path


def test_generated_web_control_types_match_fastapi_schemas() -> None:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "generate_control_types.py"
    spec = importlib.util.spec_from_file_location(
        "generate_control_types",
        script,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    generated = root / "web" / "src" / "lib" / "control-types.ts"
    assert generated.read_text(encoding="utf-8") == module.render_types()
