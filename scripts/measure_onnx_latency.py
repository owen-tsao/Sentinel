#!/usr/bin/env python3
"""Measure local CPU latency for Sentinel ONNX Runtime inference."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sentinel.ml.inference import DEFAULT_MODEL_DIR, DEFAULT_ONNX_PATH, OnnxRiskModel  # noqa: E402


DEFAULT_EVAL_PATH = Path("data/processed/sentinel_eval.jsonl")


def load_jsonl(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(row)
            if limit is not None and len(rows) >= limit:
                break
    return rows


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        raise ValueError("cannot compute percentile of empty values")
    if percentile_value < 0 or percentile_value > 100:
        raise ValueError("percentile must be between 0 and 100")
    sorted_values = sorted(values)
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (percentile_value / 100.0)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = rank - lower
    return sorted_values[lower] + ((sorted_values[upper] - sorted_values[lower]) * weight)


def latency_summary(latencies_ms: list[float]) -> dict[str, Any]:
    if not latencies_ms:
        raise ValueError("latency summary requires at least one measurement")
    return {
        "count": len(latencies_ms),
        "mean_ms": statistics.fmean(latencies_ms),
        "min_ms": min(latencies_ms),
        "p50_ms": percentile(latencies_ms, 50),
        "p95_ms": percentile(latencies_ms, 95),
        "p99_ms": percentile(latencies_ms, 99),
        "max_ms": max(latencies_ms),
    }


def measure_latency(
    rows: list[dict[str, Any]],
    predict: Callable[[dict[str, Any]], Any],
    warmup: int,
    repeat: int,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    if not rows:
        raise ValueError("latency measurement requires at least one row")
    if warmup < 0:
        raise ValueError("warmup must be non-negative")
    if repeat <= 0:
        raise ValueError("repeat must be positive")

    for index in range(warmup):
        predict(rows[index % len(rows)])

    latencies_ms: list[float] = []
    tier_counts: dict[str, int] = {}
    for _ in range(repeat):
        for row in rows:
            start = clock()
            prediction = predict(row)
            elapsed_ms = (clock() - start) * 1000.0
            latencies_ms.append(elapsed_ms)
            tier = getattr(prediction, "model_tier", "unknown")
            tier_counts[str(tier)] = tier_counts.get(str(tier), 0) + 1

    return {
        **latency_summary(latencies_ms),
        "row_count": len(rows),
        "repeat": repeat,
        "warmup": warmup,
        "tier_counts": dict(sorted(tier_counts.items())),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-path", type=Path, default=DEFAULT_EVAL_PATH)
    parser.add_argument("--onnx-path", type=Path, default=DEFAULT_ONNX_PATH)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--limit", type=int, default=None, help="Optional number of eval rows to measure.")
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output-path", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        rows = load_jsonl(args.eval_path, limit=args.limit)
        model = OnnxRiskModel(onnx_path=args.onnx_path, model_dir=args.model_dir)
        report = {
            "eval_path": str(args.eval_path),
            "onnx_path": str(args.onnx_path),
            "model_dir": str(args.model_dir),
            "provider": model.session.get_providers()[0],
            "latency": measure_latency(rows, model.predict_row, warmup=args.warmup, repeat=args.repeat),
        }
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output_path:
        args.output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output_path.write_text(output, encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
