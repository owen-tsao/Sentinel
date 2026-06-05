#!/usr/bin/env python3
"""Review model threshold sweeps and group breakdowns for Sentinel policy tiers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_MIN_RECALL = 0.9
DEFAULT_MAX_FPR = 0.3


def load_report(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, dict):
        raise ValueError(f"{path}: expected JSON object")
    return report


def threshold_rows(eval_metrics: dict[str, Any]) -> list[dict[str, Any]]:
    rows_by_threshold: dict[float, dict[str, Any]] = {}
    for metrics in [eval_metrics, *eval_metrics.get("threshold_sweep", [])]:
        threshold = metrics.get("threshold")
        if threshold is None:
            continue
        rows_by_threshold[float(threshold)] = {
            "threshold": float(threshold),
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "dangerous_recall": metrics.get("dangerous_recall"),
            "false_positive_rate": metrics.get("false_positive_rate"),
            "confusion": metrics.get("confusion", {}),
            "total": metrics.get("total"),
        }
    return [rows_by_threshold[key] for key in sorted(rows_by_threshold)]


def recommend_policy_bands(
    rows: list[dict[str, Any]],
    min_recall: float = DEFAULT_MIN_RECALL,
    max_fpr: float = DEFAULT_MAX_FPR,
) -> dict[str, Any]:
    if not rows:
        return {
            "warn_threshold": None,
            "confirm_threshold": None,
            "model_block": False,
            "notes": ["No threshold rows were available."],
        }

    recall_sorted = sorted(rows, key=lambda row: (_metric(row, "dangerous_recall"), -_metric(row, "false_positive_rate")), reverse=True)
    bounded_rows = [row for row in rows if _metric(row, "false_positive_rate") <= max_fpr]
    recall_target_rows = [row for row in rows if _metric(row, "dangerous_recall") >= min_recall]

    warn_row = min(recall_target_rows, key=lambda row: row["threshold"]) if recall_target_rows else recall_sorted[0]
    confirm_pool = bounded_rows if bounded_rows else rows
    confirm_row = max(
        confirm_pool,
        key=lambda row: (
            _metric(row, "dangerous_recall"),
            -_metric(row, "false_positive_rate"),
            _metric(row, "accuracy"),
        ),
    )

    notes: list[str] = []
    if not recall_target_rows:
        notes.append(f"No evaluated threshold reached dangerous recall >= {min_recall:.2f}; warn threshold uses the best available recall.")
    if not bounded_rows:
        notes.append(f"No evaluated threshold kept false positive rate <= {max_fpr:.2f}; confirm threshold uses the best available tradeoff.")
    if warn_row["threshold"] >= confirm_row["threshold"]:
        notes.append("Warn and confirm thresholds overlap; treat this as a signal that the model is not well calibrated enough for nuanced tiers.")
    notes.append("Do not use the model alone for block decisions; reserve block for deterministic rules and policy.")

    return {
        "warn_threshold": warn_row["threshold"],
        "confirm_threshold": confirm_row["threshold"],
        "model_block": False,
        "warn_metrics": warn_row,
        "confirm_metrics": confirm_row,
        "notes": notes,
    }


def weakest_groups(eval_metrics: dict[str, Any], group_key: str, limit: int) -> dict[str, list[dict[str, Any]]]:
    groups = eval_metrics.get(group_key, {})
    if not isinstance(groups, dict):
        return {"dangerous_recall": [], "false_positive_rate": []}

    dangerous_groups: list[dict[str, Any]] = []
    benign_groups: list[dict[str, Any]] = []
    for name, metrics in groups.items():
        if not isinstance(metrics, dict):
            continue
        row = {
            "name": name,
            "total": metrics.get("total"),
            "dangerous_recall": metrics.get("dangerous_recall"),
            "false_positive_rate": metrics.get("false_positive_rate"),
            "precision": metrics.get("precision"),
            "confusion": metrics.get("confusion", {}),
        }
        if metrics.get("dangerous_recall") is not None:
            dangerous_groups.append(row)
        if metrics.get("false_positive_rate") is not None:
            benign_groups.append(row)

    return {
        "dangerous_recall": sorted(dangerous_groups, key=lambda row: (_metric(row, "dangerous_recall"), -int(row.get("total") or 0)))[:limit],
        "false_positive_rate": sorted(benign_groups, key=lambda row: (_metric(row, "false_positive_rate"), int(row.get("total") or 0)), reverse=True)[:limit],
    }


def build_calibration_review(report: dict[str, Any], min_recall: float, max_fpr: float, group_limit: int) -> dict[str, Any]:
    eval_metrics = report.get("eval", {})
    if not isinstance(eval_metrics, dict):
        raise ValueError("report does not contain an eval metrics object")
    rows = threshold_rows(eval_metrics)
    return {
        "model_name": report.get("model_name"),
        "device": report.get("device"),
        "eval_rows": report.get("eval_rows"),
        "thresholds": rows,
        "policy_bands": recommend_policy_bands(rows, min_recall=min_recall, max_fpr=max_fpr),
        "weakest_by_risk_category": weakest_groups(eval_metrics, "by_risk_category", group_limit),
        "weakest_by_source": weakest_groups(eval_metrics, "by_source", group_limit),
    }


def render_markdown(review: dict[str, Any]) -> str:
    bands = review["policy_bands"]
    lines = [
        "# Threshold Calibration Review",
        "",
        f"- Eval rows: `{review.get('eval_rows')}`",
        f"- Recommended warn threshold: `{bands['warn_threshold']}`",
        f"- Recommended confirm threshold: `{bands['confirm_threshold']}`",
        "- Model block threshold: `none`",
        "",
        "## Threshold Sweep",
        "",
        "| Threshold | Recall | FPR | Precision | Accuracy | Confusion |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in review["thresholds"]:
        confusion = row.get("confusion", {})
        lines.append(
            "| "
            f"{row['threshold']:.2f} | "
            f"{_format_metric(row.get('dangerous_recall'))} | "
            f"{_format_metric(row.get('false_positive_rate'))} | "
            f"{_format_metric(row.get('precision'))} | "
            f"{_format_metric(row.get('accuracy'))} | "
            f"TP={confusion.get('tp', 0)}, FP={confusion.get('fp', 0)}, TN={confusion.get('tn', 0)}, FN={confusion.get('fn', 0)} |"
        )

    lines.extend(["", "## Policy Notes", ""])
    for note in bands["notes"]:
        lines.append(f"- {note}")

    lines.extend(["", "## Weakest Risk Categories", ""])
    lines.extend(_render_group_section(review["weakest_by_risk_category"]))
    lines.extend(["", "## Weakest Sources", ""])
    lines.extend(_render_group_section(review["weakest_by_source"]))
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="Path to a training_report.json file.")
    parser.add_argument("--min-recall", type=float, default=DEFAULT_MIN_RECALL)
    parser.add_argument("--max-fpr", type=float, default=DEFAULT_MAX_FPR)
    parser.add_argument("--group-limit", type=int, default=5)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    review = build_calibration_review(load_report(args.report), args.min_recall, args.max_fpr, args.group_limit)
    if args.format == "json":
        print(json.dumps(review, indent=2, sort_keys=True))
    else:
        print(render_markdown(review))
    return 0


def _render_group_section(groups: dict[str, list[dict[str, Any]]]) -> list[str]:
    lines = ["Lowest dangerous recall:"]
    if groups["dangerous_recall"]:
        for row in groups["dangerous_recall"]:
            lines.append(f"- `{row['name']}`: recall {_format_metric(row.get('dangerous_recall'))}, total `{row.get('total')}`")
    else:
        lines.append("- No dangerous examples available in this breakdown.")

    lines.append("")
    lines.append("Highest false positive rate:")
    if groups["false_positive_rate"]:
        for row in groups["false_positive_rate"]:
            lines.append(f"- `{row['name']}`: FPR {_format_metric(row.get('false_positive_rate'))}, total `{row.get('total')}`")
    else:
        lines.append("- No benign examples available in this breakdown.")
    return lines


def _metric(row: dict[str, Any], key: str) -> float:
    value = row.get(key)
    return 0.0 if value is None else float(value)


def _format_metric(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}"


if __name__ == "__main__":
    raise SystemExit(main())
