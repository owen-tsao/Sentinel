#!/usr/bin/env python3
"""Evaluate Sentinel's deterministic rules baseline on processed JSONL data."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sentinel.decision.rules import RuleDecision, evaluate_command  # noqa: E402


INTERVENTION_VERDICTS = {"confirm_required", "block"}
ESCALATION_VERDICTS = {"warn", "confirm_required", "block"}
DEFAULT_INPUTS = (
    Path("data/processed/sentinel_seed_eval.jsonl"),
    Path("data/processed/sentinel_eval.jsonl"),
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(row)
    return rows


def evaluate_rows(rows: list[dict[str, Any]], sample_limit: int = 10) -> dict[str, Any]:
    evaluated: list[tuple[dict[str, Any], RuleDecision]] = []
    for row in rows:
        decision = evaluate_command(
            context=str(row.get("context", "")),
            command=str(row.get("command", "")),
            environment=str(row.get("environment", "sandbox")),
            recent_actions=row.get("recent_actions") if isinstance(row.get("recent_actions"), list) else [],
        )
        evaluated.append((row, decision))

    total = len(evaluated)
    dangerous_rows = [(row, decision) for row, decision in evaluated if row.get("label") == 1]
    benign_rows = [(row, decision) for row, decision in evaluated if row.get("label") == 0]

    dangerous_interventions = [
        (row, decision)
        for row, decision in dangerous_rows
        if decision.verdict in INTERVENTION_VERDICTS
    ]
    dangerous_blocks = [(row, decision) for row, decision in dangerous_rows if decision.verdict == "block"]
    dangerous_misses = [
        (row, decision)
        for row, decision in dangerous_rows
        if decision.verdict not in INTERVENTION_VERDICTS
    ]
    benign_blocks = [(row, decision) for row, decision in benign_rows if decision.verdict == "block"]
    benign_escalations = [
        (row, decision)
        for row, decision in benign_rows
        if decision.verdict in ESCALATION_VERDICTS
    ]
    verdict_mismatches = [
        (row, decision)
        for row, decision in evaluated
        if row.get("expected_verdict") and decision.verdict != row.get("expected_verdict")
    ]

    return {
        "total_rows": total,
        "label_counts": dict(Counter(row.get("label") for row, _ in evaluated)),
        "expected_verdict_counts": dict(Counter(row.get("expected_verdict") for row, _ in evaluated)),
        "predicted_verdict_counts": dict(Counter(decision.verdict for _, decision in evaluated)),
        "predicted_reason_code_counts": dict(Counter(decision.reason_code for _, decision in evaluated)),
        "source_counts": dict(Counter(row.get("source") for row, _ in evaluated)),
        "risk_category_counts": dict(Counter(row.get("risk_category") for row, _ in evaluated)),
        "dangerous_recall_intervention": _ratio(len(dangerous_interventions), len(dangerous_rows)),
        "dangerous_recall_block_only": _ratio(len(dangerous_blocks), len(dangerous_rows)),
        "benign_block_false_positive_rate": _ratio(len(benign_blocks), len(benign_rows)),
        "benign_escalation_rate": _ratio(len(benign_escalations), len(benign_rows)),
        "expected_verdict_accuracy": _ratio(total - len(verdict_mismatches), total),
        "verdict_confusion": _verdict_confusion(evaluated),
        "source_breakdown": _breakdown(evaluated, key="source"),
        "risk_category_breakdown": _breakdown(evaluated, key="risk_category"),
        "failure_samples": {
            "dangerous_misses": _samples(dangerous_misses, sample_limit),
            "benign_blocks": _samples(benign_blocks, sample_limit),
            "verdict_mismatches": _samples(verdict_mismatches, sample_limit),
        },
    }


def evaluate_files(paths: list[Path], sample_limit: int = 10) -> dict[str, Any]:
    file_reports: dict[str, Any] = {}
    all_rows: list[dict[str, Any]] = []
    for path in paths:
        rows = load_jsonl(path)
        file_reports[str(path)] = evaluate_rows(rows, sample_limit=sample_limit)
        all_rows.extend(rows)

    return {
        "inputs": [str(path) for path in paths],
        "overall": evaluate_rows(all_rows, sample_limit=sample_limit),
        "by_file": file_reports,
    }


def print_human_summary(report: dict[str, Any]) -> None:
    overall = report["overall"]
    print("Sentinel rules baseline evaluation")
    print("=" * 36)
    print(f"Inputs: {', '.join(report['inputs'])}")
    print(f"Rows: {overall['total_rows']}")
    print(f"Dangerous recall (intervention): {_format_pct(overall['dangerous_recall_intervention'])}")
    print(f"Dangerous recall (block only): {_format_pct(overall['dangerous_recall_block_only'])}")
    print(f"Benign block FPR: {_format_pct(overall['benign_block_false_positive_rate'])}")
    print(f"Benign escalation rate: {_format_pct(overall['benign_escalation_rate'])}")
    print(f"Expected verdict accuracy: {_format_pct(overall['expected_verdict_accuracy'])}")
    print(f"Predicted verdicts: {overall['predicted_verdict_counts']}")
    print(f"Top reason codes: {dict(Counter(overall['predicted_reason_code_counts']).most_common(8))}")

    samples = overall["failure_samples"]
    for name in ("dangerous_misses", "benign_blocks", "verdict_mismatches"):
        print(f"\n{name}: {len(samples[name])} shown")
        for sample in samples[name][:5]:
            print(
                "- "
                f"{sample['id']} expected={sample['expected_verdict']} "
                f"label={sample['label']} predicted={sample['predicted_verdict']} "
                f"reason={sample['reason_code']} command={sample['command'][:100]}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path, default=list(DEFAULT_INPUTS))
    parser.add_argument("--include-osharm", action="store_true", help="Also evaluate data/processed/sentinel_osharm_diagnostic.jsonl.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    parser.add_argument("--sample-limit", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = list(args.inputs)
    if args.include_osharm:
        paths.append(Path("data/processed/sentinel_osharm_diagnostic.jsonl"))

    missing = [path for path in paths if not path.exists()]
    if missing:
        for path in missing:
            print(f"missing input: {path}", file=sys.stderr)
        return 1

    report = evaluate_files(paths, sample_limit=args.sample_limit)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human_summary(report)
    return 0


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _format_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.1%}"


def _verdict_confusion(evaluated: list[tuple[dict[str, Any], RuleDecision]]) -> dict[str, dict[str, int]]:
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    for row, decision in evaluated:
        confusion[str(row.get("expected_verdict"))][decision.verdict] += 1
    return {expected: dict(predicted) for expected, predicted in sorted(confusion.items())}


def _breakdown(evaluated: list[tuple[dict[str, Any], RuleDecision]], key: str) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[tuple[dict[str, Any], RuleDecision]]] = defaultdict(list)
    for row, decision in evaluated:
        grouped[str(row.get(key, "unknown"))].append((row, decision))

    breakdown: dict[str, dict[str, Any]] = {}
    for group, group_rows in sorted(grouped.items()):
        dangerous = [(row, decision) for row, decision in group_rows if row.get("label") == 1]
        benign = [(row, decision) for row, decision in group_rows if row.get("label") == 0]
        interventions = [(row, decision) for row, decision in dangerous if decision.verdict in INTERVENTION_VERDICTS]
        benign_blocks = [(row, decision) for row, decision in benign if decision.verdict == "block"]
        breakdown[group] = {
            "rows": len(group_rows),
            "label_counts": dict(Counter(row.get("label") for row, _ in group_rows)),
            "predicted_verdict_counts": dict(Counter(decision.verdict for _, decision in group_rows)),
            "dangerous_recall_intervention": _ratio(len(interventions), len(dangerous)),
            "benign_block_false_positive_rate": _ratio(len(benign_blocks), len(benign)),
        }
    return breakdown


def _samples(pairs: list[tuple[dict[str, Any], RuleDecision]], limit: int) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for row, decision in pairs[:limit]:
        samples.append(
            {
                "id": row.get("id"),
                "source": row.get("source"),
                "label": row.get("label"),
                "risk_category": row.get("risk_category"),
                "expected_verdict": row.get("expected_verdict"),
                "predicted_verdict": decision.verdict,
                "reason_code": decision.reason_code,
                "reason": decision.reason,
                "command": row.get("command"),
                "context": row.get("context"),
            }
        )
    return samples


if __name__ == "__main__":
    raise SystemExit(main())
