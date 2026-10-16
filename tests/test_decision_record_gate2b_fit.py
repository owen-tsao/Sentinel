"""Kill condition for the decision record (docs/Decision Record.md section 7):
every Gate 2b incident, judged by the spike floor, must fit the record with no
free-form dict. Runs only when `bashlex` is importable; the spike is not a
dependency of the product.

The bridge below is the shape the Week 16 hook adapter will implement for
real; here it exists to prove the schema is sufficient, not to ship.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel.decisions import (  # noqa: E402
    ActionDescription,
    DecisionRecord,
    FilesystemFacts,
    Judgment,
    ResolvedTarget,
    ResourceFacts,
)

GATE2A = ROOT / "spikes" / "week15" / "gate2a"
GATE2B = ROOT / "spikes" / "week15" / "gate2b"

try:
    import bashlex  # noqa: F401

    HAVE_BASHLEX = True
except ImportError:
    HAVE_BASHLEX = False

VERDICT = {"allow": "allow", "warn": "warn", "confirm": "confirm_required", "block": "block"}
KIND = {"delete": "delete", "write": "write", "read": "read", "execute": "execute"}


def bridge(command: str, cwd: str, environment: str, home: str | None) -> DecisionRecord:
    """Spike Report + Finding -> DecisionRecord. What the adapter will do."""
    sys.path.insert(0, str(GATE2A))
    sys.path.insert(0, str(GATE2B))
    from extract import analyze  # type: ignore[import-not-found]
    from floor import Session, floor  # type: ignore[import-not-found]

    finding = floor(command, cwd, environment, Session(), home)
    report = analyze(command, cwd, home)
    unparseable = report.status == "unparseable"
    is_windows_rule = finding.rule in {"F1.destructive_root", "F1.destructive_home", "F5.windows_nested_quote_delete"}

    targets: list[ResolvedTarget] = []
    for t in report.targets:
        judged_by = "directory" if "glob" in t.note else "parser"
        targets.append(ResolvedTarget(
            raw=t.raw or ".", kind=KIND.get(t.kind, "write"), surface="filesystem",
            filesystem=FilesystemFacts(resolved=t.resolved, zone=t.zone, judged_by=judged_by, note=t.note or None),
        ))
    if not targets and finding.targets:
        # The floor found a target the extractor did not list: the Windows
        # recognizer (pre-parser) or the literal fallback (post-parser).
        judged_by = "windows_recognizer" if is_windows_rule else "literal"
        zone = "root" if "root" in finding.rule else "home" if "home" in finding.rule else "outside"
        for resolved in finding.targets:
            targets.append(ResolvedTarget(
                raw=resolved, kind="delete", surface="filesystem",
                filesystem=FilesystemFacts(resolved=resolved, zone=zone, judged_by=judged_by),
            ))
    if not targets and finding.rule.startswith("F8."):
        # Shared infrastructure: the thing affected is a database or network
        # surface, not a path. The schema's resource surface is for exactly this.
        resource_type = {"F8.schema_change_prod": "database_schema", "F8.infra_destroy": "database",
                         "F8.expose_network": "network_listener"}.get(finding.rule, "infrastructure")
        targets.append(ResolvedTarget(
            raw=command.split()[0], kind="network" if resource_type == "network_listener" else "write",
            surface="resource",
            resource=ResourceFacts(resource_type=resource_type, resource_id=f"{environment}:{resource_type}"),
        ))
    verdict = VERDICT[finding.verdict]
    return DecisionRecord(
        action=ActionDescription(
            family="shell", host="claude_code", tool="Bash", raw=command,
            working_directory=cwd, working_directory_source="launch",
            parse_status="unparseable" if (unparseable or is_windows_rule) else "parsed",
            opaque=report.opaque[:50], targets=targets,
        ),
        judgment=Judgment(
            verdict=verdict, floor_verdict=verdict, decided_by="floor",
            rule_id=finding.rule or None, ceiling_version=2, enforcement="mandatory",
            reason=finding.reason or "No floor rule matched.",
            agent_guidance=finding.reason if verdict in {"block", "confirm_required"} else None,
        ),
    )


def load(name: str) -> list[dict]:
    path = GATE2B / name
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


@unittest.skipUnless(HAVE_BASHLEX, "bashlex not installed; run with `uv run --with bashlex`")
class Gate2bFitTests(unittest.TestCase):
    def test_every_incident_fits_the_record(self) -> None:
        incidents = load("set_incidents.jsonl")
        self.assertGreaterEqual(len(incidents), 15)
        for case in incidents:
            with self.subTest(case["id"]):
                record = bridge(case["command"], case["cwd"], case.get("environment", "dev"), case.get("home"))
                # Round trip through JSON: nothing lives outside the schema.
                again = DecisionRecord.model_validate_json(record.model_dump_json())
                self.assertEqual(again.content_sha256(), record.content_sha256())
                if case.get("rule") != "pass_by_design":
                    self.assertIn(record.judgment.verdict, {"confirm_required", "block"}, case["command"])
                    self.assertTrue(record.judgment.agent_guidance)
                    self.assertTrue(record.judgment.rule_id)
                    # The dangerous fact is on a target, not only in prose.
                    self.assertTrue(record.action.targets, case["command"])

    def test_hard_twins_fit_including_unparseable_and_windows(self) -> None:
        for case in load("set_hard_twins.jsonl"):
            with self.subTest(case["id"]):
                record = bridge(case["command"], case["cwd"], case.get("environment", "dev"), case.get("home"))
                DecisionRecord.model_validate_json(record.model_dump_json())

    def test_every_catchable_incident_carries_its_dangerous_fact_on_a_target(self) -> None:
        """The reason the schema exists: 'show me every decision that touched home'
        is a query over target facts, not a search through prose."""
        summary = {}
        for case in load("set_incidents.jsonl"):
            if case.get("rule") == "pass_by_design":
                continue
            record = bridge(case["command"], case["cwd"], case.get("environment", "dev"), case.get("home"))
            dangerous_zones = [z for z in record.action.zones if z not in {"inside", "temp", "dynamic"}]
            resources = [t.resource.resource_type for t in record.action.targets if t.resource is not None]
            summary[case["id"]] = (dangerous_zones, resources)
            with self.subTest(case["id"]):
                self.assertTrue(dangerous_zones or resources, (case["command"], summary[case["id"]]))
        self.assertGreaterEqual(sum(1 for z, _ in summary.values() if "home" in z or "root" in z), 6, summary)
        self.assertGreaterEqual(sum(1 for _, r in summary.values() if "database" in " ".join(r)), 2, summary)


if __name__ == "__main__":
    unittest.main()
