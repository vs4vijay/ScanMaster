from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from scanmaster.domain.normalization import FINGERPRINT_VERSION, finding_fingerprint
from scanmaster.domain.runs import ScanRun

NORMALIZED_SCHEMA_VERSION = "1.0.0"


def run_as_dict(run: ScanRun) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": NORMALIZED_SCHEMA_VERSION,
        "id": run.id,
        "scanner": run.scanner,
        "target": {"kind": run.target.kind.value, "value": run.target.value, "canonical": run.target.canonical},
        "state": run.state.value,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
        "external_id": run.external_id,
        "error": run.error,
        "findings": [
            {
                **asdict(item),
                "severity": item.severity.value,
                "fingerprint": finding_fingerprint(run.target, item),
                "fingerprint_version": FINGERPRINT_VERSION,
            }
            for item in sorted(run.findings, key=lambda finding: finding_fingerprint(run.target, finding))
        ],
    }
    return payload


def render_json(run: ScanRun) -> str:
    return json.dumps(run_as_dict(run), indent=2, sort_keys=True)


def render_sarif(run: ScanRun) -> str:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for finding in sorted(run.findings, key=lambda item: finding_fingerprint(run.target, item)):
        rule_id = f"{run.scanner}/{finding.native_id}"
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "helpUri": finding.references[0] if finding.references else None,
        }
        fingerprint = finding_fingerprint(run.target, finding)
        result: dict[str, object] = {
            "ruleId": rule_id,
            "level": levels.get(finding.severity.value, "none"),
            "message": {"text": finding.description or finding.title},
            "partialFingerprints": {"scanmaster/v1": fingerprint},
            "properties": {
                "lifecycle": finding.lifecycle,
                "suppressed": finding.suppressed,
                "suppressionReason": finding.suppression_reason,
                "suppressionOwner": finding.suppression_owner,
                "suppressionExpiresAt": (
                    finding.suppression_expires_at.isoformat() if finding.suppression_expires_at else None
                ),
                "enrichment": dict(finding.enrichment),
            },
        }
        if finding.location:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding.location}}}]
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ScanMaster",
                        "semanticVersion": NORMALIZED_SCHEMA_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"{run.scanner}/{run.id}"},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def render_terminal(run: ScanRun, console: Console) -> None:
    console.print(f"[bold]Run {run.id}[/bold]  {run.state.value}  {run.scanner}  {run.target.canonical}")
    if run.error:
        console.print(f"[red]{run.error}[/red]")
    table = Table("Severity", "Finding", "Location")
    for finding in run.findings:
        table.add_row(finding.severity.value, finding.title, finding.location or "-")
    console.print(table)
