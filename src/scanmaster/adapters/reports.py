from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from scanmaster.domain.runs import ScanRun


def run_as_dict(run: ScanRun) -> dict[str, object]:
    return {
        "id": run.id,
        "scanner": run.scanner,
        "target": {"kind": run.target.kind.value, "value": run.target.value, "canonical": run.target.canonical},
        "state": run.state.value,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
        "external_id": run.external_id,
        "error": run.error,
        "findings": [{**asdict(item), "severity": item.severity.value} for item in run.findings],
    }


def render_json(run: ScanRun) -> str:
    return json.dumps(run_as_dict(run), indent=2, sort_keys=True)


def render_terminal(run: ScanRun, console: Console) -> None:
    console.print(f"[bold]Run {run.id}[/bold]  {run.state.value}  {run.scanner}  {run.target.canonical}")
    if run.error:
        console.print(f"[red]{run.error}[/red]")
    table = Table("Severity", "Finding", "Location")
    for finding in run.findings:
        table.add_row(finding.severity.value, finding.title, finding.location or "-")
    console.print(table)
