from __future__ import annotations

import csv
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from scanmaster.domain.normalization import finding_fingerprint
from scanmaster.domain.policy import ScanPolicy
from scanmaster.domain.runs import Finding, ScanRun


def compare_runs(current: ScanRun, baseline: ScanRun) -> ScanRun:
    if current.scanner != baseline.scanner or current.target.canonical != baseline.target.canonical:
        raise ValueError("baseline is incompatible: scanner and canonical target must match")
    current_by_id = {finding_fingerprint(current.target, item): item for item in current.findings}
    baseline_by_id = {finding_fingerprint(baseline.target, item): item for item in baseline.findings}
    findings = [
        replace(item, lifecycle="recurring" if fingerprint in baseline_by_id else "new")
        for fingerprint, item in current_by_id.items()
    ]
    findings.extend(
        replace(item, lifecycle="resolved")
        for fingerprint, item in baseline_by_id.items()
        if fingerprint not in current_by_id
    )
    return replace(
        current, findings=tuple(sorted(findings, key=lambda item: finding_fingerprint(current.target, item)))
    )


def apply_suppressions(run: ScanRun, policy: ScanPolicy, now: datetime) -> ScanRun:
    suppressions = {item.fingerprint: item for item in policy.suppressions}
    findings: list[Finding] = []
    for finding in run.findings:
        suppression = suppressions.get(finding_fingerprint(run.target, finding))
        if suppression is None:
            findings.append(finding)
            continue
        findings.append(
            replace(
                finding,
                suppressed=suppression.expires > now,
                suppression_reason=suppression.reason,
                suppression_owner=suppression.owner,
                suppression_expires_at=suppression.expires,
            )
        )
    return replace(run, findings=tuple(findings))


def enrich_from_cache(run: ScanRun, kev_path: Path | None, epss_path: Path | None) -> ScanRun:
    kev: set[str] = set()
    epss: dict[str, str] = {}
    try:
        if kev_path and kev_path.exists():
            payload = json.loads(kev_path.read_text(encoding="utf-8"))
            kev = {str(item["cveID"]) for item in payload.get("vulnerabilities", [])}
        if epss_path and epss_path.exists():
            with epss_path.open(encoding="utf-8") as stream:
                epss = {row["cve"]: row["epss"] for row in csv.DictReader(stream) if row.get("cve")}
    except OSError, ValueError, KeyError, TypeError:
        return run
    findings = []
    for finding in run.findings:
        metadata: list[tuple[str, str]] = []
        for cve in finding.cve_ids:
            if cve in kev:
                metadata.append(("cisa_kev", "true"))
            if cve in epss:
                metadata.append(("first_epss", epss[cve]))
        findings.append(replace(finding, enrichment=tuple(metadata)))
    return replace(run, findings=tuple(findings))
