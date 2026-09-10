from __future__ import annotations

from typing import Any

import httpx

from scanmaster.domain.runs import Finding, RunState, Severity
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class Rapid7Adapter:
    supported_target_kinds = frozenset({TargetKind.HOSTNAME, TargetKind.IP_ADDRESS, TargetKind.CIDR})
    supports_durable_detach = True

    def __init__(self, base_url: str, username: str, password: str, verify: bool = True, timeout: float = 30) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/") + "/api/3",
            auth=httpx.BasicAuth(username, password),
            verify=verify,
            timeout=timeout,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    def health(self) -> None:
        response = self._client.get("/administration/info")
        response.raise_for_status()

    def submit(self, target: Target) -> Submission:
        if target.kind not in self.supported_target_kinds:
            raise ValueError("Rapid7 accepts hostname, IP, and CIDR targets only")
        self.health()
        site_response = self._client.post(
            "/sites",
            json={
                "name": f"ScanMaster {target.canonical}",
                "scan": {"assets": {"includedTargets": [target.canonical]}},
            },
        )
        site_response.raise_for_status()
        site: Any = site_response.json()
        site_id = site.get("id")
        if site_id is None:
            raise RuntimeError("Rapid7 did not return a site identifier")
        scan_response = self._client.post(f"/sites/{site_id}/scans")
        scan_response.raise_for_status()
        scan: Any = scan_response.json()
        scan_id = scan.get("id")
        if scan_id is None:
            raise RuntimeError("Rapid7 did not return a scan identifier")
        return Submission(str(scan_id), {"site": site, "scan": scan})

    def status(self, external_id: str) -> ScannerSnapshot:
        response = self._client.get(f"/scans/{external_id}")
        response.raise_for_status()
        payload: Any = response.json()
        status = str(payload.get("status", "")).lower()
        if status in {"aborted", "error", "failed", "stopped"}:
            return ScannerSnapshot(RunState.FAILED, raw=payload, error=status)
        if status not in {"finished", "completed"}:
            return ScannerSnapshot(RunState.RUNNING, raw=payload)
        findings_response = self._client.get(f"/scans/{external_id}/vulnerabilities")
        findings_response.raise_for_status()
        raw_findings: Any = findings_response.json()
        resources = raw_findings.get("resources", [])
        findings = tuple(self._finding(item) for item in resources if isinstance(item, dict))
        return ScannerSnapshot(RunState.COMPLETED, findings, {"scan": payload, "vulnerabilities": raw_findings})

    def cancel(self, external_id: str) -> object:
        response = self._client.post(f"/scans/{external_id}/stop")
        response.raise_for_status()
        return response.json() if response.content else {}

    @staticmethod
    def _finding(item: dict[str, Any]) -> Finding:
        severity_text = str(item.get("severity", "unknown")).lower()
        severity = Severity(severity_text) if severity_text in Severity else Severity.UNKNOWN
        return Finding(
            native_id=str(item.get("id", "unknown")),
            title=str(item.get("title") or item.get("name") or "Untitled Rapid7 finding"),
            severity=severity,
            description=item.get("description"),
            remediation=item.get("solution"),
            location=item.get("asset") or item.get("uri"),
            cve_ids=tuple(str(value) for value in item.get("cves", [])),
            cvss_score=float(item["cvssScore"]) if item.get("cvssScore") is not None else None,
            cvss_vector=item.get("cvssVector"),
        )
