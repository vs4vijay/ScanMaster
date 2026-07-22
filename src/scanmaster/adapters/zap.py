from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import httpx

from scanmaster.domain.runs import Finding, RunState, Severity
from scanmaster.domain.targets import Target
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class ZapAdapter:
    """ZAP Automation Framework API boundary for passive URL scans."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        verify: bool,
        timeout: float,
        plan_host_directory: Path = Path(".scanmaster/zap-plans"),
        plan_container_directory: Path = Path("/zap/wrk"),
    ) -> None:
        self._client = httpx.Client(base_url=base_url.rstrip("/"), verify=verify, timeout=timeout)
        self._api_key = api_key
        self._plan_host_directory = plan_host_directory
        self._plan_container_directory = plan_container_directory

    def _params(self, **values: str) -> dict[str, str]:
        if self._api_key:
            values["apikey"] = self._api_key
        return values

    def submit(self, target: Target) -> Submission:
        if target.kind.value != "url":
            raise ValueError("ZAP accepts URL targets only")
        plan = {
            "env": {"contexts": [{"name": "scanmaster", "urls": [target.canonical]}]},
            "jobs": [
                {"type": "spider", "parameters": {"context": "scanmaster", "url": target.canonical}},
                {"type": "passiveScan-wait", "parameters": {"maxDuration": 0}},
            ],
        }
        self._plan_host_directory.mkdir(parents=True, exist_ok=True)
        filename = f"scanmaster-{uuid.uuid4()}.json"
        host_plan_path = self._plan_host_directory / filename
        host_plan_path.write_text(json.dumps(plan), encoding="utf-8")
        container_plan_path = self._plan_container_directory / filename
        response = self._client.get(
            "/JSON/automation/action/runPlan/", params=self._params(filePath=str(container_plan_path))
        )
        response.raise_for_status()
        payload: Any = response.json()
        plan_id = str(payload.get("planId") or payload.get("planid") or payload.get("id") or "")
        if not plan_id:
            raise RuntimeError("ZAP did not return an Automation Framework plan identifier")
        return Submission(plan_id, {"plan_id": plan_id, "plan": plan, "response": payload})

    def status(self, external_id: str) -> ScannerSnapshot:
        response = self._client.get("/JSON/automation/view/planProgress/", params=self._params(planId=external_id))
        response.raise_for_status()
        payload: Any = response.json()
        errors = payload.get("error") or []
        state_text = str(payload.get("state") or payload.get("status") or "").lower()
        if errors or state_text in {"failed", "error", "stopped"}:
            detail = "; ".join(str(item) for item in errors) if isinstance(errors, list) else str(errors)
            return ScannerSnapshot(RunState.FAILED, raw=payload, error=detail or state_text)
        finished = bool(payload.get("finished")) or state_text in {"completed", "complete", "finished"}
        if not finished:
            return ScannerSnapshot(RunState.RUNNING, raw=payload)
        alerts_response = self._client.get("/JSON/core/view/alerts/", params=self._params(start="0", count="0"))
        alerts_response.raise_for_status()
        alerts_payload: Any = alerts_response.json()
        findings = tuple(self._finding(alert) for alert in alerts_payload.get("alerts", []))
        return ScannerSnapshot(RunState.COMPLETED, findings, {"progress": payload, "alerts": alerts_payload})

    def cancel(self, external_id: str) -> object:
        response = self._client.get("/JSON/automation/action/stopPlan/", params=self._params(planId=external_id))
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _finding(alert: dict[str, Any]) -> Finding:
        risk = str(alert.get("risk") or alert.get("riskdesc") or "unknown").split()[0].lower()
        severity = Severity(risk) if risk in Severity else Severity.UNKNOWN
        return Finding(
            native_id=str(alert.get("pluginId") or alert.get("alertRef") or alert.get("id") or "unknown"),
            title=str(alert.get("name") or alert.get("alert") or "Untitled ZAP finding"),
            severity=severity,
            description=alert.get("description") or alert.get("desc"),
            remediation=alert.get("solution"),
            location=alert.get("url"),
            evidence=alert.get("evidence"),
        )
