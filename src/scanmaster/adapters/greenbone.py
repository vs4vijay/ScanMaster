from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, cast
from xml.etree.ElementTree import Element

from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from scanmaster.domain.runs import Finding, RunState, Severity
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class GreenboneAdapter:
    supported_target_kinds = frozenset({TargetKind.HOSTNAME, TargetKind.IP_ADDRESS, TargetKind.CIDR})
    supports_durable_detach = True

    def __init__(
        self,
        username: str,
        password: str,
        *,
        socket_path: str | None = None,
        host: str | None = None,
        port: int = 9390,
        timeout: float = 30,
        scanner_id: str | None = None,
        scan_config_id: str | None = None,
        session_factory: Callable[[], AbstractContextManager[Any]] | None = None,
    ) -> None:
        self._username = username
        self._password = password
        self._scanner_id = scanner_id
        self._scan_config_id = scan_config_id
        self._session_factory: Callable[[], AbstractContextManager[Any]]
        if session_factory is None:
            connection = (
                TLSConnection(hostname=host, port=port, timeout=timeout)
                if host
                else UnixSocketConnection(path=socket_path, timeout=timeout)
            )
            transform = EtreeCheckCommandTransform()  # type: ignore[no-untyped-call]
            self._session_factory = cast(
                Callable[[], AbstractContextManager[Any]], lambda: GMP(connection, transform=transform)
            )
        else:
            self._session_factory = session_factory

    def submit(self, target: Target) -> Submission:
        if target.kind not in self.supported_target_kinds:
            raise ValueError("Greenbone accepts hostname, IP, and CIDR targets only")
        with self._session_factory() as gmp:
            gmp.authenticate(self._username, self._password)
            scanner_id = self._scanner_id or self._first_id(gmp.get_scanners(), "scanner", "scanner")
            config_id = self._scan_config_id or self._first_id(gmp.get_scan_configs(), "config", "scan config")
            target_response = gmp.create_target(f"ScanMaster {target.canonical}", hosts=[target.canonical])
            target_id = self._response_id(target_response, "target")
            task_response = gmp.create_task(f"ScanMaster {target.canonical}", config_id, target_id, scanner_id)
            task_id = self._response_id(task_response, "task")
            start_response = gmp.start_task(task_id)
            report_id = self._child_text(start_response, "report_id")
        return Submission(f"{task_id}:{report_id}", {"task_id": task_id, "report_id": report_id})

    def status(self, external_id: str) -> ScannerSnapshot:
        task_id, _, report_id = external_id.partition(":")
        with self._session_factory() as gmp:
            gmp.authenticate(self._username, self._password)
            task = gmp.get_task(task_id)
            status = (task.findtext(".//status") or "").lower()
            if status in {"stopped", "interrupted", "internal error", "delete requested"}:
                return ScannerSnapshot(RunState.FAILED, raw=self._safe_xml(task), error=status)
            if status not in {"done"}:
                return ScannerSnapshot(RunState.RUNNING, raw=self._safe_xml(task))
            report = gmp.get_report(report_id, details=True, ignore_pagination=True)
            findings = tuple(self._finding(item) for item in report.findall(".//result"))
            return ScannerSnapshot(RunState.COMPLETED, findings, self._safe_xml(report))

    def cancel(self, external_id: str) -> object:
        task_id = external_id.partition(":")[0]
        with self._session_factory() as gmp:
            gmp.authenticate(self._username, self._password)
            response = gmp.stop_task(task_id)
            return self._safe_xml(response)

    @staticmethod
    def _first_id(response: Element, tag: str, label: str) -> str:
        item = response.find(f".//{tag}")
        if item is None or not item.get("id"):
            raise RuntimeError(f"Greenbone did not return an available {label}")
        return str(item.get("id"))

    @staticmethod
    def _response_id(response: Element, label: str) -> str:
        value = response.get("id")
        if not value:
            raise RuntimeError(f"Greenbone did not return a {label} identifier")
        return value

    @staticmethod
    def _child_text(response: Element, tag: str) -> str:
        value = response.findtext(f".//{tag}")
        if not value:
            raise RuntimeError(f"Greenbone did not return {tag}")
        return value

    @staticmethod
    def _safe_xml(element: Element) -> dict[str, object]:
        return {"tag": element.tag, "status": element.get("status"), "status_text": element.get("status_text")}

    @staticmethod
    def _finding(item: Element) -> Finding:
        threat = (item.findtext("threat") or "unknown").lower()
        mapping = {"log": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}
        score_text = item.findtext("severity")
        nvt = item.find("nvt")
        return Finding(
            native_id=item.get("id") or (nvt.get("oid") if nvt is not None else None) or "unknown",
            title=item.findtext("name") or "Untitled Greenbone finding",
            severity=mapping.get(threat, Severity.UNKNOWN),
            description=item.findtext("description"),
            location=item.findtext("host"),
            evidence=item.findtext("description"),
            cvss_score=float(score_text) if score_text else None,
        )
