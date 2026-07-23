from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from scanmaster.domain.runs import Finding, RunState, Severity
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class NucleiProfile(StrEnum):
    SAFE = "safe"
    STANDARD = "standard"
    INTRUSIVE = "intrusive"


@dataclass(frozen=True, slots=True)
class NucleiPolicy:
    profile: NucleiProfile = NucleiProfile.SAFE
    allow_unsigned: bool = False
    allow_custom: bool = False
    allow_code: bool = False
    allow_fuzzing: bool = False
    allow_dos: bool = False

    def validate(self) -> None:
        if self.allow_custom and not self.allow_unsigned:
            raise ValueError("custom Nuclei templates require explicit unsigned-template permission")
        if self.profile is not NucleiProfile.INTRUSIVE and any((self.allow_code, self.allow_fuzzing, self.allow_dos)):
            raise ValueError("code, fuzzing, and denial-of-service templates require the intrusive profile")


class NucleiAdapter:
    """Runs the immutable Nuclei container without implicit engine or template updates."""

    supported_target_kinds = frozenset({TargetKind.URL, TargetKind.HOSTNAME, TargetKind.IP_ADDRESS, TargetKind.CIDR})
    supports_durable_detach = False

    def __init__(
        self,
        image: str,
        templates_directory: Path,
        work_directory: Path,
        rate_limit: int,
        concurrency: int,
        request_timeout: int,
        identification_header: str,
        policy: NucleiPolicy,
    ) -> None:
        policy.validate()
        self._image = image
        self._templates = templates_directory.resolve()
        self._work = work_directory.resolve()
        self._rate_limit = rate_limit
        self._concurrency = concurrency
        self._request_timeout = request_timeout
        self._header = identification_header
        self._policy = policy
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._outputs: dict[str, Path] = {}

    def submit(self, target: Target) -> Submission:
        if target.kind not in self.supported_target_kinds:
            raise ValueError(f"Nuclei does not accept {target.kind.value} targets")
        self._templates.mkdir(parents=True, exist_ok=True)
        self._work.mkdir(parents=True, exist_ok=True)
        external_id = str(uuid.uuid4())
        output = self._work / f"{external_id}.jsonl"
        command = self._command(target, output)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # noqa: S603
        self._processes[external_id] = process
        self._outputs[external_id] = output
        return Submission(external_id, {"command": command, "profile": self._policy.profile.value})

    def status(self, external_id: str) -> ScannerSnapshot:
        process = self._processes.get(external_id)
        if process is None:
            raise KeyError(f"unknown or non-recoverable Nuclei job: {external_id}")
        if process.poll() is None:
            return ScannerSnapshot(RunState.RUNNING, raw={"state": "running", "job_id": external_id})
        stdout, stderr = process.communicate()
        raw_lines = (
            self._outputs[external_id].read_text(encoding="utf-8") if self._outputs[external_id].exists() else stdout
        )
        if process.returncode != 0:
            return ScannerSnapshot(
                RunState.FAILED,
                raw={"jsonl": raw_lines, "stderr": stderr, "exit_code": process.returncode},
                error=f"Nuclei exited with status {process.returncode}: {stderr.strip()}",
            )
        try:
            findings = tuple(self._parse_jsonl(raw_lines))
        except ValueError as error:
            return ScannerSnapshot(
                RunState.FAILED,
                raw={"jsonl": raw_lines, "stderr": stderr, "exit_code": process.returncode},
                error=str(error),
            )
        return ScannerSnapshot(
            RunState.COMPLETED,
            findings,
            {"jsonl": raw_lines, "stderr": stderr, "exit_code": process.returncode},
        )

    def cancel(self, external_id: str) -> object:
        process = self._processes.get(external_id)
        if process is None:
            raise KeyError(f"unknown or non-recoverable Nuclei job: {external_id}")
        if process.poll() is None:
            process.terminate()
        return {"cancelled": True, "job_id": external_id}

    def _command(self, target: Target, output: Path) -> list[str]:
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "-v",
            f"{self._templates}:/root/nuclei-templates:ro",
            "-v",
            f"{self._work}:/scanmaster-output:rw",
            self._image,
            "-u",
            target.canonical,
            "-jsonl",
            "-o",
            f"/scanmaster-output/{output.name}",
            "-duc",
            "-rate-limit",
            str(self._rate_limit),
            "-c",
            str(self._concurrency),
            "-timeout",
            str(self._request_timeout),
            "-H",
            f"User-Agent: {self._header}",
        ]
        if not self._policy.allow_unsigned:
            command.append("-dut")
        excluded = ["code", "fuzz", "dos"]
        if self._policy.profile is NucleiProfile.STANDARD:
            excluded = ["code", "fuzz", "dos", "intrusive"]
        elif self._policy.profile is NucleiProfile.INTRUSIVE:
            excluded = []
            if not self._policy.allow_code:
                excluded.append("code")
            if not self._policy.allow_fuzzing:
                excluded.append("fuzz")
            if not self._policy.allow_dos:
                excluded.append("dos")
        if excluded:
            command.extend(("-exclude-tags", ",".join(excluded)))
        return command

    @staticmethod
    def _parse_jsonl(value: str) -> list[Finding]:
        findings: list[Finding] = []
        for number, line in enumerate(value.splitlines(), 1):
            if not line.strip():
                continue
            try:
                payload: Any = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed Nuclei JSONL at line {number}: {error.msg}") from None
            if not isinstance(payload, dict):
                raise ValueError(f"malformed Nuclei JSONL at line {number}: expected an object")
            info = cast(dict[str, Any], payload.get("info")) if isinstance(payload.get("info"), dict) else {}
            classification: dict[str, Any] = (
                cast(dict[str, Any], info.get("classification")) if isinstance(info.get("classification"), dict) else {}
            )
            severity_text = str(info.get("severity") or "unknown").lower()
            severity = Severity(severity_text) if severity_text in Severity else Severity.UNKNOWN
            findings.append(
                Finding(
                    native_id=str(payload.get("template-id") or payload.get("templateID") or "unknown"),
                    title=str(info.get("name") or payload.get("template-id") or "Untitled Nuclei finding"),
                    severity=severity,
                    description=_optional_text(info.get("description")),
                    remediation=_optional_text(info.get("remediation")),
                    location=_optional_text(payload.get("matched-at") or payload.get("host")),
                    evidence=_optional_text(payload.get("extracted-results") or payload.get("matcher-name")),
                    references=_strings(info.get("reference")),
                    cve_ids=_strings(classification.get("cve-id")),
                    cwe_ids=_strings(classification.get("cwe-id")),
                    cvss_score=_optional_float(classification.get("cvss-score")),
                    cvss_vector=_optional_text(classification.get("cvss-metrics")),
                )
            )
        return findings


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return (str(value),)


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return str(value)


def _optional_float(value: object) -> float | None:
    if isinstance(value, (str, int, float)):
        try:
            return float(value)
        except ValueError:
            return None
    return None
