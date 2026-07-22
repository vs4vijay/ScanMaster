from dataclasses import dataclass
from typing import Protocol

from scanmaster.domain.runs import Finding, RunState
from scanmaster.domain.targets import Target


@dataclass(frozen=True, slots=True)
class Submission:
    external_id: str
    raw: object


@dataclass(frozen=True, slots=True)
class ScannerSnapshot:
    state: RunState
    findings: tuple[Finding, ...] = ()
    raw: object = None
    error: str | None = None


class ScannerExecutionPort(Protocol):
    def submit(self, target: Target) -> Submission: ...
    def status(self, external_id: str) -> ScannerSnapshot: ...
    def cancel(self, external_id: str) -> object: ...
