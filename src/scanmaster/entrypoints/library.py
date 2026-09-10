"""Minimal non-CLI composition surface proving UI-independent use-case reuse."""

from dataclasses import dataclass, field

from scanmaster.application.scans import StartScan, StartScanRequest
from scanmaster.domain.runs import ScanRun
from scanmaster.ports.progress import ProgressEvent, ProgressSink


@dataclass(slots=True)
class EventCollector(ProgressSink):
    events: list[ProgressEvent] = field(default_factory=list)

    def publish(self, event: ProgressEvent) -> None:
        self.events.append(event)


class NonCliScanAdapter:
    def __init__(self, use_case: StartScan) -> None:
        self._use_case = use_case

    def scan(self, target: str, scanner: str) -> ScanRun:
        return self._use_case.execute(StartScanRequest(target, scanner))
