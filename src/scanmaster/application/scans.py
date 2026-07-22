from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from scanmaster.domain.runs import RunState, ScanRun, utc_now
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target
from scanmaster.ports.runs import ArtifactStore, RunRepository
from scanmaster.ports.scan_execution import ScannerExecutionPort


@dataclass(frozen=True, slots=True)
class StartScanRequest:
    target: str
    scanner: str


class StartScan:
    def __init__(
        self,
        repository: RunRepository,
        artifacts: ArtifactStore,
        adapter: ScannerExecutionPort,
        polling_interval: float,
        timeout: float,
    ) -> None:
        self._repository = repository
        self._artifacts = artifacts
        self._adapter = adapter
        self._polling_interval = polling_interval
        self._timeout = timeout

    def execute(self, request: StartScanRequest) -> ScanRun:
        if request.scanner != "zap":
            raise ValueError(f"scanner is not available for scanning: {request.scanner}")
        target = Target.parse(request.target)
        if target.kind is not TargetKind.URL:
            raise ValueError("ZAP accepts URL targets only")
        now = utc_now()
        run = ScanRun(str(uuid.uuid4()), request.scanner, target, RunState.PENDING, now, now)
        self._repository.create(run)
        try:
            submission = self._adapter.submit(target)
            self._repository.set_state(run.id, RunState.RUNNING, external_id=submission.external_id)
            self._artifacts.write_json(run.id, "submission", submission.raw)
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                snapshot = self._adapter.status(submission.external_id)
                self._artifacts.write_json(run.id, "latest-status", snapshot.raw)
                if snapshot.state is RunState.RUNNING:
                    time.sleep(self._polling_interval)
                    continue
                self._repository.replace_findings(run.id, snapshot.findings)
                self._repository.set_state(run.id, snapshot.state, error=snapshot.error)
                break
            else:
                self._repository.set_state(run.id, RunState.FAILED, error="scan execution timed out")
        except Exception as error:
            self._repository.set_state(run.id, RunState.FAILED, error=f"{type(error).__name__}: {error}")
        result = self._repository.get(run.id)
        assert result is not None
        return result


class GetRun:
    def __init__(self, repository: RunRepository) -> None:
        self._repository = repository

    def execute(self, run_id: str) -> ScanRun:
        run = self._repository.get(run_id)
        if run is None:
            raise KeyError(run_id)
        return run


class CancelRun:
    def __init__(self, repository: RunRepository, adapter: ScannerExecutionPort) -> None:
        self._repository = repository
        self._adapter = adapter

    def execute(self, run_id: str) -> ScanRun:
        run = GetRun(self._repository).execute(run_id)
        if run.state not in {RunState.PENDING, RunState.RUNNING}:
            raise ValueError(f"run cannot be cancelled from state {run.state.value}")
        if run.external_id:
            self._adapter.cancel(run.external_id)
        self._repository.set_state(run.id, RunState.CANCELLED)
        return GetRun(self._repository).execute(run.id)
