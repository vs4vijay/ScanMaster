from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

from scanmaster.domain.normalization import deduplicate
from scanmaster.domain.runs import RunState, ScanRun, utc_now
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target
from scanmaster.ports.progress import ProgressEvent, ProgressSink
from scanmaster.ports.runs import ArtifactStore, RunRepository
from scanmaster.ports.scan_execution import ScannerExecutionPort


@dataclass(frozen=True, slots=True)
class StartScanRequest:
    target: str
    scanner: str


@dataclass(frozen=True, slots=True)
class ScanBinding:
    name: str
    adapter: ScannerExecutionPort
    target_kinds: frozenset[TargetKind]
    supports_durable_detach: bool


@dataclass(frozen=True, slots=True)
class StartScansRequest:
    target: str
    scanners: tuple[str, ...]
    detach: bool = False
    active: bool = False
    confirm_authorized: bool = False


class StartScan:
    def __init__(
        self,
        repository: RunRepository,
        artifacts: ArtifactStore,
        adapter: ScannerExecutionPort,
        polling_interval: float,
        timeout: float,
        progress: ProgressSink | None = None,
    ) -> None:
        self._repository = repository
        self._artifacts = artifacts
        self._adapter = adapter
        self._polling_interval = polling_interval
        self._timeout = timeout
        self._progress = progress

    def execute(self, request: StartScanRequest) -> ScanRun:
        if request.scanner not in {"zap", "nuclei"}:
            raise ValueError(f"scanner is not available for scanning: {request.scanner}")
        target = Target.parse(request.target)
        if request.scanner == "zap" and target.kind is not TargetKind.URL:
            raise ValueError("ZAP accepts URL targets only")
        now = utc_now()
        run = ScanRun(str(uuid.uuid4()), request.scanner, target, RunState.PENDING, now, now)
        self._repository.create(run)
        if self._progress:
            self._progress.publish(ProgressEvent("run.created", run.id, now))
        try:
            submission = self._adapter.submit(target)
            self._repository.set_state(run.id, RunState.RUNNING, external_id=submission.external_id)
            if self._progress:
                self._progress.publish(ProgressEvent("run.submitted", submission.external_id, utc_now()))
            self._artifacts.write_json(run.id, "submission", submission.raw)
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                snapshot = self._adapter.status(submission.external_id)
                self._artifacts.write_json(run.id, "latest-status", snapshot.raw)
                if snapshot.state is RunState.RUNNING:
                    time.sleep(self._polling_interval)
                    continue
                findings = tuple(
                    finding if finding.sources else replace(finding, sources=(request.scanner,))
                    for finding in snapshot.findings
                )
                self._repository.replace_findings(run.id, deduplicate(target, findings))
                self._repository.set_state(run.id, snapshot.state, error=snapshot.error)
                break
            else:
                self._repository.set_state(run.id, RunState.FAILED, error="scan execution timed out")
        except Exception as error:
            self._repository.set_state(run.id, RunState.FAILED, error=f"{type(error).__name__}: {error}")
        result = self._repository.get(run.id)
        assert result is not None
        if self._progress:
            self._progress.publish(ProgressEvent("run.finished", result.state.value, utc_now()))
        return result


class StartScans:
    """Preflights the complete request, then runs scanner workflows concurrently."""

    def __init__(
        self,
        repository: RunRepository,
        artifacts: ArtifactStore,
        bindings: dict[str, ScanBinding],
        polling_interval: float,
        timeout: float,
    ) -> None:
        self._repository = repository
        self._artifacts = artifacts
        self._bindings = bindings
        self._polling_interval = polling_interval
        self._timeout = timeout

    def execute(self, request: StartScansRequest) -> tuple[ScanRun, ...]:
        if not request.scanners:
            raise ValueError("at least one --scanner is required")
        if len(set(request.scanners)) != len(request.scanners):
            raise ValueError("each scanner may be selected only once")
        if request.active and not request.confirm_authorized:
            raise ValueError("active scans require --active and --confirm-authorized")
        target = Target.parse(request.target)
        selected: list[ScanBinding] = []
        for name in request.scanners:
            binding = self._bindings.get(name)
            if binding is None:
                raise ValueError(f"scanner is not enabled: {name}")
            if target.kind not in binding.target_kinds:
                raise ValueError(f"{name} does not accept {target.kind.value} targets")
            if request.detach and not binding.supports_durable_detach:
                raise ValueError(f"{name} does not support durable detach")
            selected.append(binding)
        if request.detach:
            runs: list[ScanRun] = []
            for binding in selected:
                now = utc_now()
                run = ScanRun(str(uuid.uuid4()), binding.name, target, RunState.PENDING, now, now)
                self._repository.create(run)
                try:
                    submission = binding.adapter.submit(target)
                    self._repository.set_state(run.id, RunState.RUNNING, external_id=submission.external_id)
                    self._artifacts.write_json(run.id, "submission", submission.raw)
                except Exception as error:
                    self._repository.set_state(run.id, RunState.FAILED, error=f"{type(error).__name__}: {error}")
                persisted = self._repository.get(run.id)
                assert persisted is not None
                runs.append(persisted)
            return tuple(runs)

        def execute(binding: ScanBinding) -> ScanRun:
            return StartScan(
                self._repository,
                self._artifacts,
                binding.adapter,
                self._polling_interval,
                self._timeout,
            ).execute(StartScanRequest(request.target, binding.name))

        with ThreadPoolExecutor(max_workers=len(selected), thread_name_prefix="scanmaster") as executor:
            futures = [executor.submit(execute, binding) for binding in selected]
            return tuple(future.result() for future in futures)


class GetRun:
    def __init__(self, repository: RunRepository) -> None:
        self._repository = repository

    def execute(self, run_id: str) -> ScanRun:
        run = self._repository.get(run_id)
        if run is None:
            raise KeyError(run_id)
        return run


class RefreshRun:
    """Refresh a durable scanner job and persist its latest snapshot."""

    def __init__(
        self,
        repository: RunRepository,
        artifacts: ArtifactStore,
        adapters: dict[str, ScannerExecutionPort],
    ) -> None:
        self._repository = repository
        self._artifacts = artifacts
        self._adapters = adapters

    def execute(self, run_id: str) -> ScanRun:
        run = GetRun(self._repository).execute(run_id)
        if run.state is not RunState.RUNNING or not run.external_id:
            return run
        adapter = self._adapters.get(run.scanner)
        if adapter is None:
            raise ValueError(f"scanner is not enabled for status refresh: {run.scanner}")
        snapshot = adapter.status(run.external_id)
        self._artifacts.write_json(run.id, "latest-status", snapshot.raw)
        if snapshot.state is not RunState.RUNNING:
            self._repository.replace_findings(run.id, snapshot.findings)
            self._repository.set_state(run.id, snapshot.state, error=snapshot.error)
        return GetRun(self._repository).execute(run.id)


class CancelRun:
    def __init__(
        self, repository: RunRepository, adapters: dict[str, ScannerExecutionPort] | ScannerExecutionPort
    ) -> None:
        self._repository = repository
        self._adapters = adapters

    def execute(self, run_id: str) -> ScanRun:
        run = GetRun(self._repository).execute(run_id)
        if run.state not in {RunState.PENDING, RunState.RUNNING}:
            raise ValueError(f"run cannot be cancelled from state {run.state.value}")
        adapter = self._adapters.get(run.scanner) if isinstance(self._adapters, dict) else self._adapters
        if adapter is None:
            raise ValueError(f"scanner is not enabled for cancellation: {run.scanner}")
        if run.external_id:
            adapter.cancel(run.external_id)
        self._repository.set_state(run.id, RunState.CANCELLED)
        return GetRun(self._repository).execute(run.id)
