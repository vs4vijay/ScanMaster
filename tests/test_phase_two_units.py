import json
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.adapters.reports import render_json, render_terminal
from scanmaster.adapters.zap import ZapAdapter
from scanmaster.application.scans import CancelRun, GetRun, StartScan, StartScanRequest
from scanmaster.domain.runs import Finding, RunState, ScanRun, Severity, utc_now
from scanmaster.domain.targets import Target
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class FakeAdapter:
    def __init__(self) -> None:
        self.polls = 0
        self.cancelled: str | None = None

    def submit(self, target: Target) -> Submission:
        return Submission("external-1", {"target": target.canonical})

    def status(self, external_id: str) -> ScannerSnapshot:
        self.polls += 1
        if self.polls == 1:
            return ScannerSnapshot(RunState.RUNNING, raw={"state": "running"})
        return ScannerSnapshot(
            RunState.COMPLETED,
            (Finding("zap-1", "Header", Severity.LOW, location="https://example.test/"),),
            {"state": "completed"},
        )

    def cancel(self, external_id: str) -> object:
        self.cancelled = external_id
        return {"ok": True}


def infrastructure(tmp_path: Path) -> tuple[SqliteRunRepository, FilesystemArtifactStore]:
    repository = SqliteRunRepository(tmp_path / "nested" / "state.db")
    return repository, FilesystemArtifactStore(tmp_path / "artifacts", repository)


def test_scan_use_case_repository_artifacts_and_reports(tmp_path: Path) -> None:
    repository, artifacts = infrastructure(tmp_path)
    adapter = FakeAdapter()
    result = StartScan(repository, artifacts, adapter, 0, 2).execute(
        StartScanRequest("https://EXAMPLE.test:443", "zap")
    )
    assert result.state is RunState.COMPLETED
    assert result.external_id == "external-1"
    assert result.findings[0].native_id == "zap-1"
    assert GetRun(repository).execute(result.id) == result
    assert json.loads(render_json(result))["state"] == "completed"
    console = Console(record=True)
    render_terminal(result, console)
    assert "Header" in console.export_text()
    assert (tmp_path / "artifacts" / result.id / "latest-status.json").exists()
    redacted_path = artifacts.write_json(result.id, "sensitive", {"Authorization": "Bearer secret", "safe": [1]})
    assert "secret" not in Path(redacted_path).read_text()
    with pytest.raises(KeyError):
        GetRun(repository).execute("missing")


def test_cancellation_and_invalid_states(tmp_path: Path) -> None:
    repository, _ = infrastructure(tmp_path)
    adapter = FakeAdapter()
    now = utc_now()
    running = ScanRun("run-1", "zap", Target.parse("https://example.test"), RunState.RUNNING, now, now, "external-1")
    repository.create(running)
    cancelled = CancelRun(repository, adapter).execute(running.id)
    assert cancelled.state is RunState.CANCELLED
    assert adapter.cancelled == "external-1"
    with pytest.raises(ValueError, match="cannot be cancelled"):
        CancelRun(repository, adapter).execute(running.id)
    with pytest.raises(KeyError):
        repository.set_state("missing", RunState.FAILED)
    with pytest.raises(KeyError):
        repository.replace_findings("missing", ())


def test_scan_validation_and_adapter_failure_are_persisted(tmp_path: Path) -> None:
    repository, artifacts = infrastructure(tmp_path)
    adapter = FakeAdapter()
    use_case = StartScan(repository, artifacts, adapter, 0, 1)
    with pytest.raises(ValueError, match="not available"):
        use_case.execute(StartScanRequest("https://example.test", "nuclei"))
    with pytest.raises(ValueError, match="URL targets only"):
        use_case.execute(StartScanRequest("192.0.2.1", "zap"))

    def fail(_target: Target) -> Submission:
        raise httpx.ConnectError("offline")

    adapter.submit = fail  # type: ignore[method-assign]
    result = use_case.execute(StartScanRequest("https://example.test", "zap"))
    assert result.state is RunState.FAILED
    assert "offline" in (result.error or "")


def test_zap_http_boundary_and_normalization() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("runPlan/"):
            assert "filePath" in request.url.params
            return httpx.Response(200, json={"planId": "p1"})
        if request.url.path.endswith("planProgress/"):
            return httpx.Response(200, json={"status": "finished"})
        if request.url.path.endswith("alerts/"):
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "alertRef": "a1",
                            "alert": "Issue",
                            "riskdesc": "High (High)",
                            "desc": "Details",
                            "solution": "Fix",
                            "url": "https://x/",
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"Result": "OK"})

    adapter = ZapAdapter("https://zap.test", "secret", True, 1, Path("/tmp/scanmaster-zap-test"))
    adapter._client = httpx.Client(base_url="https://zap.test", transport=httpx.MockTransport(handler))  # type: ignore[attr-defined]
    submission = adapter.submit(Target.parse("https://example.test"))
    snapshot = adapter.status(submission.external_id)
    assert snapshot.state is RunState.COMPLETED
    assert snapshot.findings[0].severity is Severity.HIGH
    adapter.cancel(submission.external_id)
    assert len(calls) == 4


@pytest.mark.parametrize(
    ("payload", "state"),
    [
        ({"state": "running"}, RunState.RUNNING),
        ({"state": "failed", "error": "bad plan"}, RunState.FAILED),
    ],
)
def test_zap_nonterminal_status(payload: dict[str, str], state: RunState) -> None:
    adapter = ZapAdapter("https://zap.test", None, True, 1, Path("/tmp/scanmaster-zap-test"))
    adapter._client = httpx.Client(
        base_url="https://zap.test", transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    )  # type: ignore[attr-defined]
    assert adapter.status("p1").state is state


def test_zap_rejects_non_url_and_missing_plan_id() -> None:
    adapter = ZapAdapter("https://zap.test", None, True, 1, Path("/tmp/scanmaster-zap-test"))
    with pytest.raises(ValueError):
        adapter.submit(Target.parse("example.test"))
    adapter._client = httpx.Client(
        base_url="https://zap.test", transport=httpx.MockTransport(lambda _: httpx.Response(200, json={}))
    )  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="identifier"):
        adapter.submit(Target.parse("https://example.test"))
