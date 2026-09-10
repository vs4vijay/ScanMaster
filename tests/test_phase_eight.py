from pathlib import Path

from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.application.scans import StartScan
from scanmaster.domain.runs import RunState
from scanmaster.domain.targets import Target
from scanmaster.entrypoints.library import EventCollector, NonCliScanAdapter
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class NonCliFixtureScanner:
    def submit(self, target: Target) -> Submission:
        return Submission("job-1", {"target": target.canonical})

    def status(self, external_id: str) -> ScannerSnapshot:
        return ScannerSnapshot(RunState.COMPLETED, raw={"job": external_id})

    def cancel(self, external_id: str) -> object:
        return {}


def test_non_cli_adapter_consumes_progress_without_typer_or_rich(tmp_path: Path) -> None:
    repository = SqliteRunRepository(tmp_path / "state.db")
    artifacts = FilesystemArtifactStore(tmp_path / "artifacts", repository)
    events = EventCollector()
    use_case = StartScan(repository, artifacts, NonCliFixtureScanner(), 0.01, 1, events)

    run = NonCliScanAdapter(use_case).scan("https://example.test", "zap")

    assert run.state is RunState.COMPLETED
    assert [event.kind for event in events.events] == ["run.created", "run.submitted", "run.finished"]
    source = Path(__file__).parents[1] / "src" / "scanmaster" / "entrypoints" / "library.py"
    text = source.read_text(encoding="utf-8")
    assert "typer" not in text.lower()
    assert "rich" not in text.lower()
