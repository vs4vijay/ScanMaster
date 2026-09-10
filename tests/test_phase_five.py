from contextlib import contextmanager
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import fromstring

import httpx
import pytest

from scanmaster.adapters.greenbone import GreenboneAdapter
from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.adapters.rapid7 import Rapid7Adapter
from scanmaster.application.scans import RefreshRun, ScanBinding, StartScans, StartScansRequest
from scanmaster.domain.runs import RunState
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target


class FakeGmp:
    def authenticate(self, username: str, password: str) -> None:
        assert (username, password) == ("user", "password")

    def get_scanners(self) -> Any:
        return fromstring('<get_scanners_response><scanner id="scanner-1"/></get_scanners_response>')

    def get_scan_configs(self) -> Any:
        return fromstring('<get_configs_response><config id="config-1"/></get_configs_response>')

    def create_target(self, name: str, *, hosts: list[str]) -> Any:
        assert hosts == ["192.0.2.0/24"]
        return fromstring('<create_target_response id="target-1"/>')

    def create_task(self, name: str, config_id: str, target_id: str, scanner_id: str) -> Any:
        assert (config_id, target_id, scanner_id) == ("config-1", "target-1", "scanner-1")
        return fromstring('<create_task_response id="task-1"/>')

    def start_task(self, task_id: str) -> Any:
        return fromstring("<start_task_response><report_id>report-1</report_id></start_task_response>")

    def get_task(self, task_id: str) -> Any:
        return fromstring("<get_tasks_response><task><status>Done</status></task></get_tasks_response>")

    def get_report(self, report_id: str, **_: object) -> Any:
        return fromstring(
            '<report><result id="finding-1"><name>Example</name><threat>High</threat>'
            "<severity>8.1</severity><host>192.0.2.2</host></result></report>"
        )

    def stop_task(self, task_id: str) -> Any:
        return fromstring('<stop_task_response status="200"/>')


@contextmanager
def gmp_session() -> Any:
    yield FakeGmp()


def test_greenbone_durable_lifecycle() -> None:
    adapter = GreenboneAdapter("user", "password", session_factory=gmp_session)
    submission = adapter.submit(Target.parse("192.0.2.0/24"))
    assert submission.external_id == "task-1:report-1"
    snapshot = adapter.status(submission.external_id)
    assert snapshot.state is RunState.COMPLETED
    assert snapshot.findings[0].cvss_score == 8.1
    assert adapter.cancel(submission.external_id) == {"tag": "stop_task_response", "status": "200", "status_text": None}


def test_rapid7_contract_and_url_rejection() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        responses = {
            "/api/3/administration/info": {},
            "/api/3/sites": {"id": 7},
            "/api/3/sites/7/scans": {"id": 8},
            "/api/3/scans/8": {"status": "finished"},
            "/api/3/scans/8/vulnerabilities": {
                "resources": [{"id": "v1", "title": "Issue", "severity": "high", "cvssScore": 8.0}]
            },
            "/api/3/scans/8/stop": {},
        }
        return httpx.Response(200, json=responses[request.url.path])

    adapter = Rapid7Adapter("https://rapid7.test", "user", "password")
    adapter._client = httpx.Client(  # type: ignore[attr-defined]
        base_url="https://rapid7.test/api/3", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ValueError, match="hostname, IP, and CIDR"):
        adapter.submit(Target.parse("https://example.test"))
    submission = adapter.submit(Target.parse("192.0.2.1"))
    assert submission.external_id == "8"
    assert adapter.status("8").findings[0].severity.value == "high"
    adapter.cancel("8")
    assert requests[0] == "/api/3/administration/info"


def test_infrastructure_adapters_are_durable() -> None:
    assert GreenboneAdapter.supports_durable_detach
    assert Rapid7Adapter.supports_durable_detach


class DurableFixture:
    def submit(self, target: Target) -> Any:
        return type("Submission", (), {"external_id": "external-1", "raw": {"submitted": True}})()

    def status(self, external_id: str) -> Any:
        return type(
            "Snapshot",
            (),
            {"state": RunState.COMPLETED, "findings": (), "raw": {"done": True}, "error": None},
        )()

    def cancel(self, external_id: str) -> object:
        return {}


def test_detached_run_refreshes_from_fresh_use_case(tmp_path: Path) -> None:
    repository = SqliteRunRepository(tmp_path / "state.db")
    artifacts = FilesystemArtifactStore(tmp_path / "artifacts", repository)
    adapter = DurableFixture()
    binding = ScanBinding("greenbone", adapter, frozenset({TargetKind.IP_ADDRESS}), True)
    run = StartScans(repository, artifacts, {"greenbone": binding}, 0.01, 1).execute(
        StartScansRequest("192.0.2.1", ("greenbone",), detach=True)
    )[0]
    assert run.state is RunState.RUNNING
    assert run.external_id == "external-1"
    refreshed = RefreshRun(repository, artifacts, {"greenbone": adapter}).execute(run.id)
    assert refreshed.state is RunState.COMPLETED
    assert (tmp_path / "artifacts" / run.id / "latest-status.json").exists()
