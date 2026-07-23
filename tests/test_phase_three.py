import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scanmaster.adapters.nuclei import NucleiAdapter, NucleiPolicy
from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.application.scans import ScanBinding, StartScans, StartScansRequest
from scanmaster.domain.runs import Finding, RunState, Severity
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target
from scanmaster.ports.scan_execution import ScannerSnapshot, Submission


class CompletedAdapter:
    def __init__(self, fails: bool = False) -> None:
        self.fails = fails
        self.submissions = 0

    def submit(self, target: Target) -> Submission:
        self.submissions += 1
        if self.fails:
            raise RuntimeError("fixture backend failure")
        return Submission(f"job-{self.submissions}", {"target": target.canonical})

    def status(self, external_id: str) -> ScannerSnapshot:
        return ScannerSnapshot(
            RunState.COMPLETED,
            (Finding(external_id, "fixture", Severity.LOW),),
            {"state": "completed"},
        )

    def cancel(self, external_id: str) -> object:
        return {"cancelled": external_id}


def test_nuclei_jsonl_normalization_and_malformed_input() -> None:
    line = json.dumps(
        {
            "template-id": "CVE-2026-1",
            "matched-at": "https://example.test/a",
            "extracted-results": ["proof"],
            "info": {
                "name": "Issue",
                "severity": "critical",
                "reference": ["https://advisory.test/1"],
                "classification": {
                    "cve-id": ["CVE-2026-1"],
                    "cwe-id": ["CWE-79"],
                    "cvss-score": 9.8,
                    "cvss-metrics": "CVSS:3.1/test",
                },
            },
        }
    )
    finding = NucleiAdapter._parse_jsonl(line)[0]
    assert finding.native_id == "CVE-2026-1"
    assert finding.severity is Severity.CRITICAL
    assert finding.cve_ids == ("CVE-2026-1",)
    assert finding.cvss_score == 9.8
    with pytest.raises(ValueError, match="line 1"):
        NucleiAdapter._parse_jsonl("not-json")


def test_nuclei_policy_and_reproducible_command(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsigned"):
        NucleiPolicy(allow_custom=True).validate()
    with pytest.raises(ValueError, match="intrusive"):
        NucleiPolicy(allow_code=True).validate()
    adapter = NucleiAdapter(
        "image@sha256:digest", tmp_path / "templates", tmp_path / "work", 7, 3, 4, "scanner", NucleiPolicy()
    )
    command = adapter._command(Target.parse("https://example.test"), (tmp_path / "work" / "out.jsonl").resolve())
    assert command[0:3] == ["docker", "run", "--rm"]
    assert "-duc" in command and "-dut" in command
    assert command[command.index("-rate-limit") + 1] == "7"
    assert "code,fuzz,dos" in command


def test_multi_scanner_partial_failure_and_preflight(tmp_path: Path) -> None:
    repository = SqliteRunRepository(tmp_path / "state.db")
    artifacts = FilesystemArtifactStore(tmp_path / "artifacts", repository)
    good = CompletedAdapter()
    bad = CompletedAdapter(fails=True)
    bindings = {
        "zap": ScanBinding("zap", good, frozenset({TargetKind.URL}), True),
        "nuclei": ScanBinding("nuclei", bad, frozenset({TargetKind.URL}), False),
    }
    use_case = StartScans(repository, artifacts, bindings, 0, 1)
    runs = use_case.execute(StartScansRequest("https://example.test", ("zap", "nuclei")))
    assert {run.state for run in runs} == {RunState.COMPLETED, RunState.FAILED}
    assert len(tuple((tmp_path / "artifacts").glob("*/submission.json"))) == 1

    fresh_good = CompletedAdapter()
    preflight = StartScans(
        repository,
        artifacts,
        {"zap": ScanBinding("zap", fresh_good, frozenset({TargetKind.URL}), True)},
        0,
        1,
    )
    with pytest.raises(ValueError, match="does not accept"):
        preflight.execute(StartScansRequest("192.0.2.1", ("zap",)))
    assert fresh_good.submissions == 0
    with pytest.raises(ValueError, match="at least one"):
        preflight.execute(StartScansRequest("https://example.test", ()))
    with pytest.raises(ValueError, match="durable detach"):
        use_case.execute(StartScansRequest("https://example.test", ("nuclei",), detach=True))


def test_nuclei_cli_persists_and_reloads_from_new_process(tmp_path: Path) -> None:
    binary_directory = tmp_path / "bin"
    binary_directory.mkdir()
    docker = binary_directory / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' \'{"template-id":"fixture-template","matched-at":"https://example.test/",'
        '"info":{"name":"Fixture issue","severity":"medium"}}\'\n',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SCANMASTER_")}
    environment.update(
        {
            "PATH": f"{binary_directory}{os.pathsep}{environment['PATH']}",
            "SCANMASTER_NUCLEI_ENABLED": "true",
            "SCANMASTER_DATABASE_PATH": str(tmp_path / "state.db"),
            "SCANMASTER_ARTIFACT_PATH": str(tmp_path / "artifacts"),
            "SCANMASTER_NUCLEI_TEMPLATES_DIRECTORY": str(tmp_path / "templates"),
            "SCANMASTER_POLLING_INTERVAL_SECONDS": "0.01",
        }
    )
    scan = subprocess.run(
        [sys.executable, "-m", "scanmaster", "scan", "https://example.test", "--scanner", "nuclei"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert scan.returncode == 0, scan.stderr
    match = re.search(r"Run ([0-9a-f-]{36})", scan.stdout)
    assert match
    report = subprocess.run(
        [sys.executable, "-m", "scanmaster", "report", match.group(1), "--format", "json"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert report.returncode == 0, report.stderr
    payload = json.loads(report.stdout)
    assert payload["findings"][0]["native_id"] == "fixture-template"
