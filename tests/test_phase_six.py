import json
from datetime import UTC, datetime

import pytest

from scanmaster.adapters.reports import render_json, render_sarif
from scanmaster.domain.normalization import deduplicate, finding_fingerprint
from scanmaster.domain.runs import Finding, RunState, ScanRun, Severity
from scanmaster.domain.targets import Target
from scanmaster.entrypoints.cli import _threshold_violated


def fixture_run() -> ScanRun:
    target = Target.parse("https://example.test")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    finding = Finding(
        "native-1",
        "Example issue",
        Severity.HIGH,
        description="Description",
        location="https://example.test/path",
        references=("https://advisory.test/1",),
        cve_ids=("CVE-2026-1",),
        sources=("zap",),
        confidence="high",
    )
    return ScanRun("run-1", "zap", target, RunState.COMPLETED, now, now, findings=(finding,))


def test_normalized_json_and_sarif_are_deterministic() -> None:
    run = fixture_run()
    normalized = json.loads(render_json(run))
    assert normalized["schema_version"] == "1.0.0"
    assert normalized["findings"][0]["fingerprint"] == finding_fingerprint(run.target, run.findings[0])

    first = render_sarif(run)
    assert first == render_sarif(run)
    sarif = json.loads(first)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "zap/native-1"
    assert sarif["runs"][0]["results"][0]["partialFingerprints"]["scanmaster/v1"]


def test_deduplication_merges_sources_and_references() -> None:
    run = fixture_run()
    finding = run.findings[0]
    duplicate = Finding(
        finding.native_id,
        finding.title,
        Severity.MEDIUM,
        location=finding.location,
        references=("https://advisory.test/2",),
        cve_ids=finding.cve_ids,
        sources=("nuclei",),
    )
    merged = deduplicate(run.target, (finding, duplicate))
    assert len(merged) == 1
    assert merged[0].sources == ("nuclei", "zap")
    assert len(merged[0].references) == 2


def test_threshold_exit_contract_logic() -> None:
    run = fixture_run()
    assert _threshold_violated(run, "high")
    assert not _threshold_violated(run, "critical")
    assert not _threshold_violated(run, "never")
    with pytest.raises(ValueError, match="--fail-on"):
        _threshold_violated(run, "invalid")
