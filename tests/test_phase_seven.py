import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.adapters.policy import load_policy, validate_policy_target
from scanmaster.application.findings import apply_suppressions, compare_runs, enrich_from_cache
from scanmaster.domain.normalization import finding_fingerprint
from scanmaster.domain.runs import Finding, RunState, ScanRun, Severity
from scanmaster.domain.targets import Target


def make_run(run_id: str, findings: tuple[Finding, ...]) -> ScanRun:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return ScanRun(run_id, "zap", Target.parse("https://example.test"), RunState.COMPLETED, now, now, findings=findings)


def test_comparison_classifies_new_recurring_and_resolved() -> None:
    recurring = Finding("1", "Recurring", Severity.MEDIUM, location="/a")
    resolved = Finding("2", "Resolved", Severity.LOW, location="/b")
    new = Finding("3", "New", Severity.HIGH, location="/c")
    result = compare_runs(make_run("current", (recurring, new)), make_run("baseline", (recurring, resolved)))
    assert {item.title: item.lifecycle for item in result.findings} == {
        "Recurring": "recurring",
        "Resolved": "resolved",
        "New": "new",
    }
    with pytest.raises(ValueError, match="incompatible"):
        compare_runs(result, replace(result, scanner="nuclei"))


def test_policy_scope_and_expiring_suppression(tmp_path: Path) -> None:
    run = make_run("run", (Finding("1", "Issue", Severity.HIGH),))
    fingerprint = finding_fingerprint(run.target, run.findings[0])
    expires = datetime.now(UTC) + timedelta(days=1)
    policy_file = tmp_path / "scanmaster.yaml"
    policy_file.write_text(
        "include_targets: ['https://*.test']\n"
        "exclude_targets: ['https://blocked.test']\n"
        "suppressions:\n"
        f"  - fingerprint: {fingerprint}\n"
        "    reason: accepted risk\n"
        "    owner: security@example.test\n"
        f"    expires: '{expires.isoformat()}'\n",
        encoding="utf-8",
    )
    policy = load_policy(policy_file)
    validate_policy_target(policy, "https://example.test")
    with pytest.raises(ValueError, match="excluded"):
        validate_policy_target(policy, "https://blocked.test")
    suppressed = apply_suppressions(run, policy, datetime.now(UTC))
    assert suppressed.findings[0].suppressed
    expired = apply_suppressions(run, policy, expires + timedelta(seconds=1))
    assert not expired.findings[0].suppressed
    assert expired.findings[0].suppression_reason == "accepted risk"
    assert load_policy(tmp_path / "absent.yaml").suppressions == ()
    with pytest.raises(ValueError, match="outside"):
        validate_policy_target(policy, "https://example.com")
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("- not-a-mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_policy(invalid)
    untouched = apply_suppressions(make_run("empty", (Finding("2", "Other", Severity.LOW),)), policy, expires)
    assert untouched.findings[0].suppression_reason is None


def test_offline_enrichment_and_artifact_boundaries(tmp_path: Path) -> None:
    finding = Finding("1", "CVE", Severity.HIGH, cve_ids=("CVE-2026-1",))
    run = make_run("run", (finding,))
    kev = tmp_path / "kev.json"
    epss = tmp_path / "epss.csv"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1"}]}), encoding="utf-8")
    epss.write_text("cve,epss\nCVE-2026-1,0.95\n", encoding="utf-8")
    enriched = enrich_from_cache(run, kev, epss)
    assert dict(enriched.findings[0].enrichment) == {"cisa_kev": "true", "first_epss": "0.95"}
    assert enrich_from_cache(run, tmp_path / "missing", None) == run
    malformed = tmp_path / "malformed.json"
    malformed.write_text("not json", encoding="utf-8")
    assert enrich_from_cache(run, malformed, None) == run

    repository = SqliteRunRepository(tmp_path / "state.db")
    repository.create(run)
    store = FilesystemArtifactStore(tmp_path / "artifacts", repository, 1, 1024)
    path = Path(store.write_json(run.id, "one", {"authorization": "secret", "safe": True}))
    assert "secret" not in path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="file-count"):
        store.write_json(run.id, "two", {})
    with pytest.raises(ValueError, match="escapes"):
        store.write_json("../escape", "bad", {})
    old_time = datetime.now(UTC).timestamp() - 3 * 86400
    os.utime(path, (old_time, old_time))
    FilesystemArtifactStore(tmp_path / "artifacts", repository, retention_days=1)
    assert not path.exists()
