import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanmaster.adapters.logging import SecretRedactionFilter
from scanmaster.entrypoints.cli import app

runner = CliRunner()


def test_commands_through_typer_boundary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["--version"]).exit_code == 0
    assert runner.invoke(app, ["scanners"]).exit_code == 0
    assert runner.invoke(app, ["doctor"]).exit_code == 0


def test_invalid_settings_and_tls_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SCANMASTER_RAPID7_ENABLED", "true")
    invalid = runner.invoke(app, ["doctor"])
    assert invalid.exit_code == 2

    monkeypatch.setenv("SCANMASTER_RAPID7_ENABLED", "false")
    monkeypatch.setenv("SCANMASTER_ZAP_ENABLED", "true")
    monkeypatch.setenv("SCANMASTER_ZAP_TLS_VERIFY", "false")
    warning = runner.invoke(app, ["doctor"])
    assert warning.exit_code == 0


def test_logging_filter_redacts_secret() -> None:
    from pydantic import SecretStr

    record = logging.LogRecord("test", logging.INFO, __file__, 1, "token=%s", ("private-token",), None)
    filter_ = SecretRedactionFilter((SecretStr("private-token"), None))
    assert filter_.filter(record) is True
    assert record.getMessage() == "token=**********"
