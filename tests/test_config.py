from pathlib import Path

import pytest
from pydantic import ValidationError

from scanmaster.adapters.config import Settings, load_settings


def test_process_environment_wins_over_dotenv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("SCANMASTER_LOG_LEVEL=DEBUG\n", encoding="utf-8")
    monkeypatch.setenv("SCANMASTER_LOG_LEVEL", "ERROR")

    assert load_settings(dotenv).log_level == "ERROR"


@pytest.mark.parametrize(
    ("name", "value"),
    (("SCANMASTER_POLLING_INTERVAL_SECONDS", "0"), ("SCANMASTER_LOG_LEVEL", "VERBOSE")),
)
def test_invalid_values_fail(name: str, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


def test_rapid7_cross_field_validation_and_secret_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "do-not-leak-this-password"
    monkeypatch.setenv("SCANMASTER_RAPID7_ENABLED", "true")
    monkeypatch.setenv("SCANMASTER_RAPID7_PASSWORD", secret)
    with pytest.raises(ValidationError) as captured:
        Settings()

    assert "SCANMASTER_RAPID7_URL" in str(captured.value)
    assert secret not in str(captured.value)


def test_greenbone_credentials_must_be_paired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCANMASTER_GREENBONE_ENABLED", "true")
    monkeypatch.setenv("SCANMASTER_GREENBONE_USERNAME", "operator")
    with pytest.raises(ValidationError, match="must be supplied together"):
        Settings()


def test_tls_override_inherits_default() -> None:
    inherited = Settings(tls_verify_default=False)
    overridden = Settings(tls_verify_default=False, zap_tls_verify=True)
    assert inherited.tls_verify_for("zap") is False
    assert overridden.tls_verify_for("zap") is True
