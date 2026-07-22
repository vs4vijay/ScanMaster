import os
import subprocess
import sys
from pathlib import Path


def run_cli(
    tmp_path: Path, *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("SCANMASTER_")}
    env.update(environment or {})
    return subprocess.run(
        [sys.executable, "-m", "scanmaster", *arguments],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_phase_one_user_workflow(tmp_path: Path) -> None:
    version = run_cli(tmp_path, "--version")
    scanners = run_cli(tmp_path, "scanners")
    doctor = run_cli(tmp_path, "doctor")

    assert version.returncode == 0 and "scanmaster 0.1.0" in version.stdout
    assert scanners.returncode == 0
    assert all(name in scanners.stdout for name in ("zap", "nuclei", "greenbone", "rapid7"))
    assert doctor.returncode == 0
    assert "disabled" in doctor.stdout


def test_invalid_configuration_exits_two_without_leaking_secret(tmp_path: Path) -> None:
    secret = "phase-one-super-secret"
    result = run_cli(
        tmp_path,
        "doctor",
        environment={"SCANMASTER_RAPID7_ENABLED": "true", "SCANMASTER_RAPID7_PASSWORD": secret},
    )
    assert result.returncode == 2
    assert "Invalid configuration" in result.stderr
    assert secret not in result.stdout + result.stderr


def test_tls_opt_out_is_prominent(tmp_path: Path) -> None:
    result = run_cli(
        tmp_path,
        "doctor",
        environment={"SCANMASTER_ZAP_ENABLED": "true", "SCANMASTER_ZAP_TLS_VERIFY": "false"},
    )
    assert result.returncode == 0
    assert "WARNING: TLS verification is disabled for zap" in result.stderr
