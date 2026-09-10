from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

from dotenv import load_dotenv
from pydantic import Field, HttpUrl, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANMASTER_", case_sensitive=False, extra="ignore")

    database_path: Path = Path(".scanmaster/scanmaster.db")
    artifact_path: Path = Path(".scanmaster/artifacts")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    polling_interval_seconds: float = Field(default=2.0, gt=0, le=300)
    execution_timeout_seconds: int = Field(default=3600, gt=0, le=86400)
    retention_days: int = Field(default=30, ge=1, le=3650)
    artifact_max_files_per_run: int = Field(default=100, ge=1, le=10000)
    artifact_max_bytes_per_file: int = Field(default=10_000_000, ge=1024, le=1_000_000_000)
    tls_verify_default: bool = True

    zap_enabled: bool = False
    zap_url: HttpUrl = HttpUrl("http://127.0.0.1:8080")
    zap_api_key: SecretStr | None = None
    zap_plan_host_directory: Path = Path(".scanmaster/zap-plans")
    zap_plan_container_directory: Path = Path("/zap/wrk")
    zap_tls_verify: bool | None = None

    nuclei_enabled: bool = False
    nuclei_image: str = (
        "projectdiscovery/nuclei:v3.8.0@sha256:aa3a9c0894629405b5bbe644765dfffd6ff87b7663b5f1d64bcbc01341da335a"
    )
    nuclei_templates_directory: Path = Path(".scanmaster/nuclei-templates")
    nuclei_rate_limit: int = Field(default=50, ge=1, le=1000)
    nuclei_concurrency: int = Field(default=10, ge=1, le=100)
    nuclei_timeout_seconds: int = Field(default=10, ge=1, le=300)
    nuclei_identification_header: str = "ScanMaster/0.1 authorized-security-scan"
    nuclei_tls_verify: bool | None = None

    greenbone_enabled: bool = False
    greenbone_socket_path: Path = Path("/run/gvmd/gvmd.sock")
    greenbone_host: str | None = None
    greenbone_port: int = Field(default=9390, ge=1, le=65535)
    greenbone_username: str | None = None
    greenbone_password: SecretStr | None = None
    greenbone_scanner_id: str | None = None
    greenbone_scan_config_id: str | None = None
    greenbone_tls_verify: bool | None = None

    rapid7_enabled: bool = False
    rapid7_url: HttpUrl | None = None
    rapid7_username: str | None = None
    rapid7_password: SecretStr | None = None
    rapid7_tls_verify: bool | None = None

    @model_validator(mode="after")
    def validate_scanner_requirements(self) -> Self:
        if self.greenbone_enabled and (self.greenbone_username is None or self.greenbone_password is None):
            raise ValueError("Greenbone username and password must be supplied together when enabled")
        if self.rapid7_enabled:
            missing = [
                label
                for label, value in (
                    ("SCANMASTER_RAPID7_URL", self.rapid7_url),
                    ("SCANMASTER_RAPID7_USERNAME", self.rapid7_username),
                    ("SCANMASTER_RAPID7_PASSWORD", self.rapid7_password),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"Rapid7 is enabled but required settings are missing: {', '.join(missing)}")
        return self

    def tls_verify_for(self, scanner: str) -> bool:
        override = getattr(self, f"{scanner}_tls_verify")
        return self.tls_verify_default if override is None else bool(override)


def load_settings(dotenv_path: Path | None = None) -> Settings:
    load_dotenv(dotenv_path=dotenv_path, override=False)
    return Settings()
