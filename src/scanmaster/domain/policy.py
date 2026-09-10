from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SuppressionPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    expires: datetime


class ScanPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    include_targets: tuple[str, ...] = ()
    exclude_targets: tuple[str, ...] = ()
    scanner_profiles: dict[str, str] = Field(default_factory=dict)
    rate_limits: dict[str, int] = Field(default_factory=dict)
    timeouts: dict[str, int] = Field(default_factory=dict)
    fail_on: str = "never"
    suppressions: tuple[SuppressionPolicy, ...] = ()
