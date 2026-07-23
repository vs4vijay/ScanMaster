from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from scanmaster.domain.targets import Target


class RunState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Finding:
    native_id: str
    title: str
    severity: Severity
    description: str | None = None
    remediation: str | None = None
    location: str | None = None
    evidence: str | None = None
    references: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str | None = None


@dataclass(frozen=True, slots=True)
class ScanRun:
    id: str
    scanner: str
    target: Target
    state: RunState
    created_at: datetime
    updated_at: datetime
    external_id: str | None = None
    error: str | None = None
    findings: tuple[Finding, ...] = ()


def utc_now() -> datetime:
    return datetime.now(UTC)
