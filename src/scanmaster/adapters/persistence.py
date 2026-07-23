from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import ForeignKey, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from sqlalchemy.pool import NullPool

from scanmaster.domain.runs import Finding, RunState, ScanRun, Severity, utc_now
from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target


class Base(DeclarativeBase):
    pass


class RunRow(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scanner: Mapped[str] = mapped_column(String(40))
    target_kind: Mapped[str] = mapped_column(String(20))
    target_value: Mapped[str] = mapped_column(Text)
    target_canonical: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str | None] = mapped_column(String(200))
    error: Mapped[str | None] = mapped_column(Text)
    findings: Mapped[list[FindingRow]] = relationship(cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    native_id: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    cve_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    cwe_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    cvss_score: Mapped[float | None]
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    occurrences: Mapped[list[OccurrenceRow]] = relationship(cascade="all, delete-orphan")


class ScannerJobRow(Base):
    __tablename__ = "scanner_jobs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    scanner: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str] = mapped_column(String(200))
    state: Mapped[str] = mapped_column(String(20))


class OccurrenceRow(Base):
    __tablename__ = "occurrences"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    location: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)


class ArtifactRow(Base):
    __tablename__ = "artifacts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40))


class SqliteRunRepository:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{path}", poolclass=NullPool)
        Base.metadata.create_all(self._engine)

    def create(self, run: ScanRun) -> None:
        with Session(self._engine) as session, session.begin():
            session.add(
                RunRow(
                    id=run.id,
                    scanner=run.scanner,
                    target_kind=run.target.kind.value,
                    target_value=run.target.value,
                    target_canonical=run.target.canonical,
                    state=run.state.value,
                    created_at=run.created_at.isoformat(),
                    updated_at=run.updated_at.isoformat(),
                    external_id=run.external_id,
                    error=run.error,
                )
            )

    def get(self, run_id: str) -> ScanRun | None:
        with Session(self._engine) as session:
            row = session.scalar(select(RunRow).where(RunRow.id == run_id))
            if row is None:
                return None
            return ScanRun(
                row.id,
                row.scanner,
                Target(TargetKind(row.target_kind), row.target_value, row.target_canonical),
                RunState(row.state),
                datetime.fromisoformat(row.created_at),
                datetime.fromisoformat(row.updated_at),
                row.external_id,
                row.error,
                tuple(
                    Finding(
                        item.native_id,
                        item.title,
                        Severity(item.severity),
                        item.description,
                        item.remediation,
                        item.location,
                        item.evidence,
                        tuple(json.loads(item.references_json)),
                        tuple(json.loads(item.cve_ids_json)),
                        tuple(json.loads(item.cwe_ids_json)),
                        item.cvss_score,
                        item.cvss_vector,
                    )
                    for item in row.findings
                ),
            )

    def set_state(
        self, run_id: str, state: RunState, *, external_id: str | None = None, error: str | None = None
    ) -> None:
        with Session(self._engine) as session, session.begin():
            row = session.get(RunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            row.state = state.value
            row.updated_at = utc_now().isoformat()
            if external_id is not None:
                row.external_id = external_id
                session.add(
                    ScannerJobRow(run_id=run_id, scanner=row.scanner, external_id=external_id, state=state.value)
                )
            row.error = error

    def replace_findings(self, run_id: str, findings: tuple[Finding, ...]) -> None:
        with Session(self._engine) as session, session.begin():
            row = session.get(RunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            row.findings.clear()
            row.findings.extend(
                FindingRow(
                    native_id=f.native_id,
                    title=f.title,
                    severity=f.severity.value,
                    description=f.description,
                    remediation=f.remediation,
                    location=f.location,
                    evidence=f.evidence,
                    references_json=json.dumps(f.references),
                    cve_ids_json=json.dumps(f.cve_ids),
                    cwe_ids_json=json.dumps(f.cwe_ids),
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    occurrences=[OccurrenceRow(location=f.location, evidence=f.evidence)],
                )
                for f in findings
            )

    def record_artifact(self, run_id: str, name: str, path: str) -> None:
        with Session(self._engine) as session, session.begin():
            session.add(ArtifactRow(run_id=run_id, name=name, path=path, created_at=utc_now().isoformat()))


class FilesystemArtifactStore:
    def __init__(self, root: Path, repository: SqliteRunRepository) -> None:
        self._root = root.resolve()
        self._repository = repository

    def write_json(self, run_id: str, name: str, payload: object) -> str:
        directory = self._root / run_id
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"{name}.json"
        destination.write_text(json.dumps(_redact(payload), indent=2, sort_keys=True, default=str), encoding="utf-8")
        self._repository.record_artifact(run_id, name, str(destination))
        return str(destination)


_SENSITIVE_KEYS = frozenset({"apikey", "api_key", "authorization", "cookie", "password", "token"})


def _redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): "**********" if str(key).lower() in _SENSITIVE_KEYS else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value
