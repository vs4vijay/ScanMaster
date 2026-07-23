from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from scanmaster import __version__
from scanmaster.adapters.config import Settings, load_settings
from scanmaster.adapters.logging import configure_logging
from scanmaster.adapters.nuclei import NucleiAdapter, NucleiPolicy, NucleiProfile
from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.adapters.reports import render_json, render_terminal
from scanmaster.adapters.scanners import build_stub_adapters
from scanmaster.adapters.zap import ZapAdapter
from scanmaster.application.diagnostics import Diagnose, DiagnoseRequest, ListScanners, ListScannersRequest
from scanmaster.application.scans import CancelRun, GetRun, ScanBinding, StartScans, StartScansRequest
from scanmaster.domain.runs import RunState
from scanmaster.domain.scanners import TargetKind

app = typer.Typer(help="Orchestrate authorized security scans.", no_args_is_help=True)
console = Console()
error_console = Console(stderr=True)


def _settings() -> Settings:
    try:
        settings = load_settings(Path(".env"))
    except ValidationError as error:
        error_console.print(f"[bold red]Invalid configuration:[/bold red] {error}")
        raise typer.Exit(2) from None
    configure_logging(
        settings.log_level,
        (settings.zap_api_key, settings.greenbone_password, settings.rapid7_password),
    )
    return settings


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"scanmaster {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """ScanMaster command-line interface."""


@app.command("scanners")
def scanners() -> None:
    """List available scanners and their configuration state."""
    adapters = build_stub_adapters(_settings())
    result = ListScanners(adapters).execute(ListScannersRequest())
    table = Table("Scanner", "State", "Targets", "Modes", "Durable detach")
    for scanner in result.scanners:
        capabilities = scanner.capabilities
        table.add_row(
            scanner.name,
            "enabled" if scanner.enabled else "disabled",
            ", ".join(sorted(kind.value for kind in capabilities.target_kinds)),
            ", ".join(sorted(mode.value for mode in capabilities.scan_modes)),
            "yes" if capabilities.supports_durable_detach else "no",
        )
    console.print(table)


@app.command("doctor")
def doctor() -> None:
    """Validate configuration and scanner prerequisites."""
    settings = _settings()
    adapters = build_stub_adapters(settings)
    result = Diagnose(adapters).execute(DiagnoseRequest())
    table = Table("Scanner", "Status", "Detail")
    for check in result.checks:
        table.add_row(check.scanner, check.status, check.detail)
    console.print(table)
    disabled_tls = [
        adapter.descriptor.name for adapter in adapters if adapter.descriptor.enabled and not adapter.tls_verify
    ]
    for scanner in disabled_tls:
        error_console.print(f"[bold yellow]WARNING: TLS verification is disabled for {scanner}.[/bold yellow]")
    if not result.passed:
        raise typer.Exit(2)


def _runtime(settings: Settings) -> tuple[SqliteRunRepository, FilesystemArtifactStore, ZapAdapter]:
    repository = SqliteRunRepository(settings.database_path)
    artifacts = FilesystemArtifactStore(settings.artifact_path, repository)
    adapter = ZapAdapter(
        str(settings.zap_url),
        settings.zap_api_key.get_secret_value() if settings.zap_api_key else None,
        settings.tls_verify_for("zap"),
        settings.execution_timeout_seconds,
        settings.zap_plan_host_directory,
        settings.zap_plan_container_directory,
    )
    return repository, artifacts, adapter


def _scan_bindings(
    settings: Settings,
    profile: NucleiProfile,
) -> dict[str, ScanBinding]:
    bindings: dict[str, ScanBinding] = {}
    if settings.zap_enabled:
        _, _, zap = _runtime(settings)
        bindings["zap"] = ScanBinding("zap", zap, frozenset({TargetKind.URL}), True)
    if settings.nuclei_enabled:
        nuclei = NucleiAdapter(
            settings.nuclei_image,
            settings.nuclei_templates_directory,
            settings.artifact_path / "nuclei-work",
            settings.nuclei_rate_limit,
            settings.nuclei_concurrency,
            settings.nuclei_timeout_seconds,
            settings.nuclei_identification_header,
            NucleiPolicy(profile=profile),
        )
        bindings["nuclei"] = ScanBinding(
            "nuclei", nuclei, NucleiAdapter.supported_target_kinds, NucleiAdapter.supports_durable_detach
        )
    return bindings


@app.command("scan")
def scan(
    target: Annotated[str, typer.Argument(help="Authorized target URL.")],
    scanner: Annotated[list[str], typer.Option("--scanner", help="Scanner to run; repeat for multiple.")],
    profile: Annotated[NucleiProfile, typer.Option("--profile", help="Nuclei safety profile.")] = NucleiProfile.SAFE,
    confirm_authorized: Annotated[
        bool, typer.Option("--confirm-authorized", help="Confirm authorization for intrusive scanning.")
    ] = False,
    detach: Annotated[bool, typer.Option("--detach", help="Return after durable scanner submission.")] = False,
) -> None:
    """Run a passive scan and persist its result."""
    settings = _settings()
    if profile is NucleiProfile.INTRUSIVE and not confirm_authorized:
        error_console.print("[bold red]Intrusive Nuclei scans require --confirm-authorized.[/bold red]")
        raise typer.Exit(2)
    repository = SqliteRunRepository(settings.database_path)
    artifacts = FilesystemArtifactStore(settings.artifact_path, repository)
    try:
        runs = StartScans(
            repository,
            artifacts,
            _scan_bindings(settings, profile),
            settings.polling_interval_seconds,
            settings.execution_timeout_seconds,
        ).execute(StartScansRequest(target, tuple(scanner), detach))
    except ValueError as error:
        error_console.print(f"[bold red]Invalid scan request:[/bold red] {error}")
        raise typer.Exit(2) from None
    for run in runs:
        render_terminal(run, console)
    if any(run.state is RunState.FAILED for run in runs):
        raise typer.Exit(2)


@app.command("status")
def status(run_id: Annotated[str, typer.Argument(help="Persisted run identifier.")]) -> None:
    """Show a persisted run from this or a previous process."""
    repository, _, _ = _runtime(_settings())
    try:
        run = GetRun(repository).execute(run_id)
    except KeyError:
        error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
        raise typer.Exit(2) from None
    render_terminal(run, console)


@app.command("cancel")
def cancel(run_id: Annotated[str, typer.Argument(help="Persisted run identifier.")]) -> None:
    """Cancel an active ZAP run."""
    repository, _, adapter = _runtime(_settings())
    try:
        run = CancelRun(repository, adapter).execute(run_id)
    except (KeyError, ValueError) as error:
        error_console.print(f"[bold red]Unable to cancel run:[/bold red] {error}")
        raise typer.Exit(2) from None
    render_terminal(run, console)


@app.command("report")
def report(
    run_id: Annotated[str, typer.Argument(help="Persisted run identifier.")],
    report_format: Annotated[str, typer.Option("--format", help="terminal or json")] = "terminal",
) -> None:
    """Render a persisted scan report."""
    repository, _, _ = _runtime(_settings())
    try:
        run = GetRun(repository).execute(run_id)
    except KeyError:
        error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
        raise typer.Exit(2) from None
    if report_format == "json":
        console.print(render_json(run), markup=False)
    elif report_format == "terminal":
        render_terminal(run, console)
    else:
        error_console.print("[bold red]Invalid report format:[/bold red] expected terminal or json")
        raise typer.Exit(2)


def main() -> None:
    app()
