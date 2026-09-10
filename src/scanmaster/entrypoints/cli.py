from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from scanmaster import __version__
from scanmaster.adapters.config import Settings, load_settings
from scanmaster.adapters.greenbone import GreenboneAdapter
from scanmaster.adapters.logging import configure_logging
from scanmaster.adapters.nuclei import NucleiAdapter, NucleiPolicy, NucleiProfile
from scanmaster.adapters.persistence import FilesystemArtifactStore, SqliteRunRepository
from scanmaster.adapters.policy import load_policy, validate_policy_target
from scanmaster.adapters.rapid7 import Rapid7Adapter
from scanmaster.adapters.reports import render_json, render_sarif, render_terminal
from scanmaster.adapters.scanners import build_stub_adapters
from scanmaster.adapters.zap import ZapAdapter, ZapAuthentication, ZapScanPolicy, ZapSpider
from scanmaster.application.diagnostics import Diagnose, DiagnoseRequest, ListScanners, ListScannersRequest
from scanmaster.application.findings import apply_suppressions, compare_runs, enrich_from_cache
from scanmaster.application.scans import CancelRun, GetRun, RefreshRun, ScanBinding, StartScans, StartScansRequest
from scanmaster.domain.runs import RunState
from scanmaster.domain.scanners import TargetKind

app = typer.Typer(help="Orchestrate authorized security scans.", no_args_is_help=True)
console = Console()
error_console = Console(stderr=True)
SEVERITY_RANK = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _threshold_violated(run: object, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if fail_on not in SEVERITY_RANK:
        raise ValueError("--fail-on must be low, medium, high, critical, or never")
    findings = getattr(run, "findings", ())
    return any(
        not item.suppressed
        and item.lifecycle != "resolved"
        and SEVERITY_RANK[item.severity.value] >= SEVERITY_RANK[fail_on]
        for item in findings
    )


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


def _runtime(
    settings: Settings, policy: ZapScanPolicy | None = None
) -> tuple[SqliteRunRepository, FilesystemArtifactStore, ZapAdapter]:
    repository = SqliteRunRepository(settings.database_path)
    artifacts = FilesystemArtifactStore(
        settings.artifact_path,
        repository,
        settings.artifact_max_files_per_run,
        settings.artifact_max_bytes_per_file,
        settings.retention_days,
    )
    adapter = ZapAdapter(
        str(settings.zap_url),
        settings.zap_api_key.get_secret_value() if settings.zap_api_key else None,
        settings.tls_verify_for("zap"),
        settings.execution_timeout_seconds,
        settings.zap_plan_host_directory,
        settings.zap_plan_container_directory,
        policy,
    )
    return repository, artifacts, adapter


def _scan_bindings(
    settings: Settings,
    profile: NucleiProfile,
    zap_policy: ZapScanPolicy | None = None,
) -> dict[str, ScanBinding]:
    bindings: dict[str, ScanBinding] = {}
    if settings.zap_enabled:
        _, _, zap = _runtime(settings, zap_policy)
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
    if settings.greenbone_enabled:
        assert settings.greenbone_username and settings.greenbone_password
        greenbone = GreenboneAdapter(
            settings.greenbone_username,
            settings.greenbone_password.get_secret_value(),
            socket_path=str(settings.greenbone_socket_path),
            host=settings.greenbone_host,
            port=settings.greenbone_port,
            timeout=settings.execution_timeout_seconds,
            scanner_id=settings.greenbone_scanner_id,
            scan_config_id=settings.greenbone_scan_config_id,
        )
        bindings["greenbone"] = ScanBinding("greenbone", greenbone, GreenboneAdapter.supported_target_kinds, True)
    if settings.rapid7_enabled:
        assert settings.rapid7_url and settings.rapid7_username and settings.rapid7_password
        rapid7 = Rapid7Adapter(
            str(settings.rapid7_url),
            settings.rapid7_username,
            settings.rapid7_password.get_secret_value(),
            settings.tls_verify_for("rapid7"),
            settings.execution_timeout_seconds,
        )
        bindings["rapid7"] = ScanBinding("rapid7", rapid7, Rapid7Adapter.supported_target_kinds, True)
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
    active: Annotated[bool, typer.Option("--active", help="Enable active ZAP scanning.")] = False,
    api_spec: Annotated[str | None, typer.Option("--api-spec", help="OpenAPI document path or URL.")] = None,
    graphql_endpoint: Annotated[str | None, typer.Option("--graphql-endpoint")] = None,
    spider: Annotated[ZapSpider, typer.Option("--spider")] = ZapSpider.TRADITIONAL,
    authentication: Annotated[ZapAuthentication, typer.Option("--authentication")] = ZapAuthentication.NONE,
    authentication_secret_env: Annotated[str | None, typer.Option("--authentication-secret-env")] = None,
    include_path: Annotated[list[str] | None, typer.Option("--include-path")] = None,
    exclude_path: Annotated[list[str] | None, typer.Option("--exclude-path")] = None,
    fail_on: Annotated[str, typer.Option("--fail-on", help="Finding threshold or never.")] = "never",
    policy_path: Annotated[Path, typer.Option("--policy", help="Policy-as-code YAML path.")] = Path("scanmaster.yaml"),
) -> None:
    """Run a passive scan and persist its result."""
    settings = _settings()
    try:
        policy = load_policy(policy_path)
        validate_policy_target(policy, target)
    except (ValueError, ValidationError) as error:
        error_console.print(f"[bold red]Invalid policy:[/bold red] {error}")
        raise typer.Exit(2) from None
    if fail_on == "never" and policy.fail_on != "never":
        fail_on = policy.fail_on
    if (profile is NucleiProfile.INTRUSIVE or active) and not confirm_authorized:
        error_console.print("[bold red]Active or intrusive scans require --confirm-authorized.[/bold red]")
        raise typer.Exit(2)
    try:
        zap_policy = ZapScanPolicy(
            active=active,
            authorized=confirm_authorized,
            spider=spider,
            api_spec=api_spec,
            graphql_endpoint=graphql_endpoint,
            authentication=authentication,
            authentication_secret_env=authentication_secret_env,
            include_paths=tuple(include_path or ()),
            exclude_paths=tuple(exclude_path or ()),
        )
        zap_policy.validate()
    except ValueError as error:
        error_console.print(f"[bold red]Invalid scan request:[/bold red] {error}")
        raise typer.Exit(2) from None
    repository = SqliteRunRepository(settings.database_path)
    artifacts = FilesystemArtifactStore(
        settings.artifact_path,
        repository,
        settings.artifact_max_files_per_run,
        settings.artifact_max_bytes_per_file,
        settings.retention_days,
    )
    try:
        runs = StartScans(
            repository,
            artifacts,
            _scan_bindings(settings, profile, zap_policy),
            settings.polling_interval_seconds,
            settings.execution_timeout_seconds,
        ).execute(StartScansRequest(target, tuple(scanner), detach, active, confirm_authorized))
    except ValueError as error:
        error_console.print(f"[bold red]Invalid scan request:[/bold red] {error}")
        raise typer.Exit(2) from None
    for run in runs:
        render_terminal(run, console)
    if any(run.state is RunState.FAILED for run in runs):
        raise typer.Exit(2)
    try:
        violated = any(_threshold_violated(run, fail_on) for run in runs)
    except ValueError as error:
        error_console.print(f"[bold red]Invalid scan request:[/bold red] {error}")
        raise typer.Exit(2) from None
    if violated:
        raise typer.Exit(1)


@app.command("status")
def status(run_id: Annotated[str, typer.Argument(help="Persisted run identifier.")]) -> None:
    """Show a persisted run from this or a previous process."""
    settings = _settings()
    repository, artifacts, _ = _runtime(settings)
    adapters = {name: binding.adapter for name, binding in _scan_bindings(settings, NucleiProfile.SAFE).items()}
    try:
        run = RefreshRun(repository, artifacts, adapters).execute(run_id)
    except KeyError, ValueError:
        error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
        raise typer.Exit(2) from None
    render_terminal(run, console)


@app.command("cancel")
def cancel(run_id: Annotated[str, typer.Argument(help="Persisted run identifier.")]) -> None:
    """Cancel an active scanner run."""
    settings = _settings()
    repository, _, _ = _runtime(settings)
    adapters = {name: binding.adapter for name, binding in _scan_bindings(settings, NucleiProfile.SAFE).items()}
    try:
        run = CancelRun(repository, adapters).execute(run_id)
    except (KeyError, ValueError) as error:
        error_console.print(f"[bold red]Unable to cancel run:[/bold red] {error}")
        raise typer.Exit(2) from None
    render_terminal(run, console)


@app.command("report")
def report(
    run_id: Annotated[str, typer.Argument(help="Persisted run identifier.")],
    report_format: Annotated[str, typer.Option("--format", help="terminal, json, or sarif")] = "terminal",
    fail_on: Annotated[str, typer.Option("--fail-on", help="Finding threshold or never.")] = "never",
    baseline: Annotated[str | None, typer.Option("--baseline", help="Compatible baseline run ID.")] = None,
    new_only: Annotated[bool, typer.Option("--new-only", help="Show only new findings.")] = False,
    fail_on_new: Annotated[bool, typer.Option("--fail-on-new")] = False,
    policy_path: Annotated[Path, typer.Option("--policy")] = Path("scanmaster.yaml"),
    kev_cache: Annotated[Path | None, typer.Option("--kev-cache")] = None,
    epss_cache: Annotated[Path | None, typer.Option("--epss-cache")] = None,
) -> None:
    """Render a persisted scan report."""
    repository, _, _ = _runtime(_settings())
    try:
        run = GetRun(repository).execute(run_id)
    except KeyError:
        error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
        raise typer.Exit(2) from None
    try:
        if baseline:
            baseline_run = GetRun(repository).execute(baseline)
            run = compare_runs(run, baseline_run)
        elif new_only or fail_on_new:
            raise ValueError("--new-only and --fail-on-new require --baseline")
        policy = load_policy(policy_path)
        run = apply_suppressions(run, policy, datetime.now(UTC))
        run = enrich_from_cache(run, kev_cache, epss_cache)
        if new_only:
            run = replace(run, findings=tuple(item for item in run.findings if item.lifecycle == "new"))
        if fail_on == "never" and policy.fail_on != "never":
            fail_on = policy.fail_on
    except (KeyError, ValueError, ValidationError) as error:
        error_console.print(f"[bold red]Invalid report policy/baseline:[/bold red] {error}")
        raise typer.Exit(2) from None
    if report_format == "json":
        console.print(render_json(run), markup=False)
    elif report_format == "sarif":
        console.print(render_sarif(run), markup=False)
    elif report_format == "terminal":
        render_terminal(run, console)
    else:
        error_console.print("[bold red]Invalid report format:[/bold red] expected terminal, json, or sarif")
        raise typer.Exit(2)
    try:
        if fail_on_new and any(item.lifecycle == "new" and not item.suppressed for item in run.findings):
            raise typer.Exit(1)
        if _threshold_violated(run, fail_on):
            raise typer.Exit(1)
    except ValueError as error:
        error_console.print(f"[bold red]Invalid report threshold:[/bold red] {error}")
        raise typer.Exit(2) from None


def main() -> None:
    app()
