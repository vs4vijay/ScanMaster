from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from scanmaster import __version__
from scanmaster.adapters.config import Settings, load_settings
from scanmaster.adapters.logging import configure_logging
from scanmaster.adapters.scanners import build_stub_adapters
from scanmaster.application.diagnostics import Diagnose, DiagnoseRequest, ListScanners, ListScannersRequest

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


def main() -> None:
    app()
