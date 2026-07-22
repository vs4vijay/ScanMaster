from dataclasses import dataclass

from scanmaster.application.diagnostics import (
    Diagnose,
    DiagnoseRequest,
    ListScanners,
    ListScannersRequest,
)
from scanmaster.domain.scanners import ScanMode, ScannerCapabilities, ScannerDescriptor, TargetKind

CAPABILITIES = ScannerCapabilities(frozenset({TargetKind.URL}), frozenset({ScanMode.PASSIVE}), False, True, False)


@dataclass
class HealthAdapter:
    descriptor: ScannerDescriptor
    result: tuple[bool, str] = (True, "ready")
    raises: bool = False

    def check_health(self) -> tuple[bool, str]:
        if self.raises:
            raise RuntimeError("vendor secret must not cross boundary")
        return self.result


def test_list_scanners_can_filter_disabled() -> None:
    adapters = (
        HealthAdapter(ScannerDescriptor("on", "On", True, CAPABILITIES)),
        HealthAdapter(ScannerDescriptor("off", "Off", False, CAPABILITIES)),
    )
    result = ListScanners(adapters).execute(ListScannersRequest(include_disabled=False))
    assert [scanner.name for scanner in result.scanners] == ["on"]


def test_diagnostics_isolate_adapter_failures() -> None:
    adapters = (
        HealthAdapter(ScannerDescriptor("good", "Good", True, CAPABILITIES)),
        HealthAdapter(ScannerDescriptor("bad", "Bad", True, CAPABILITIES), raises=True),
        HealthAdapter(ScannerDescriptor("off", "Off", False, CAPABILITIES)),
    )
    result = Diagnose(adapters).execute(DiagnoseRequest())
    assert result.passed is False
    assert [(item.scanner, item.status) for item in result.checks] == [
        ("good", "healthy"),
        ("bad", "failed"),
        ("off", "disabled"),
    ]
    assert "secret" not in result.checks[1].detail
