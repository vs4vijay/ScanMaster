from dataclasses import dataclass

from scanmaster.domain.scanners import ScannerDescriptor
from scanmaster.ports.scanners import ScannerHealthPort


@dataclass(frozen=True, slots=True)
class ListScannersRequest:
    include_disabled: bool = True


@dataclass(frozen=True, slots=True)
class ListScannersResult:
    scanners: tuple[ScannerDescriptor, ...]


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    scanner: str
    status: str
    detail: str

    @property
    def passed(self) -> bool:
        return self.status in {"healthy", "disabled"}


@dataclass(frozen=True, slots=True)
class DiagnoseRequest:
    include_disabled: bool = True


@dataclass(frozen=True, slots=True)
class DiagnoseResult:
    checks: tuple[DiagnosticCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)


class ListScanners:
    def __init__(self, scanners: tuple[ScannerHealthPort, ...]) -> None:
        self._scanners = scanners

    def execute(self, request: ListScannersRequest) -> ListScannersResult:
        descriptors = tuple(scanner.descriptor for scanner in self._scanners)
        if not request.include_disabled:
            descriptors = tuple(item for item in descriptors if item.enabled)
        return ListScannersResult(descriptors)


class Diagnose:
    def __init__(self, scanners: tuple[ScannerHealthPort, ...]) -> None:
        self._scanners = scanners

    def execute(self, request: DiagnoseRequest) -> DiagnoseResult:
        checks: list[DiagnosticCheck] = []
        for scanner in self._scanners:
            if not scanner.descriptor.enabled:
                if request.include_disabled:
                    checks.append(DiagnosticCheck(scanner.descriptor.name, "disabled", "not configured"))
                continue
            try:
                healthy, detail = scanner.check_health()
            except Exception:  # adapter failures are deliberately isolated
                healthy, detail = False, "health adapter failed"
            checks.append(DiagnosticCheck(scanner.descriptor.name, "healthy" if healthy else "failed", detail))
        return DiagnoseResult(tuple(checks))
