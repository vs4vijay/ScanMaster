from dataclasses import dataclass
from typing import Protocol

from scanmaster.domain.scanners import ScanMode, ScannerCapabilities, ScannerDescriptor, TargetKind


class ScannerSettings(Protocol):
    zap_enabled: bool
    nuclei_enabled: bool
    greenbone_enabled: bool
    rapid7_enabled: bool

    def tls_verify_for(self, scanner: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class StubHealthAdapter:
    descriptor: ScannerDescriptor
    tls_verify: bool

    def check_health(self) -> tuple[bool, str]:
        # Vendor connectivity is introduced with each scanner's vertical slice.
        return True, "configuration valid; connectivity check pending adapter implementation"


WEB = frozenset({TargetKind.URL, TargetKind.API_SPECIFICATION})
INFRA = frozenset({TargetKind.HOSTNAME, TargetKind.IP_ADDRESS, TargetKind.CIDR})


def build_stub_adapters(settings: ScannerSettings) -> tuple[StubHealthAdapter, ...]:
    specs = (
        ("zap", "OWASP ZAP", WEB, frozenset({ScanMode.PASSIVE, ScanMode.ACTIVE}), True),
        ("nuclei", "Nuclei", WEB | INFRA, frozenset({ScanMode.PASSIVE, ScanMode.ACTIVE}), False),
        ("greenbone", "Greenbone", INFRA, frozenset({ScanMode.ACTIVE}), True),
        ("rapid7", "Rapid7 InsightVM", INFRA, frozenset({ScanMode.ACTIVE}), True),
    )
    adapters = []
    for name, display, targets, modes, durable in specs:
        enabled = bool(getattr(settings, f"{name}_enabled"))
        capabilities = ScannerCapabilities(targets, modes, True, True, durable)
        adapters.append(
            StubHealthAdapter(
                ScannerDescriptor(name, display, enabled, capabilities),
                settings.tls_verify_for(name),
            )
        )
    return tuple(adapters)
