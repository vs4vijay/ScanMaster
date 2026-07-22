from dataclasses import dataclass
from enum import StrEnum


class TargetKind(StrEnum):
    URL = "url"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip"
    CIDR = "cidr"
    API_SPECIFICATION = "api-spec"


class ScanMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass(frozen=True, slots=True)
class ScannerCapabilities:
    target_kinds: frozenset[TargetKind]
    scan_modes: frozenset[ScanMode]
    supports_authentication: bool
    supports_cancellation: bool
    supports_durable_detach: bool
    prerequisites: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerDescriptor:
    name: str
    display_name: str
    enabled: bool
    capabilities: ScannerCapabilities
