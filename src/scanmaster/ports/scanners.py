from typing import Protocol

from scanmaster.domain.scanners import ScannerDescriptor


class ScannerHealthPort(Protocol):
    @property
    def descriptor(self) -> ScannerDescriptor: ...

    def check_health(self) -> tuple[bool, str]: ...
