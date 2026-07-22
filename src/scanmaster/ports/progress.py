from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    kind: str
    message: str
    occurred_at: datetime


class ProgressSink(Protocol):
    def publish(self, event: ProgressEvent) -> None: ...
