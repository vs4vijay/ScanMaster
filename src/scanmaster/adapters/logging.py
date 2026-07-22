import logging
from collections.abc import Iterable

from pydantic import SecretStr


class SecretRedactionFilter(logging.Filter):
    def __init__(self, secrets: Iterable[SecretStr | None]) -> None:
        super().__init__()
        self._values = tuple(secret.get_secret_value() for secret in secrets if secret and secret.get_secret_value())

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for value in self._values:
            message = message.replace(value, "**********")
        record.msg = message
        record.args = ()
        return True


def configure_logging(level: str, secrets: Iterable[SecretStr | None]) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter(secrets))
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logging.basicConfig(level=level, handlers=[handler], force=True)
