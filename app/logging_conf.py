from __future__ import annotations

import logging
import os

_REDACTED_ENV_VARS = ("NETBOX_TOKEN", "NETBOX_WEBHOOK_SECRET", "TSIG_SECRET")


class _SecretRedactionFilter(logging.Filter):
    """Defense in depth: application code should never log secret values
    directly, but if one slips into a message (e.g. via an exception repr),
    scrub known secret values pulled from the environment.
    """

    def __init__(self) -> None:
        super().__init__()
        self._secrets = [
            v for name in _REDACTED_ENV_VARS if (v := os.environ.get(name))
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = msg
        for secret in self._secrets:
            redacted = redacted.replace(secret, "***REDACTED***")
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    handler.addFilter(_SecretRedactionFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
