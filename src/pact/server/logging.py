"""Shared server logging setup for PACT deployments."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self


class LogFormat(StrEnum):
    """Supported server log output formats."""

    PLAIN = "plain"
    JSON = "json"


class JsonLogFormatter(logging.Formatter):
    """Format log records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(
                record.created, UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "request_id",
            "method",
            "path",
            "status_code",
            "duration_ms",
            "client_ip",
            "deployment_mode",
            "registry_url",
            "store_backend",
        ):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    """Runtime logging controls shared by CLI, ASGI, and Lambda variants."""

    level: str = "INFO"
    format: LogFormat = LogFormat.PLAIN
    access_log: bool = True

    @classmethod
    def from_env(cls) -> Self:
        """Load logging controls from environment variables."""

        return cls(
            level=os.getenv("PACT_LOG_LEVEL", "INFO"),
            format=LogFormat(os.getenv("PACT_LOG_FORMAT", "plain")),
            access_log=_env_bool("PACT_ACCESS_LOG", default=True),
        )

    def normalized_level(self) -> str:
        """Return an uppercase logging level name accepted by logging."""

        level = self.level.upper()
        if level not in logging.getLevelNamesMapping():
            raise ValueError(f"unsupported log level: {self.level}")
        return level

    def to_dict(self) -> dict[str, object]:
        """Serialize logging settings for diagnostics."""

        return {
            "level": self.normalized_level(),
            "format": self.format.value,
            "access_log": self.access_log,
        }


def configure_logging(
    config: LoggingConfig | None = None,
    *,
    force: bool = False,
) -> None:
    """Configure process logging for all server variants."""

    selected = config or LoggingConfig.from_env()
    level = selected.normalized_level()
    root = logging.getLogger()
    if root.handlers and not force:
        root.setLevel(level)
        _set_known_logger_levels(level)
        return
    handler = logging.StreamHandler(sys.stdout)
    if selected.format is LogFormat.JSON:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s [%(name)s] %(message)s"
            )
        )
    root.handlers = [handler]
    root.setLevel(level)
    _set_known_logger_levels(level)


def server_logger(name: str) -> logging.Logger:
    """Return a namespaced PACT server logger."""

    return logging.getLogger(f"pact.server.{name}")


def request_log_extra(
    *,
    request_id: str,
    method: str,
    path: str,
    status_code: int | None = None,
    duration_ms: float | None = None,
    client_ip: str | None = None,
) -> dict[str, object]:
    """Build structured request fields for log records."""

    extra: dict[str, object] = {
        "request_id": request_id,
        "method": method,
        "path": path,
    }
    if status_code is not None:
        extra["status_code"] = status_code
    if duration_ms is not None:
        extra["duration_ms"] = round(duration_ms, 3)
    if client_ip is not None:
        extra["client_ip"] = client_ip
    return extra


def monotonic_ms() -> float:
    """Return the current monotonic clock value in milliseconds."""

    return time.perf_counter() * 1000


def _set_known_logger_levels(level: str) -> None:
    logging.getLogger("pact").setLevel(level)
    logging.getLogger("uvicorn").setLevel(level)
    logging.getLogger("uvicorn.error").setLevel(level)
    logging.getLogger("uvicorn.access").setLevel(level)


def _env_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")
