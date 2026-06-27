"""Package and deployment metadata."""

from __future__ import annotations

import os
import subprocess
from importlib.metadata import version
from pathlib import Path

PACKAGE_NAME = "pact"
PACKAGE_VERSION = version(PACKAGE_NAME)
UNKNOWN_COMMIT = "unknown"

_COMMIT_ENV_NAMES = (
    "PACT_COMMIT_SHA",
    "PACT_GIT_COMMIT",
    "GIT_COMMIT",
    "SOURCE_VERSION",
)


def deployment_commit() -> str:
    """Return the deployed source commit hash when available."""

    for name in _COMMIT_ENV_NAMES:
        value = os.getenv(name)
        if value:
            return value.strip()
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=Path(__file__).resolve().parents[2],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN_COMMIT
    commit = completed.stdout.strip()
    return commit or UNKNOWN_COMMIT


def server_metadata() -> dict[str, str]:
    """Return public server build metadata."""

    return {
        "package": PACKAGE_NAME,
        "version": PACKAGE_VERSION,
        "commit": deployment_commit(),
    }
