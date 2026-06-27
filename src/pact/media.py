"""Media-type helpers."""

from __future__ import annotations

import mimetypes
from pathlib import Path

DEFAULT_BINARY_MIME_TYPE = "application/octet-stream"


def infer_mime_type(name: str | Path, default: str | None = None) -> str:
    """Infer a MIME type from a file name."""

    mime_type, _encoding = mimetypes.guess_type(str(name))
    if mime_type is not None:
        return mime_type
    if default is not None:
        return default
    raise ValueError("could not infer a MIME type from the input path")
