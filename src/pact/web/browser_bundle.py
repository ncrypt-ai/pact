"""Pyodide browser package assembly."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

CORE_MODULES = (
    "browser.py",
    "canonical.py",
    "crypto.py",
    "identity.py",
    "manifest.py",
    "policy.py",
    "privacy.py",
    "registry/__init__.py",
    "registry/app.py",
    "registry/store.py",
    "carriers/__init__.py",
    "carriers/text.py",
    "carriers/structured.py",
    "detection/__init__.py",
    "detection/evidence.py",
    "detection/probes.py",
    "detection/risk.py",
    "detection/statistics.py",
    "watermarks/__init__.py",
    "watermarks/base.py",
    "watermarks/canary.py",
    "watermarks/invisible.py",
    "watermarks/lexical.py",
    "watermarks/semantic.py",
    "watermarks/statistical.py",
    "watermarks/syntactic.py",
    "watermarks/textual.py",
)
C2PA_MODULES = (
    "carriers/c2pa.py",
    "carriers/c2pa_text.py",
)
DOCUMENT_MODULES = ("carriers/c2pa.py",)
IMAGE_MODULES = ("watermarks/image.py",)
FEATURE_MODULES = {
    "core": (),
    "c2pa": C2PA_MODULES,
    "documents": DOCUMENT_MODULES,
    "image-watermarks": IMAGE_MODULES,
}


def browser_python_archive(feature: str) -> bytes:
    """Build a zipimport-compatible Python archive for one browser feature."""

    source_directory = Path(__file__).resolve().parents[1]
    modules = [*CORE_MODULES, *FEATURE_MODULES[feature]]
    archive = io.BytesIO()
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED
    ) as package:
        package.writestr(
            "pact/__init__.py",
            '"""Browser-safe PACT runtime bundle."""\n',
        )
        for module in sorted(set(modules)):
            package.write(source_directory / module, f"pact/{module}")
    return archive.getvalue()
