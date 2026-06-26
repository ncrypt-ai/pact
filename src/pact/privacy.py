"""Privacy-boundary checks for public registry payloads."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from pact.crypto import base64url_encode
from pact.manifest import SignedManifest


class PrivacySeverity(StrEnum):
    """Severity levels emitted by privacy audits."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class PrivacyAuditError(ValueError):
    """Raised when a public payload fails privacy validation."""


@dataclass(frozen=True, slots=True)
class PrivacyFinding:
    """One privacy finding for a public payload."""

    severity: PrivacySeverity
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-compatible finding."""

        return {
            "severity": self.severity.value,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class PrivacyAuditReport:
    """Result of checking a public payload against private local material."""

    findings: tuple[PrivacyFinding, ...]

    @property
    def passed(self) -> bool:
        """Whether the payload has no privacy errors."""

        return not any(
            finding.severity is PrivacySeverity.ERROR
            for finding in self.findings
        )

    def require_passed(self) -> None:
        """Raise when the payload contains private material."""

        if self.passed:
            return
        errors = [
            f"{finding.path}: {finding.message}"
            for finding in self.findings
            if finding.severity is PrivacySeverity.ERROR
        ]
        raise PrivacyAuditError("; ".join(errors))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible report."""

        return {
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }


_FORBIDDEN_FIELD_NAMES = {
    "nonce",
    "content",
    "raw_content",
    "plaintext",
    "plain_text",
    "private_key",
    "private_key_pem",
    "watermark_secret",
    "canary",
    "prompt",
    "response",
    "responses",
    "probe_set",
    "protected_text",
}


def audit_signed_manifest_publication(
    signed: SignedManifest,
    *,
    content: bytes | None = None,
    nonce: bytes | None = None,
    private_values: tuple[bytes | str, ...] = (),
) -> PrivacyAuditReport:
    """Audit a signed manifest before publishing it to a registry."""

    findings: list[PrivacyFinding] = [
        PrivacyFinding(
            PrivacySeverity.INFO,
            "registry_pseudonym_disclosed",
            "$.manifest.claimant_key_id",
            "the registry-scoped claimant key identifier is public",
        ),
        PrivacyFinding(
            PrivacySeverity.INFO,
            "salted_commitment_disclosed",
            "$.manifest.content_binding.commitment",
            "the public content binding is salted and does not include the nonce",
        ),
    ]
    _scan_json_value(
        signed.to_dict(),
        "$",
        findings,
        private_markers=_private_markers(
            content=content,
            nonce=nonce,
            private_values=private_values,
        ),
    )
    if signed.manifest.source_url is not None:
        findings.append(
            PrivacyFinding(
                PrivacySeverity.WARNING,
                "source_url_disclosed",
                "$.manifest.source_url",
                "source URLs may identify an account, site, or publication context",
            )
        )
    if signed.manifest.licensing_url is not None:
        findings.append(
            PrivacyFinding(
                PrivacySeverity.WARNING,
                "licensing_url_disclosed",
                "$.manifest.licensing_url",
                "licensing URLs may identify an account, site, or rights holder",
            )
        )
    return PrivacyAuditReport(tuple(findings))


def audit_registry_claim_payload(
    payload: Mapping[str, object],
    *,
    content: bytes | None = None,
    nonce: bytes | None = None,
    private_values: tuple[bytes | str, ...] = (),
) -> PrivacyAuditReport:
    """Audit the mutation payload used to register a claim."""

    findings: list[PrivacyFinding] = []
    unexpected = set(payload) - {"signed_manifest_json"}
    for key in sorted(unexpected):
        findings.append(
            PrivacyFinding(
                PrivacySeverity.ERROR,
                "unexpected_registry_claim_field",
                f"$.{key}",
                "claim registration accepts only a signed manifest envelope",
            )
        )
    manifest_json = payload.get("signed_manifest_json")
    if not isinstance(manifest_json, str):
        findings.append(
            PrivacyFinding(
                PrivacySeverity.ERROR,
                "missing_signed_manifest",
                "$.signed_manifest_json",
                "claim registration requires a signed manifest JSON string",
            )
        )
        return PrivacyAuditReport(tuple(findings))
    markers = _private_markers(
        content=content,
        nonce=nonce,
        private_values=private_values,
    )
    _scan_string(
        manifest_json,
        "$.signed_manifest_json",
        findings,
        private_markers=markers,
    )
    try:
        signed = SignedManifest.from_json(manifest_json)
    except ValueError as error:
        findings.append(
            PrivacyFinding(
                PrivacySeverity.ERROR,
                "invalid_signed_manifest",
                "$.signed_manifest_json",
                str(error),
            )
        )
        return PrivacyAuditReport(tuple(findings))
    return PrivacyAuditReport(
        tuple(findings)
        + audit_signed_manifest_publication(
            signed,
            content=content,
            nonce=nonce,
            private_values=private_values,
        ).findings
    )


def audit_public_json_payload(
    payload: Mapping[str, object],
    *,
    content: bytes | None = None,
    nonce: bytes | None = None,
    private_values: tuple[bytes | str, ...] = (),
) -> PrivacyAuditReport:
    """Audit an arbitrary public JSON payload for private local material."""

    findings: list[PrivacyFinding] = []
    _scan_json_value(
        payload,
        "$",
        findings,
        private_markers=_private_markers(
            content=content,
            nonce=nonce,
            private_values=private_values,
        ),
    )
    return PrivacyAuditReport(tuple(findings))


def _scan_json_value(
    value: object,
    path: str,
    findings: list[PrivacyFinding],
    *,
    private_markers: tuple[tuple[str, str], ...],
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_path = f"{path}.{key}"
            if key in _FORBIDDEN_FIELD_NAMES:
                findings.append(
                    PrivacyFinding(
                        PrivacySeverity.ERROR,
                        "forbidden_public_field",
                        key_path,
                        "field name indicates private material",
                    )
                )
            _scan_json_value(
                child,
                key_path,
                findings,
                private_markers=private_markers,
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_json_value(
                child,
                f"{path}[{index}]",
                findings,
                private_markers=private_markers,
            )
    elif isinstance(value, str):
        _scan_string(
            value,
            path,
            findings,
            private_markers=private_markers,
        )


def _scan_string(
    value: str,
    path: str,
    findings: list[PrivacyFinding],
    *,
    private_markers: tuple[tuple[str, str], ...],
) -> None:
    if (
        "-----BEGIN PRIVATE KEY-----" in value
        or "-----BEGIN EC PRIVATE KEY-----" in value
    ):
        findings.append(
            PrivacyFinding(
                PrivacySeverity.ERROR,
                "private_key_material_disclosed",
                path,
                "private key material must never be public",
            )
        )
    for code, marker in private_markers:
        if marker and marker in value:
            findings.append(
                PrivacyFinding(
                    PrivacySeverity.ERROR,
                    code,
                    path,
                    "private local material appears in a public payload",
                )
            )


def _private_markers(
    *,
    content: bytes | None,
    nonce: bytes | None,
    private_values: tuple[bytes | str, ...],
) -> tuple[tuple[str, str], ...]:
    markers: list[tuple[str, str]] = []
    if content:
        markers.extend(_byte_markers("content_disclosed", content))
        markers.extend(
            _byte_markers(
                "unsalted_content_hash_disclosed",
                hashlib.sha256(content).digest(),
            )
        )
    if nonce:
        markers.extend(_byte_markers("nonce_disclosed", nonce))
    for value in private_values:
        if isinstance(value, bytes):
            markers.extend(_byte_markers("private_value_disclosed", value))
        elif len(value) >= 8:
            markers.append(("private_value_disclosed", value))
    return tuple(dict.fromkeys(markers))


def _byte_markers(code: str, value: bytes) -> list[tuple[str, str]]:
    markers = [
        (code, value.hex()),
        (code, base64url_encode(value)),
        (code, base64.b64encode(value).decode("ascii")),
    ]
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return markers
    normalized = text.strip()
    if len(normalized) >= 8:
        markers.append((code, normalized))
    try:
        json_text = json.dumps(normalized)[1:-1]
    except TypeError:
        return markers
    if len(json_text) >= 8:
        markers.append((code, json_text))
    return markers
