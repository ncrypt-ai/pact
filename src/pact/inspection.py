"""Inspection helpers for manifests, carriers, and registered claims."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

from pact.carriers import (
    CarrierError,
    extract_html_carrier,
    extract_text_carrier,
    extract_xml_carrier,
)
from pact.crypto import base64url_encode
from pact.manifest import SignedManifest, VerificationReport, verify_manifest

if TYPE_CHECKING:
    from pact.registry.app import RegisteredClaim, RegistryService


@dataclass(frozen=True, slots=True)
class InspectionSource:
    """Summary of inspected source bytes."""

    mime_type: str
    size_bytes: int
    sha256: str

    @classmethod
    def create(cls, content: bytes, mime_type: str) -> InspectionSource:
        """Summarize source content without returning the content itself."""

        return cls(
            mime_type=mime_type,
            size_bytes=len(content),
            sha256=base64url_encode(hashlib.sha256(content).digest()),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible source summary."""

        return asdict(self)


@dataclass(frozen=True, slots=True)
class ExtractedReference:
    """Manifest or claim reference recovered from inspected content."""

    carrier: str
    signed_manifest: SignedManifest | None = None
    claim_id: UUID | None = None
    locator: dict[str, object] | None = None
    content: bytes | None = None
    details: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible reference summary."""

        return {
            "carrier": self.carrier,
            "claim_id": None if self.claim_id is None else str(self.claim_id),
            "signed_manifest": None
            if self.signed_manifest is None
            else self.signed_manifest.to_dict(),
            "locator": self.locator,
            "details": self.details or {},
        }


def inspect_content(
    content: bytes,
    *,
    mime_type: str,
    registry_service: RegistryService | None = None,
) -> dict[str, object]:
    """Inspect a manifest or carrier and resolve registry evidence if present."""

    source = InspectionSource.create(content, mime_type)
    errors: list[dict[str, str]] = []
    reference = _extract_reference(content, mime_type, errors)
    result: dict[str, object] = {
        "input": source.to_dict(),
        "recognized": reference is not None,
        "reference": None if reference is None else reference.to_dict(),
        "manifest": None,
        "signed_manifest": None,
        "registry_claim": None,
        "registry_verification": None,
        "source_material": None,
        "parser_errors": errors,
    }
    if reference is None:
        return result

    signed = reference.signed_manifest
    claim = None
    if registry_service is not None:
        claim = _resolve_claim(registry_service, reference)
        if claim is not None:
            signed = claim.signed_manifest
            result["registry_claim"] = _claim_dict(claim)
            result["registry_verification"] = _registry_verification(
                registry_service,
                claim.claim_id,
                content=_content_for_reference(reference),
                nonce=_nonce_for_reference(reference),
            )
    if signed is not None:
        result["manifest"] = signed.manifest.to_dict()
        result["signed_manifest"] = signed.to_dict()
        result["source_material"] = _source_material_report(
            source,
            signed=signed,
            registry_service=registry_service,
            content=_content_for_reference(reference),
            nonce=_nonce_for_reference(reference),
        )
    return result


def _extract_reference(
    content: bytes,
    mime_type: str,
    errors: list[dict[str, str]],
) -> ExtractedReference | None:
    try:
        signed = SignedManifest.from_json(content)
        return ExtractedReference(
            carrier="signed_manifest_json",
            signed_manifest=signed,
            claim_id=signed.manifest.claim_id,
        )
    except Exception as error:
        _record_error(errors, "signed_manifest_json", error)

    if _is_html(mime_type):
        reference = _try_structured_carrier(
            "html",
            extract_html_carrier,
            content,
            errors,
        )
        if reference is not None:
            return reference
    if _is_xml(mime_type):
        reference = _try_structured_carrier(
            "xml",
            extract_xml_carrier,
            content,
            errors,
        )
        if reference is not None:
            return reference
    if _is_text(mime_type):
        try:
            extracted = extract_text_carrier(content)
            signed = extracted.signed_manifest
            locator = extracted.locator
            return ExtractedReference(
                carrier=f"text:{extracted.mode.value}",
                signed_manifest=signed,
                claim_id=signed.manifest.claim_id
                if signed is not None
                else locator.claim_id
                if locator is not None
                else None,
                locator=None if locator is None else locator.to_dict(),
                content=extracted.content,
                details={
                    "content": InspectionSource.create(
                        extracted.content,
                        mime_type,
                    ).to_dict()
                },
            )
        except Exception as error:
            _record_error(errors, "text", error)

    if mime_type.startswith("image/"):
        reference = _try_image_watermark(content, mime_type, errors)
        if reference is not None:
            return reference

    reference = _try_c2pa(content, mime_type, errors)
    if reference is not None:
        return reference
    return _try_embedded_c2pa_sidecar(content, mime_type, errors)


def _try_structured_carrier(
    carrier: str,
    extractor: Any,
    content: bytes,
    errors: list[dict[str, str]],
) -> ExtractedReference | None:
    try:
        extracted = extractor(content)
    except Exception as error:
        _record_error(errors, carrier, error)
        return None
    return ExtractedReference(
        carrier=carrier,
        signed_manifest=extracted.signed_manifest,
        claim_id=extracted.signed_manifest.manifest.claim_id,
        locator=None
        if extracted.locator is None
        else extracted.locator.to_dict(),
        content=extracted.content,
        details={
            "content": InspectionSource.create(
                extracted.content,
                extracted.signed_manifest.manifest.mime_type,
            ).to_dict()
        },
    )


def _try_image_watermark(
    content: bytes,
    mime_type: str,
    errors: list[dict[str, str]],
) -> ExtractedReference | None:
    try:
        from pact.watermarks import decode_image_soft_binding

        decoded = decode_image_soft_binding(content, mime_type)
    except Exception as error:
        _record_error(errors, "image_watermark", error)
        return None
    if not decoded.detected or decoded.locator is None:
        return None
    return ExtractedReference(
        carrier="image_watermark",
        locator=decoded.locator.to_dict(),
        details={"decoder_version": decoded.decoder_version},
    )


def _try_c2pa(
    content: bytes,
    mime_type: str,
    errors: list[dict[str, str]],
) -> ExtractedReference | None:
    try:
        from pact.carriers.c2pa import read_c2pa_asset

        result = read_c2pa_asset(content, mime_type=mime_type)
    except Exception as error:
        _record_error(errors, "c2pa", error)
        return None
    claim_id = _find_uuid(result.manifest_store_json, "pact_claim_id")
    return ExtractedReference(
        carrier="c2pa",
        claim_id=claim_id,
        details={
            "embedded": result.embedded,
            "validation_state": result.validation_state,
            "active_manifest": result.active_manifest,
            "validation_results": result.validation_results,
            "manifest_store": result.manifest_store_json,
        },
    )


def _try_embedded_c2pa_sidecar(
    content: bytes,
    mime_type: str,
    errors: list[dict[str, str]],
) -> ExtractedReference | None:
    try:
        from pact.carriers.c2pa import (
            extract_c2pa_manifest_from_pdf,
            extract_c2pa_manifest_from_zip_document,
        )

        if mime_type == "application/pdf":
            sidecar = extract_c2pa_manifest_from_pdf(content)
            carrier = "pdf_c2pa_sidecar"
        elif _is_zip_document(mime_type):
            sidecar = extract_c2pa_manifest_from_zip_document(content)
            carrier = "zip_c2pa_sidecar"
        else:
            return None
    except Exception as error:
        _record_error(errors, "embedded_c2pa_sidecar", error)
        return None
    return ExtractedReference(
        carrier=carrier,
        details={
            "manifest_store_size_bytes": len(sidecar),
            "manifest_store_sha256": base64url_encode(
                hashlib.sha256(sidecar).digest()
            ),
        },
    )


def _resolve_claim(
    service: RegistryService,
    reference: ExtractedReference,
) -> RegisteredClaim | None:
    if reference.claim_id is not None:
        try:
            return service.get_claim(reference.claim_id)
        except Exception:
            return None
    locator_value = reference.locator
    if reference.carrier == "image_watermark" and locator_value is not None:
        try:
            from pact.watermarks.base import TrustMarkLocator

            return service.find_claim_by_watermark_locator(
                TrustMarkLocator.from_dict(locator_value)
            )
        except Exception:
            return None
    return None


def _registry_verification(
    service: RegistryService,
    claim_id: UUID,
    *,
    content: bytes | None,
    nonce: bytes | None,
) -> dict[str, object] | None:
    try:
        return service.verify_claim(
            claim_id,
            content=content,
            nonce=nonce,
        ).to_dict()
    except Exception:
        return None


def _source_material_report(
    source: InspectionSource,
    *,
    signed: SignedManifest,
    registry_service: RegistryService | None,
    content: bytes | None,
    nonce: bytes | None,
) -> dict[str, object]:
    public_jwk = None
    if registry_service is not None:
        try:
            public_jwk = registry_service.get_profile(
                signed.manifest.claimant_key_id
            ).public_jwk
        except Exception:
            public_jwk = None
    report = None
    if public_jwk is not None:
        report = _manifest_verification(
            signed,
            public_jwk,
            content=content,
            nonce=nonce,
        )
    return {
        **source.to_dict(),
        "content_binding_checked": content is not None and nonce is not None,
        "verification": report,
    }


def _manifest_verification(
    signed: SignedManifest,
    public_jwk: Mapping[str, object],
    *,
    content: bytes | None,
    nonce: bytes | None,
) -> dict[str, object]:
    report: VerificationReport = verify_manifest(
        signed,
        public_jwk,
        content=content,
        nonce=nonce,
    )
    return {**asdict(report), "valid": report.valid}


def _content_for_reference(reference: ExtractedReference) -> bytes | None:
    return reference.content


def _nonce_for_reference(reference: ExtractedReference) -> bytes | None:
    if reference.locator is None:
        return None
    try:
        from pact.carriers.text import InvisibleLocator

        return InvisibleLocator.from_dict(reference.locator).nonce
    except (CarrierError, ValueError):
        return None


def _claim_dict(claim: RegisteredClaim) -> dict[str, object]:
    return {
        "claim_id": str(claim.claim_id),
        "claimant_key_id": claim.claimant_key_id,
        "registered_at": claim.registered_at.isoformat(),
        "revoked_at": None
        if claim.revoked_at is None
        else claim.revoked_at.isoformat(),
        "revocation_reason": claim.revocation_reason,
        "signed_manifest": claim.signed_manifest.to_dict(),
    }


def _record_error(
    errors: list[dict[str, str]],
    parser: str,
    error: Exception,
) -> None:
    errors.append({"parser": parser, "error": str(error)})


def _find_uuid(value: object, key: str) -> UUID | None:
    if isinstance(value, dict):
        item = value.get(key)
        if isinstance(item, str):
            try:
                return UUID(item)
            except ValueError:
                pass
        for child in value.values():
            found = _find_uuid(child, key)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = _find_uuid(child, key)
            if found is not None:
                return found
    return None


def _is_text(mime_type: str) -> bool:
    return mime_type.startswith("text/") or mime_type in {
        "application/json",
        "application/x-ndjson",
    }


def _is_html(mime_type: str) -> bool:
    return mime_type in {"text/html", "application/xhtml+xml"}


def _is_xml(mime_type: str) -> bool:
    return mime_type.endswith("+xml") or mime_type in {
        "application/xml",
        "text/xml",
    }


def _is_zip_document(mime_type: str) -> bool:
    return mime_type in {
        "application/epub+zip",
        "application/oxps",
        "application/vnd.ms-xpsdocument",
        "application/vnd.oasis.opendocument.presentation",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
