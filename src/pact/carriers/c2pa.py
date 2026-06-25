"""C2PA image carriers and external-manifest bootstrap helpers."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from c2pa import (
    Builder,
    C2paBuilderIntent,
    C2paDigitalSourceType,
    C2paSignerInfo,
    C2paSigningAlg,
    Reader,
    Signer,
)
from c2pa import (
    C2paError as NativeC2paError,
)

from pact.canonical import canonical_json
from pact.carriers.text import CarrierError
from pact.crypto import base64url_encode
from pact.manifest import SignedManifest

_SUPPORTED_READER_MIME_TYPES = frozenset(Reader.get_supported_mime_types())
_SUPPORTED_BUILDER_MIME_TYPES = frozenset(Builder.get_supported_mime_types())

_EMBEDDED_IMAGE_MIME_TYPES = tuple(
    mime_type
    for mime_type in (
        "image/avif",
        "image/dng",
        "image/gif",
        "image/heic",
        "image/heif",
        "image/jpeg",
        "image/jxl",
        "image/png",
        "image/svg+xml",
        "image/tiff",
        "image/webp",
    )
    if mime_type in _SUPPORTED_BUILDER_MIME_TYPES
)

_PDF_MIME_TYPES = {"application/pdf", "pdf"}


class C2paError(CarrierError):
    """Raised when C2PA credential operations fail."""


@dataclass(frozen=True, slots=True)
class C2paSignerMaterial:
    """PEM signer material accepted by the official C2PA SDK."""

    certificate_chain_pem: bytes
    private_key_pem: bytes
    algorithm: C2paSigningAlg = C2paSigningAlg.ES256
    tsa_url: bytes = b""

    def to_sdk_signer(self) -> Signer:
        """Create an SDK Signer from PEM material."""

        try:
            return Signer.from_info(
                C2paSignerInfo(
                    self.algorithm,
                    self.certificate_chain_pem,
                    self.private_key_pem,
                    self.tsa_url,
                )
            )
        except (NativeC2paError, TypeError, ValueError) as error:
            raise C2paError("invalid C2PA signer material") from error


@dataclass(frozen=True, slots=True)
class C2paAsset:
    """Embedded C2PA output for a signable asset."""

    mime_type: str
    asset_bytes: bytes
    manifest_store_bytes: bytes


@dataclass(frozen=True, slots=True)
class C2paReadResult:
    """Parsed C2PA data recovered from an asset."""

    mime_type: str
    embedded: bool
    validation_state: str | None
    active_manifest: dict[str, Any] | None
    validation_results: dict[str, Any] | None
    manifest_store_json: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ExternalManifestReference:
    """Spec-aligned external-manifest reference metadata."""

    asset_mime_type: str
    manifest_uri: str
    media_type: str
    provenance_uri: str
    claim_id: str
    registry_url: str
    asset_sha256: str
    visible_notice: str

    def to_dict(self) -> dict[str, str]:
        """Return the bootstrap metadata as a JSON-compatible mapping."""

        return {
            "asset_mime_type": self.asset_mime_type,
            "manifest_uri": self.manifest_uri,
            "media_type": self.media_type,
            "provenance_uri": self.provenance_uri,
            "claim_id": self.claim_id,
            "registry_url": self.registry_url,
            "asset_sha256": self.asset_sha256,
            "visible_notice": self.visible_notice,
        }

    def to_json(self) -> bytes:
        """Return canonical JSON bytes for the external-manifest reference."""

        return canonical_json(self.to_dict())


def c2pa_supported_reader_mime_types() -> tuple[str, ...]:
    """Return MIME types the installed SDK can read."""

    return tuple(sorted(_SUPPORTED_READER_MIME_TYPES))


def c2pa_supported_builder_mime_types() -> tuple[str, ...]:
    """Return MIME types the installed SDK can embed."""

    return tuple(sorted(_SUPPORTED_BUILDER_MIME_TYPES))


def c2pa_supported_embedded_image_mime_types() -> tuple[str, ...]:
    """Return image MIME types supported for embedded C2PA writing."""

    return _EMBEDDED_IMAGE_MIME_TYPES


def c2pa_pdf_embedding_supported() -> bool:
    """Return whether the installed SDK can embed C2PA into PDFs."""

    return any(mime_type in _SUPPORTED_BUILDER_MIME_TYPES for mime_type in _PDF_MIME_TYPES)


def build_c2pa_manifest_definition(
    signed: SignedManifest,
    *,
    title: str,
    claim_generator: str = "pact",
) -> dict[str, object]:
    """Build a minimal manifest definition accepted by the C2PA SDK."""

    return {
        "claim_generator": claim_generator,
        "title": title,
        "assertions": [],
        "metadata": {
            "pact_claim_id": str(signed.manifest.claim_id),
            "pact_registry_url": signed.manifest.registry_url,
            "pact_manifest_sha256": base64url_encode(
                hashlib.sha256(signed.to_json()).digest()
            ),
        },
    }


def embed_c2pa_image(
    asset_bytes: bytes,
    mime_type: str,
    *,
    signed: SignedManifest,
    signer_material: C2paSignerMaterial,
    title: str,
    claim_generator: str = "pact",
    digital_source_type: C2paDigitalSourceType = C2paDigitalSourceType.DIGITAL_CREATION,
) -> C2paAsset:
    """Embed a C2PA manifest store into a supported image asset."""

    if mime_type not in _EMBEDDED_IMAGE_MIME_TYPES:
        raise C2paError(
            "embedded C2PA writing is only available for supported image formats"
        )
    manifest_definition = build_c2pa_manifest_definition(
        signed,
        title=title,
        claim_generator=claim_generator,
    )
    try:
        with Builder(manifest_definition) as builder:
            builder.set_intent(
                C2paBuilderIntent.CREATE,
                digital_source_type=digital_source_type,
            )
            with signer_material.to_sdk_signer() as signer:
                import io

                source = io.BytesIO(asset_bytes)
                dest = io.BytesIO()
                manifest_store = builder.sign(signer, mime_type, source, dest)
                return C2paAsset(
                    mime_type=mime_type,
                    asset_bytes=dest.getvalue(),
                    manifest_store_bytes=manifest_store,
                )
    except NativeC2paError as error:
        raise C2paError(f"C2PA image embedding failed: {error}") from error


def read_c2pa_asset(
    asset: bytes | str | Path,
    *,
    mime_type: str | None = None,
) -> C2paReadResult:
    """Read a C2PA manifest store from an asset path or in-memory bytes."""

    try:
        if isinstance(asset, (str, Path)):
            reader = Reader(asset)
            result_mime_type = mime_type or Path(asset).suffix.lstrip(".")
        else:
            if mime_type is None:
                raise C2paError("mime_type is required when reading raw bytes")
            import io

            reader = Reader(mime_type, io.BytesIO(asset))
            result_mime_type = mime_type
    except NativeC2paError as error:
        raise C2paError(f"C2PA asset reading failed: {error}") from error

    with reader:
        try:
            manifest_store_json = json.loads(reader.json())
        except json.JSONDecodeError as error:
            raise C2paError("C2PA manifest store JSON is invalid") from error
        return C2paReadResult(
            mime_type=result_mime_type,
            embedded=reader.is_embedded(),
            validation_state=reader.get_validation_state(),
            active_manifest=reader.get_active_manifest(),
            validation_results=reader.get_validation_results(),
            manifest_store_json=manifest_store_json,
        )


def build_external_manifest_reference(
    asset_bytes: bytes,
    asset_mime_type: str,
    signed: SignedManifest,
    *,
    manifest_uri: str,
) -> ExternalManifestReference:
    """Create a spec-aligned external-manifest reference description."""

    if not manifest_uri:
        raise C2paError("manifest_uri must not be blank")
    digest = base64url_encode(hashlib.sha256(asset_bytes).digest())
    notice = (
        "This asset references external Content Credentials at "
        f"{manifest_uri}."
    )
    return ExternalManifestReference(
        asset_mime_type=asset_mime_type,
        manifest_uri=manifest_uri,
        media_type="application/c2pa",
        provenance_uri=manifest_uri,
        claim_id=str(signed.manifest.claim_id),
        registry_url=signed.manifest.registry_url,
        asset_sha256=digest,
        visible_notice=notice,
    )


def pdf_external_manifest_reference(
    pdf_bytes: bytes,
    signed: SignedManifest,
    *,
    manifest_uri: str,
) -> ExternalManifestReference:
    """Create a PDF external-manifest reference bootstrap."""

    return build_external_manifest_reference(
        pdf_bytes,
        "application/pdf",
        signed,
        manifest_uri=manifest_uri,
    )
