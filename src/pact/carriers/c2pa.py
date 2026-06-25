"""C2PA carriers and external-manifest bootstrap helpers."""

import hashlib
import json
import zipfile
from dataclasses import dataclass
from io import BytesIO
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
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    TextStringObject,
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
_ZIP_MANIFEST_PATH = "META-INF/content_credential.c2pa"
_ZIP_BASED_MIME_TYPES = {
    "application/epub+zip",
    "application/oxps",
    "application/vnd.ms-xpsdocument",
    "application/vnd.oasis.opendocument.presentation",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "docx",
    "epub",
    "odp",
    "ods",
    "odt",
    "oxps",
    "pptx",
    "xlsx",
}


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
    """Return whether this package can embed C2PA manifest stores into PDFs."""

    return True


def c2pa_supported_embedded_document_mime_types() -> tuple[str, ...]:
    """Return document/container formats this package can embed into."""

    return tuple(sorted({"application/pdf", *_ZIP_BASED_MIME_TYPES}))


def _require_manifest_store_bytes(manifest_store_bytes: bytes) -> None:
    if not manifest_store_bytes:
        raise C2paError("manifest_store_bytes must not be empty")


def _normalize_document_mime_type(mime_type: str) -> str:
    normalized = mime_type.strip().lower()
    aliases = {
        "pdf": "application/pdf",
        "docx": (
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document"
        ),
        "xlsx": (
            "application/vnd.openxmlformats-officedocument"
            ".spreadsheetml.sheet"
        ),
        "pptx": (
            "application/vnd.openxmlformats-officedocument"
            ".presentationml.presentation"
        ),
        "odt": "application/vnd.oasis.opendocument.text",
        "ods": "application/vnd.oasis.opendocument.spreadsheet",
        "odp": "application/vnd.oasis.opendocument.presentation",
        "epub": "application/epub+zip",
        "oxps": "application/oxps",
    }
    return aliases.get(normalized, normalized)


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


def embed_c2pa_manifest_in_pdf(
    pdf_bytes: bytes,
    manifest_store_bytes: bytes,
    *,
    filename: str = "content_credential.c2pa",
    description: str = "C2PA Manifest Store",
) -> C2paAsset:
    """Embed a prebuilt C2PA manifest store into a PDF embedded file stream."""

    _require_manifest_store_bytes(manifest_store_bytes)
    try:
        reader = PdfReader(BytesIO(pdf_bytes))
        writer = PdfWriter()
        writer.clone_document_from_reader(reader)
        embedded = writer.add_attachment(filename, manifest_store_bytes)
        embedded.subtype = NameObject("/application/c2pa")
        embedded.associated_file_relationship = NameObject("/C2PA_Manifest")
        embedded.description = TextStringObject(description)
        writer.root_object[NameObject("/AF")] = ArrayObject(
            [embedded.pdf_object.indirect_reference]
        )
        destination = BytesIO()
        writer.write(destination)
    except Exception as error:  # pragma: no cover - pypdf errors vary by input
        raise C2paError(f"C2PA PDF embedding failed: {error}") from error
    return C2paAsset(
        mime_type="application/pdf",
        asset_bytes=destination.getvalue(),
        manifest_store_bytes=manifest_store_bytes,
    )


def extract_c2pa_manifest_from_pdf(pdf_bytes: bytes) -> bytes:
    """Extract the active C2PA manifest store from a PDF embedded file stream."""

    try:
        reader = PdfReader(BytesIO(pdf_bytes))
        root = reader.trailer["/Root"].get_object()
        if not isinstance(root, DictionaryObject):
            raise C2paError("PDF catalog is malformed")
        associated_files = root.get("/AF")
        if associated_files is None:
            raise C2paError("PDF does not contain a C2PA associated file")
        for file_spec in associated_files:
            resolved = file_spec.get_object()
            if resolved.get("/AFRelationship") != "/C2PA_Manifest":
                continue
            embedded_files = resolved.get("/EF")
            if embedded_files is None or "/F" not in embedded_files:
                continue
            return embedded_files["/F"].get_object().get_data()
    except C2paError:
        raise
    except Exception as error:  # pragma: no cover - pypdf errors vary by input
        raise C2paError(f"C2PA PDF extraction failed: {error}") from error
    raise C2paError("PDF does not contain a C2PA manifest store")


def embed_c2pa_manifest_in_zip_document(
    asset_bytes: bytes,
    mime_type: str,
    manifest_store_bytes: bytes,
) -> C2paAsset:
    """Embed a prebuilt C2PA manifest store in a ZIP-based document format."""

    _require_manifest_store_bytes(manifest_store_bytes)
    normalized_mime_type = _normalize_document_mime_type(mime_type)
    if normalized_mime_type not in c2pa_supported_embedded_document_mime_types():
        raise C2paError(
            "ZIP-based C2PA embedding is only available for supported document"
            " formats"
        )
    if normalized_mime_type == "application/pdf":
        raise C2paError("use embed_c2pa_manifest_in_pdf() for PDFs")

    try:
        source_buffer = BytesIO(asset_bytes)
        destination_buffer = BytesIO()
        with zipfile.ZipFile(source_buffer) as source_zip:
            with zipfile.ZipFile(destination_buffer, "w") as destination_zip:
                destination_zip.comment = source_zip.comment
                seen_manifest = False
                for info in source_zip.infolist():
                    if info.filename == _ZIP_MANIFEST_PATH:
                        seen_manifest = True
                        continue
                    copied = zipfile.ZipInfo(info.filename, info.date_time)
                    copied.compress_type = info.compress_type
                    copied.comment = info.comment
                    copied.create_system = info.create_system
                    copied.create_version = info.create_version
                    copied.extract_version = info.extract_version
                    copied.flag_bits = info.flag_bits
                    copied.external_attr = info.external_attr
                    copied.internal_attr = info.internal_attr
                    copied.volume = info.volume
                    copied.extra = info.extra
                    destination_zip.writestr(copied, source_zip.read(info.filename))

                manifest_info = zipfile.ZipInfo(_ZIP_MANIFEST_PATH)
                manifest_info.compress_type = zipfile.ZIP_STORED
                destination_zip.writestr(manifest_info, manifest_store_bytes)
                _ = seen_manifest
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise C2paError(f"C2PA ZIP embedding failed: {error}") from error

    return C2paAsset(
        mime_type=normalized_mime_type,
        asset_bytes=destination_buffer.getvalue(),
        manifest_store_bytes=manifest_store_bytes,
    )


def extract_c2pa_manifest_from_zip_document(asset_bytes: bytes) -> bytes:
    """Extract an embedded C2PA manifest store from a ZIP-based document."""

    try:
        with zipfile.ZipFile(BytesIO(asset_bytes)) as archive:
            return archive.read(_ZIP_MANIFEST_PATH)
    except KeyError as error:
        raise C2paError("ZIP document does not contain a C2PA manifest store") from error
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise C2paError(f"C2PA ZIP extraction failed: {error}") from error


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
