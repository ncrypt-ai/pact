"""TrustMark-backed soft bindings for registered image claims."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, cast
from uuid import UUID

from pact.watermarks.base import (
    TRUSTMARK_WATERMARK_ID,
    DecodedImageWatermark,
    ImageWatermark,
    ImageWatermarkBackend,
    TrustMarkLocator,
    WatermarkError,
)

if TYPE_CHECKING:
    from pact.registry.app import RegisteredClaim, RegistryService

SUPPORTED_IMAGE_WATERMARK_MIME_TYPES = (
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/webp",
)

_PILLOW_SAVE_FORMATS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/tiff": "TIFF",
    "image/webp": "WEBP",
}


class ImageWatermarkDependencyError(WatermarkError):
    """Raised when optional image watermark dependencies are unavailable."""


@dataclass(frozen=True, slots=True)
class ImageSoftBindingVerification:
    """Result of resolving a decoded watermark against one registry."""

    detected: bool
    locator: TrustMarkLocator | None
    claim: RegisteredClaim | None
    reason: str | None = None

    @property
    def registry_match(self) -> bool:
        """Whether the decoded locator resolved to one registry claim."""

        return self.claim is not None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible verification summary."""

        return {
            "detected": self.detected,
            "locator": None if self.locator is None else self.locator.to_dict(),
            "claim_id": None if self.claim is None else str(self.claim.claim_id),
            "claimant_key_id": (
                None if self.claim is None else self.claim.claimant_key_id
            ),
            "reason": self.reason,
            "registry_match": self.registry_match,
        }


def _require_supported_image_mime_type(mime_type: str) -> str:
    if mime_type not in SUPPORTED_IMAGE_WATERMARK_MIME_TYPES:
        raise WatermarkError(
            "unsupported image watermark MIME type; expected one of "
            + ", ".join(SUPPORTED_IMAGE_WATERMARK_MIME_TYPES)
        )
    return mime_type


def trustmark_supported_image_mime_types() -> tuple[str, ...]:
    """Return image MIME types supported by the TrustMark wrapper."""

    return SUPPORTED_IMAGE_WATERMARK_MIME_TYPES


class TrustMarkBackend:
    """Thin adapter around the optional TrustMark runtime."""

    def __init__(
        self,
        *,
        model_type: str = "Q",
        use_ecc: bool = False,
        verbose: bool = False,
    ) -> None:
        self.model_type = model_type
        self.use_ecc = use_ecc
        self.verbose = verbose
        self._engine = self._load_engine()

    def _load_engine(self):  # type: ignore[no-untyped-def]
        try:
            from trustmark import TrustMark
        except ImportError as error:
            raise ImageWatermarkDependencyError(
                "TrustMark support requires the optional "
                "'image-watermark' dependency group"
            ) from error
        engine = TrustMark(
            verbose=self.verbose,
            model_type=self.model_type,
            use_ECC=self.use_ecc,
            secret_len=96,
            loadRemover=False,
            loadBBoxDetector=False,
        )
        if engine.encoder is None or engine.decoder is None:
            raise ImageWatermarkDependencyError(
                "TrustMark model files are unavailable. Install the "
                "'image-watermark' dependency group and allow the runtime "
                "to download the TrustMark checkpoints on first use."
            )
        return engine

    def _load_image(self, image_bytes: bytes):
        try:
            from PIL import Image
        except ImportError as error:
            raise ImageWatermarkDependencyError(
                "TrustMark support requires Pillow from the "
                "'image-watermark' dependency group"
            ) from error
        image = Image.open(BytesIO(image_bytes))
        return image.convert("RGB")

    def capacity_bits(self) -> int:
        return int(self._engine.schemaCapacity())

    def embed_bits(
        self,
        image_bytes: bytes,
        mime_type: str,
        payload_bits: str,
        *,
        strength: float,
    ) -> bytes:
        image = self._load_image(image_bytes)
        watermarked = self._engine.encode(
            image,
            payload_bits,
            MODE="binary",
            WM_STRENGTH=strength,
        )
        output = BytesIO()
        watermarked.save(output, format=_PILLOW_SAVE_FORMATS[mime_type])
        return output.getvalue()

    def decode_bits(
        self,
        image_bytes: bytes,
        mime_type: str,
    ) -> tuple[str | None, int | None]:
        del mime_type
        image = self._load_image(image_bytes)
        payload_bits, detected, version = self._engine.decode(image, MODE="binary")
        if not detected:
            return None, None
        return cast(str, payload_bits), cast(int, version)


def embed_image_soft_binding(
    image_bytes: bytes,
    mime_type: str,
    *,
    claim_id: UUID,
    registry_root_fingerprint: str,
    strength: float = 1.0,
    backend: ImageWatermarkBackend | None = None,
) -> ImageWatermark:
    """Embed a TrustMark soft binding that resolves to one registered claim."""

    mime_type = _require_supported_image_mime_type(mime_type)
    locator = TrustMarkLocator.create(claim_id, registry_root_fingerprint)
    payload_bits = locator.to_payload_bits()
    resolved_backend = backend or TrustMarkBackend()
    if resolved_backend.capacity_bits() < len(payload_bits):
        raise WatermarkError("watermark backend capacity is too small for PACT")
    watermarked_bytes = resolved_backend.embed_bits(
        image_bytes,
        mime_type,
        payload_bits,
        strength=strength,
    )
    return ImageWatermark(
        mime_type=mime_type,
        image_bytes=watermarked_bytes,
        locator=locator,
    )


def decode_image_soft_binding(
    image_bytes: bytes,
    mime_type: str,
    *,
    backend: ImageWatermarkBackend | None = None,
) -> DecodedImageWatermark:
    """Decode a TrustMark soft binding from an image, if present."""

    mime_type = _require_supported_image_mime_type(mime_type)
    resolved_backend = backend or TrustMarkBackend()
    payload_bits, version = resolved_backend.decode_bits(image_bytes, mime_type)
    if payload_bits is None:
        return DecodedImageWatermark(detected=False, locator=None)
    locator = TrustMarkLocator.from_payload_bits(payload_bits)
    return DecodedImageWatermark(
        detected=True,
        locator=locator,
        decoder_version=version,
    )


def verify_image_soft_binding(
    image_bytes: bytes,
    mime_type: str,
    *,
    registry_service: RegistryService,
    backend: ImageWatermarkBackend | None = None,
) -> ImageSoftBindingVerification:
    """Decode a TrustMark watermark and resolve it against one registry."""

    decoded = decode_image_soft_binding(
        image_bytes,
        mime_type,
        backend=backend,
    )
    if decoded.locator is None:
        return ImageSoftBindingVerification(
            detected=False,
            locator=None,
            claim=None,
            reason="no TrustMark locator detected",
        )
    claim = registry_service.find_claim_by_watermark_locator(decoded.locator)
    if claim is None:
        return ImageSoftBindingVerification(
            detected=True,
            locator=decoded.locator,
            claim=None,
            reason="locator did not match any registered claim",
        )
    return ImageSoftBindingVerification(
        detected=True,
        locator=decoded.locator,
        claim=claim,
    )


def watermark_id_for_image_soft_binding() -> str:
    """Return the manifest watermark identifier for TrustMark soft bindings."""

    return TRUSTMARK_WATERMARK_ID
