"""TrustMark-backed soft bindings for registered image claims."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from math import cos, pi, sqrt
from typing import TYPE_CHECKING, Literal, cast
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
PERCEPTUAL_IMAGE_WATERMARK_ID = "pact.perceptual.image.v1"

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
            "locator": None
            if self.locator is None
            else self.locator.to_dict(),
            "claim_id": None
            if self.claim is None
            else str(self.claim.claim_id),
            "claimant_key_id": (
                None if self.claim is None else self.claim.claimant_key_id
            ),
            "reason": self.reason,
            "registry_match": self.registry_match,
        }


@dataclass(frozen=True, slots=True)
class ImagePerceptualHash:
    """One 64-bit perceptual hash for a transformed image view."""

    algorithm: Literal["ahash", "dhash", "phash"]
    transform: str
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 16:
            raise WatermarkError("perceptual hash values must be 64-bit hex")
        try:
            int(self.value, 16)
        except ValueError as error:
            raise WatermarkError(
                "perceptual hash values must be hex"
            ) from error

    def distance(self, other: ImagePerceptualHash) -> int:
        """Return the Hamming distance to another compatible hash."""

        if self.algorithm != other.algorithm:
            raise WatermarkError("perceptual hash algorithms must match")
        left = int(self.value, 16)
        right = int(other.value, 16)
        return (left ^ right).bit_count()

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-compatible hash record."""

        return {
            "algorithm": self.algorithm,
            "transform": self.transform,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ImagePerceptualHash:
        """Parse a JSON-compatible hash record."""

        algorithm = value.get("algorithm")
        transform = value.get("transform")
        hash_value = value.get("value")
        if algorithm not in {"ahash", "dhash", "phash"}:
            raise WatermarkError("unsupported perceptual hash algorithm")
        if not isinstance(transform, str) or not transform:
            raise WatermarkError("perceptual hash transform must be a string")
        if not isinstance(hash_value, str):
            raise WatermarkError("perceptual hash value must be a string")
        return cls(
            algorithm=cast(Literal["ahash", "dhash", "phash"], algorithm),
            transform=transform,
            value=hash_value,
        )


@dataclass(frozen=True, slots=True)
class ImagePerceptualFingerprint:
    """Perceptual hashes computed from an image and expected transformations."""

    mime_type: str
    width: int
    height: int
    hashes: tuple[ImagePerceptualHash, ...]
    fingerprint_id: str = PERCEPTUAL_IMAGE_WATERMARK_ID

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible fingerprint."""

        return {
            "fingerprint_id": self.fingerprint_id,
            "mime_type": self.mime_type,
            "width": self.width,
            "height": self.height,
            "hashes": [item.to_dict() for item in self.hashes],
        }

    @classmethod
    def from_dict(
        cls,
        value: dict[str, object],
    ) -> ImagePerceptualFingerprint:
        """Parse a JSON-compatible fingerprint."""

        fingerprint_id = value.get("fingerprint_id")
        mime_type = value.get("mime_type")
        width = value.get("width")
        height = value.get("height")
        hashes = value.get("hashes")
        if fingerprint_id != PERCEPTUAL_IMAGE_WATERMARK_ID:
            raise WatermarkError(
                "unsupported perceptual fingerprint identifier"
            )
        resolved_fingerprint_id = cast(str, fingerprint_id)
        if not isinstance(mime_type, str):
            raise WatermarkError(
                "perceptual fingerprint mime_type must be a string"
            )
        if not isinstance(width, int) or not isinstance(height, int):
            raise WatermarkError(
                "perceptual fingerprint dimensions must be integers"
            )
        if not isinstance(hashes, list):
            raise WatermarkError(
                "perceptual fingerprint hashes must be an array"
            )
        parsed_hashes = tuple(
            ImagePerceptualHash.from_dict(cast(dict[str, object], item))
            for item in hashes
        )
        return cls(
            mime_type=mime_type,
            width=width,
            height=height,
            hashes=parsed_hashes,
            fingerprint_id=resolved_fingerprint_id,
        )


@dataclass(frozen=True, slots=True)
class ImagePerceptualMatch:
    """Similarity report between two perceptual image fingerprints."""

    matched: bool
    score: float
    inspected: int
    matches: int
    min_distance: int | None
    threshold: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible match report."""

        return {
            "matched": self.matched,
            "score": self.score,
            "inspected": self.inspected,
            "matches": self.matches,
            "min_distance": self.min_distance,
            "threshold": self.threshold,
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


def perceptual_image_watermark_id() -> str:
    """Return the manifest watermark identifier for perceptual fingerprints."""

    return PERCEPTUAL_IMAGE_WATERMARK_ID


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
        payload_bits, detected, version = self._engine.decode(
            image, MODE="binary"
        )
        if not detected:
            return None, None
        return cast(str, payload_bits), cast(int, version)


def _load_rgb_image(image_bytes: bytes):
    try:
        from PIL import Image
    except ImportError as error:
        raise ImageWatermarkDependencyError(
            "perceptual image fingerprints require Pillow from the "
            "'image-watermark' dependency group"
        ) from error
    image = Image.open(BytesIO(image_bytes))
    return image.convert("RGB")


def _resample_lanczos():
    try:
        from PIL import Image
    except ImportError as error:
        raise ImageWatermarkDependencyError(
            "perceptual image fingerprints require Pillow from the "
            "'image-watermark' dependency group"
        ) from error
    return Image.Resampling.LANCZOS


def _image_to_grayscale_values(image, size: tuple[int, int]) -> list[int]:
    gray = image.convert("L").resize(size, _resample_lanczos())
    flattened = getattr(gray, "get_flattened_data", None)
    if flattened is not None:
        return list(flattened())
    return list(gray.getdata())


def _bits_to_hex(bits: list[bool]) -> str:
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return f"{value:016x}"


def _average_hash(image) -> str:
    values = _image_to_grayscale_values(image, (8, 8))
    threshold = sum(values) / len(values)
    return _bits_to_hex([value >= threshold for value in values])


def _difference_hash(image) -> str:
    values = _image_to_grayscale_values(image, (9, 8))
    bits = []
    for row in range(8):
        start = row * 9
        for column in range(8):
            bits.append(values[start + column] > values[start + column + 1])
    return _bits_to_hex(bits)


def _dct_coefficient(values: list[float], u: int, v: int) -> float:
    total = 0.0
    for y in range(32):
        for x in range(32):
            total += (
                values[y * 32 + x]
                * cos(((2 * x + 1) * u * pi) / 64)
                * cos(((2 * y + 1) * v * pi) / 64)
            )
    au = 1 / sqrt(2) if u == 0 else 1
    av = 1 / sqrt(2) if v == 0 else 1
    return 0.25 * au * av * total


def _perceptual_hash(image) -> str:
    values = [
        float(value) for value in _image_to_grayscale_values(image, (32, 32))
    ]
    coefficients = [
        _dct_coefficient(values, u, v) for v in range(8) for u in range(8)
    ]
    low_frequency = coefficients[1:]
    threshold = sorted(low_frequency)[len(low_frequency) // 2]
    return _bits_to_hex([value >= threshold for value in coefficients])


def _center_crop(image, ratio: float):
    width, height = image.size
    crop_width = max(1, int(width * ratio))
    crop_height = max(1, int(height * ratio))
    left = (width - crop_width) // 2
    top = (height - crop_height) // 2
    return image.crop((left, top, left + crop_width, top + crop_height))


def _round_trip_image(image, mime_type: str, *, quality: int = 80):
    output = BytesIO()
    image.save(
        output,
        format=_PILLOW_SAVE_FORMATS[mime_type],
        quality=quality,
    )
    return _load_rgb_image(output.getvalue())


def _round_trip_format(image, image_format: str, *, quality: int = 80):
    output = BytesIO()
    image.save(output, format=image_format, quality=quality)
    return _load_rgb_image(output.getvalue())


def _fingerprint_transformations(
    image, mime_type: str
) -> tuple[tuple[str, object], ...]:
    from PIL import ImageEnhance, ImageFilter

    width, height = image.size
    small_size = (max(8, width // 2), max(8, height // 2))
    resized = image.resize(small_size, _resample_lanczos()).resize(
        (width, height),
        _resample_lanczos(),
    )
    cropped_90 = _center_crop(image, 0.90).resize(
        (width, height),
        _resample_lanczos(),
    )
    cropped_75 = _center_crop(image, 0.75).resize(
        (width, height),
        _resample_lanczos(),
    )
    recompressed = _round_trip_image(image, mime_type)
    jpeg_roundtrip = _round_trip_format(image, "JPEG")
    webp_roundtrip = _round_trip_format(image, "WEBP")
    photo_resampled = ImageEnhance.Contrast(
        image.filter(ImageFilter.GaussianBlur(radius=0.4))
    ).enhance(1.08)
    return (
        ("original", image),
        ("resize-half", resized),
        ("crop-90", cropped_90),
        ("crop-75", cropped_75),
        ("recompress", recompressed),
        ("format-jpeg", jpeg_roundtrip),
        ("format-webp", webp_roundtrip),
        ("photo-resample", photo_resampled),
    )


def create_image_perceptual_fingerprint(
    image_bytes: bytes,
    mime_type: str,
) -> ImagePerceptualFingerprint:
    """Create robust perceptual hashes for an image and common transformations."""

    mime_type = _require_supported_image_mime_type(mime_type)
    image = _load_rgb_image(image_bytes)
    hashes: list[ImagePerceptualHash] = []
    for transform, transformed in _fingerprint_transformations(
        image, mime_type
    ):
        hashes.extend(
            (
                ImagePerceptualHash(
                    "ahash", transform, _average_hash(transformed)
                ),
                ImagePerceptualHash(
                    "dhash", transform, _difference_hash(transformed)
                ),
                ImagePerceptualHash(
                    "phash", transform, _perceptual_hash(transformed)
                ),
            )
        )
    width, height = image.size
    return ImagePerceptualFingerprint(
        mime_type=mime_type,
        width=width,
        height=height,
        hashes=tuple(hashes),
    )


def compare_image_perceptual_fingerprints(
    expected: ImagePerceptualFingerprint,
    observed: ImagePerceptualFingerprint,
    *,
    threshold: int = 10,
    minimum_score: float = 0.60,
) -> ImagePerceptualMatch:
    """Compare two transformed perceptual fingerprint sets."""

    if threshold < 0 or threshold > 64:
        raise WatermarkError(
            "perceptual hash threshold must be between 0 and 64"
        )
    if not 0.0 <= minimum_score <= 1.0:
        raise WatermarkError("minimum_score must be between 0.0 and 1.0")
    expected_hashes = expected.hashes
    observed_by_algorithm: dict[str, list[ImagePerceptualHash]] = {}
    for item in observed.hashes:
        observed_by_algorithm.setdefault(item.algorithm, []).append(item)
    distances: list[int] = []
    matches = 0
    for expected_hash in expected_hashes:
        candidates = observed_by_algorithm.get(expected_hash.algorithm, [])
        if not candidates:
            continue
        distance = min(
            expected_hash.distance(candidate) for candidate in candidates
        )
        distances.append(distance)
        if distance <= threshold:
            matches += 1
    inspected = len(distances)
    score = 0.0 if inspected == 0 else matches / inspected
    return ImagePerceptualMatch(
        matched=score >= minimum_score,
        score=score,
        inspected=inspected,
        matches=matches,
        min_distance=None if not distances else min(distances),
        threshold=threshold,
    )


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
        raise WatermarkError(
            "watermark backend capacity is too small for PACT"
        )
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
    payload_bits, version = resolved_backend.decode_bits(
        image_bytes, mime_type
    )
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
