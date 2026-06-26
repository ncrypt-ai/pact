"""Shared types for watermark carriers and verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from pact.crypto import base64url_decode, base64url_encode

TRUSTMARK_WATERMARK_ID = "pact.trustmark.image.v1"
_TRUSTMARK_CONTEXT = b"pact:trustmark:image:v1\x00"
_TRUSTMARK_CHECKSUM_CONTEXT = b"pact:trustmark:image:v1:checksum\x00"
_TRUSTMARK_VERSION = 1
_TRUSTMARK_TAG_BYTES = 10
_TRUSTMARK_PAYLOAD_BYTES = 12


class WatermarkError(ValueError):
    """Raised when a watermark payload or image operation is invalid."""


class ImageWatermarkBackend(Protocol):
    """Minimal backend interface for image watermark embedding and decoding."""

    def capacity_bits(self) -> int: ...

    def embed_bits(
        self,
        image_bytes: bytes,
        mime_type: str,
        payload_bits: str,
        *,
        strength: float,
    ) -> bytes: ...

    def decode_bits(
        self,
        image_bytes: bytes,
        mime_type: str,
    ) -> tuple[str | None, int | None]: ...


@dataclass(frozen=True, slots=True)
class TrustMarkLocator:
    """Compact lookup token carried inside a TrustMark soft binding."""

    lookup_tag: bytes
    version: int = _TRUSTMARK_VERSION

    def __post_init__(self) -> None:
        if len(self.lookup_tag) != _TRUSTMARK_TAG_BYTES:
            raise WatermarkError("TrustMark lookup tags must be 10 bytes")
        if self.version != _TRUSTMARK_VERSION:
            raise WatermarkError("unsupported TrustMark locator version")

    @classmethod
    def create(cls, claim_id: UUID, registry_root_fingerprint: str) -> TrustMarkLocator:
        """Create a compact locator for one registered claim."""

        root_fingerprint = registry_root_fingerprint.encode("ascii")
        tag = hashlib.sha256(
            _TRUSTMARK_CONTEXT + claim_id.bytes + root_fingerprint
        ).digest()[:_TRUSTMARK_TAG_BYTES]
        return cls(tag)

    @classmethod
    def from_payload_bytes(cls, payload: bytes) -> TrustMarkLocator:
        """Parse and validate a raw 96-bit watermark payload."""

        if len(payload) != _TRUSTMARK_PAYLOAD_BYTES:
            raise WatermarkError("TrustMark payloads must be exactly 96 bits")
        version = payload[0]
        body = payload[:-1]
        checksum = payload[-1:]
        expected = hashlib.sha256(_TRUSTMARK_CHECKSUM_CONTEXT + body).digest()[:1]
        if checksum != expected:
            raise WatermarkError("TrustMark payload checksum does not match")
        return cls(payload[1:-1], version=version)

    @classmethod
    def from_payload_bits(cls, payload_bits: str) -> TrustMarkLocator:
        """Parse and validate a TrustMark binary payload string."""

        if len(payload_bits) != _TRUSTMARK_PAYLOAD_BYTES * 8:
            raise WatermarkError("TrustMark payloads must be exactly 96 bits")
        if set(payload_bits) - {"0", "1"}:
            raise WatermarkError("TrustMark payloads must be binary strings")
        payload = bytes(
            int(payload_bits[index : index + 8], 2)
            for index in range(0, len(payload_bits), 8)
        )
        return cls.from_payload_bytes(payload)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> TrustMarkLocator:
        """Parse a JSON-compatible locator payload."""

        version = value.get("version")
        lookup_tag = value.get("lookup_tag")
        if not isinstance(version, int):
            raise WatermarkError("TrustMark locator version must be an integer")
        if not isinstance(lookup_tag, str):
            raise WatermarkError("TrustMark lookup_tag must be a string")
        return cls(base64url_decode(lookup_tag, length=10), version=version)

    def to_payload_bytes(self) -> bytes:
        """Return the raw 96-bit payload for image embedding."""

        body = bytes([self.version]) + self.lookup_tag
        checksum = hashlib.sha256(_TRUSTMARK_CHECKSUM_CONTEXT + body).digest()[:1]
        return body + checksum

    def to_payload_bits(self) -> str:
        """Return the raw 96-bit payload as a binary string."""

        return "".join(f"{byte:08b}" for byte in self.to_payload_bytes())

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible locator representation."""

        return {
            "version": self.version,
            "lookup_tag": base64url_encode(self.lookup_tag),
            "payload_bits": self.to_payload_bits(),
        }

    def matches_claim(self, claim_id: UUID, registry_root_fingerprint: str) -> bool:
        """Return whether this locator belongs to the provided claim."""

        expected = type(self).create(claim_id, registry_root_fingerprint)
        return self.lookup_tag == expected.lookup_tag


@dataclass(frozen=True, slots=True)
class ImageWatermark:
    """Embedded image watermark output."""

    mime_type: str
    image_bytes: bytes
    locator: TrustMarkLocator
    watermark_id: str = TRUSTMARK_WATERMARK_ID

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible embedded watermark summary."""

        return {
            "mime_type": self.mime_type,
            "image_size_bytes": len(self.image_bytes),
            "locator": self.locator.to_dict(),
            "watermark_id": self.watermark_id,
        }


@dataclass(frozen=True, slots=True)
class DecodedImageWatermark:
    """Decoded TrustMark watermark output."""

    detected: bool
    locator: TrustMarkLocator | None
    decoder_version: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible decoded watermark summary."""

        return {
            "detected": self.detected,
            "locator": None if self.locator is None else self.locator.to_dict(),
            "decoder_version": self.decoder_version,
        }
