"""Shared types for watermark carriers and verification."""

from __future__ import annotations

import difflib
import hashlib
import re
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
    def create(
        cls, claim_id: UUID, registry_root_fingerprint: str
    ) -> TrustMarkLocator:
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
        expected = hashlib.sha256(_TRUSTMARK_CHECKSUM_CONTEXT + body).digest()[
            :1
        ]
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
            raise WatermarkError(
                "TrustMark locator version must be an integer"
            )
        if not isinstance(lookup_tag, str):
            raise WatermarkError("TrustMark lookup_tag must be a string")
        return cls(base64url_decode(lookup_tag, length=10), version=version)

    def to_payload_bytes(self) -> bytes:
        """Return the raw 96-bit payload for image embedding."""

        body = bytes([self.version]) + self.lookup_tag
        checksum = hashlib.sha256(_TRUSTMARK_CHECKSUM_CONTEXT + body).digest()[
            :1
        ]
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

    def matches_claim(
        self, claim_id: UUID, registry_root_fingerprint: str
    ) -> bool:
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
            "locator": None
            if self.locator is None
            else self.locator.to_dict(),
            "decoder_version": self.decoder_version,
        }


@dataclass(frozen=True, slots=True)
class TextWatermarkParameters:
    """Safety and behavior controls for experimental text watermarking."""

    user_confirmation: bool = False
    allow_semantic_methods: bool = False
    approved_canary_phrase: str | None = None
    max_changes: int = 8
    selection_stride: int = 3


@dataclass(frozen=True, slots=True)
class TextWatermarkEligibility:
    """Result of checking whether content is safe to transform."""

    prose_like: bool
    blocked_reasons: tuple[str, ...]
    locked_spans: tuple[tuple[int, int], ...]

    @property
    def allowed(self) -> bool:
        """Whether the content may be transformed."""

        return self.prose_like and not self.blocked_reasons


@dataclass(frozen=True, slots=True)
class TextWatermarkRecord:
    """One experimental text watermark embedding record."""

    method_id: str
    secret_digest: str
    metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible embedding record."""

        return {
            "method_id": self.method_id,
            "secret_digest": self.secret_digest,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class TextWatermarkDetection:
    """Detection measurements for one text watermark method."""

    method_id: str
    detected: bool
    score: float
    inspected: int
    matches: int
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible detection report."""

        return {
            "method_id": self.method_id,
            "detected": self.detected,
            "score": self.score,
            "inspected": self.inspected,
            "matches": self.matches,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class TextWatermarkQualityReport:
    """Diff and safety report for a text watermark transform."""

    method_id: str
    safe: bool
    changed_lines: int
    changed_characters: int
    unified_diff: str
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible quality report."""

        return {
            "method_id": self.method_id,
            "safe": self.safe,
            "changed_lines": self.changed_lines,
            "changed_characters": self.changed_characters,
            "unified_diff": self.unified_diff,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class TextWatermarkEmbedding:
    """Embedded experimental watermark plus its review artifacts."""

    transformed_content: str
    record: TextWatermarkRecord
    quality_report: TextWatermarkQualityReport

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible embedding summary."""

        return {
            "transformed_content": self.transformed_content,
            "record": self.record.to_dict(),
            "quality_report": self.quality_report.to_dict(),
        }


class TextWatermarkPlugin(Protocol):
    """Common interface for experimental text watermark plugins."""

    method_id: str
    semantic: bool

    def embed(
        self,
        content: str,
        secret: bytes | str,
        parameters: TextWatermarkParameters,
    ) -> TextWatermarkEmbedding: ...

    def detect(
        self,
        content_or_outputs: str,
        secret: bytes | str,
        record: TextWatermarkRecord,
    ) -> TextWatermarkDetection: ...

    def assess(
        self,
        original: str,
        transformed: str,
    ) -> TextWatermarkQualityReport: ...


_URL_PATTERN = re.compile(r"https?://\S+")
_INLINE_CODE_PATTERN = re.compile(r"`[^`\n]+`")
_QUOTE_PATTERN = re.compile(r"\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'")
_CITATION_PATTERN = re.compile(r"\[[0-9,\s]+\]")
_SENTENCE_PATTERN = re.compile(r"[^.!?]+[.!?]|[^.!?]+$")
_CODE_HINTS = (
    "```",
    "#!/usr/bin",
    "import ",
    "def ",
    "class ",
    "{",
    "}",
    "<html",
)
_LEGAL_HINTS = (
    "terms and conditions",
    "governing law",
    "limitation of liability",
    "indemnify",
    "warranty",
)
_MEDICAL_SAFETY_HINTS = (
    "dosage",
    "contraindication",
    "first aid",
    "warning:",
    "danger:",
    "hazard",
    "emergency",
)


def secret_digest(secret: bytes | str) -> str:
    """Return a short stable digest for an experimental watermark secret."""

    raw = secret.encode("utf-8") if isinstance(secret, str) else secret
    return base64url_encode(hashlib.sha256(raw).digest()[:12])


def secret_bytes(secret: bytes | str) -> bytes:
    """Return the secret as raw bytes."""

    return secret.encode("utf-8") if isinstance(secret, str) else secret


def assess_text_watermark_eligibility(
    content: str,
) -> TextWatermarkEligibility:
    """Return whether content is safe for experimental text transforms."""

    lowered = content.lower()
    reasons: list[str] = []
    if any(hint in lowered for hint in _CODE_HINTS):
        reasons.append("content appears to contain code or configuration")
    if any(hint in lowered for hint in _LEGAL_HINTS):
        reasons.append("content appears to contain legal language")
    if any(hint in lowered for hint in _MEDICAL_SAFETY_HINTS):
        reasons.append("content appears to contain medical or safety language")
    lines = [line for line in content.splitlines() if line.strip()]
    structured_lines = sum(
        1
        for line in lines
        if ":" in line and len(line.split()) <= 8 and not line.endswith(".")
    )
    if lines and structured_lines / len(lines) >= 0.35:
        reasons.append("content appears to be a structured record")
    spans = sorted(
        {
            match.span()
            for pattern in (
                _URL_PATTERN,
                _INLINE_CODE_PATTERN,
                _QUOTE_PATTERN,
                _CITATION_PATTERN,
            )
            for match in pattern.finditer(content)
        }
    )
    prose_like = bool(_SENTENCE_PATTERN.search(content))
    return TextWatermarkEligibility(
        prose_like=prose_like,
        blocked_reasons=tuple(reasons),
        locked_spans=tuple(spans),
    )


def require_text_watermark_safety(
    content: str,
    parameters: TextWatermarkParameters,
    *,
    semantic: bool,
) -> TextWatermarkEligibility:
    """Enforce the experimental text watermark safety policy."""

    if not parameters.user_confirmation:
        raise WatermarkError(
            "experimental text watermarking requires user confirmation"
        )
    if semantic and not parameters.allow_semantic_methods:
        raise WatermarkError(
            "semantic text watermark methods are disabled by default"
        )
    eligibility = assess_text_watermark_eligibility(content)
    if not eligibility.prose_like:
        raise WatermarkError(
            "experimental text watermarking is restricted to prose"
        )
    if eligibility.blocked_reasons:
        raise WatermarkError("; ".join(eligibility.blocked_reasons))
    return eligibility


def text_unified_diff(original: str, transformed: str) -> str:
    """Return a unified diff for review."""

    return "\n".join(
        difflib.unified_diff(
            original.splitlines(),
            transformed.splitlines(),
            fromfile="original",
            tofile="transformed",
            lineterm="",
        )
    )


def build_quality_report(
    method_id: str,
    original: str,
    transformed: str,
    *,
    warnings: tuple[str, ...] = (),
) -> TextWatermarkQualityReport:
    """Build a standard quality report for one transform."""

    diff = text_unified_diff(original, transformed)
    changed_lines = sum(
        1
        for line in diff.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    )
    changed_characters = sum(
        1
        for before, after in zip(original, transformed, strict=False)
        if before != after
    ) + abs(len(original) - len(transformed))
    return TextWatermarkQualityReport(
        method_id=method_id,
        safe=original != transformed,
        changed_lines=changed_lines,
        changed_characters=changed_characters,
        unified_diff=diff,
        warnings=warnings,
    )


def split_sentences(content: str) -> list[str]:
    """Split prose into simple sentence-sized units."""

    return [
        match.group(0).strip() for match in _SENTENCE_PATTERN.finditer(content)
    ]


def sentence_offsets(content: str) -> list[tuple[int, int]]:
    """Return sentence spans inside the original content."""

    return [match.span() for match in _SENTENCE_PATTERN.finditer(content)]


def index_is_locked(
    index: int, locked_spans: tuple[tuple[int, int], ...]
) -> bool:
    """Return whether one character index is inside a locked span."""

    return any(start <= index < end for start, end in locked_spans)


def sentence_selected(
    secret: bytes | str, sentence_index: int, stride: int
) -> bool:
    """Return whether a sentence is selected for keyed watermarking."""

    raw = secret_bytes(secret) + sentence_index.to_bytes(4, "big")
    return (
        int.from_bytes(hashlib.sha256(raw).digest()[:2], "big")
        % max(stride, 1)
        == 0
    )
