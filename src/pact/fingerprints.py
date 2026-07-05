"""Content fingerprint generation and registry similarity matching."""

from __future__ import annotations

import hashlib
import re
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from io import BytesIO
from typing import cast
from xml.etree import ElementTree

from pact.canonical import (
    CanonicalizationProfile,
    JsonValue,
    canonical_json,
    canonicalize_content,
)
from pact.crypto import base64url_encode
from pact.manifest import ContentFingerprint
from pact.watermarks import (
    ImagePerceptualFingerprint,
    WatermarkError,
    compare_image_perceptual_fingerprints,
    create_image_perceptual_fingerprint,
)

EXACT_SHA256_FINGERPRINT_ID = "pact.exact.sha256.v1"
TEXT_SIMHASH_FINGERPRINT_ID = "pact.text.simhash.v1"
IMAGE_PERCEPTUAL_FINGERPRINT_ID = "pact.image.perceptual.v1"

TEXT_SIMHASH_BITS = 64
TEXT_SIMHASH_MATCH_DISTANCE = 8

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)?")
_ZIP_TEXT_MEMBERS = (
    "word/document.xml",
    "xl/sharedStrings.xml",
    "content.opf",
)


@dataclass(frozen=True, slots=True)
class FingerprintMatch:
    """One advisory fingerprint match between two signed manifests."""

    fingerprint_id: str
    algorithm: str
    score: float
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "algorithm": self.algorithm,
            "score": self.score,
            "reason": self.reason,
        }


def create_content_fingerprints(
    content: bytes,
    mime_type: str,
    canonicalization: CanonicalizationProfile,
) -> tuple[ContentFingerprint, ...]:
    """Create public perceptual fingerprints for manifest storage."""

    fingerprints = []
    text = _extract_text(content, mime_type, canonicalization)
    if text:
        fingerprints.append(_text_simhash_fingerprint(text, mime_type))
    if mime_type.startswith("image/"):
        image_fingerprint = _image_perceptual_fingerprint(content, mime_type)
        if image_fingerprint is not None:
            fingerprints.append(image_fingerprint)
    return tuple(fingerprints)


def compare_content_fingerprints(
    expected: tuple[ContentFingerprint, ...],
    observed: tuple[ContentFingerprint, ...],
) -> tuple[FingerprintMatch, ...]:
    """Return advisory exact or similarity matches between fingerprint sets."""

    matches: list[FingerprintMatch] = []
    for left in expected:
        for right in observed:
            match = _compare_fingerprint(left, right)
            if match is not None:
                matches.append(match)
    matches.sort(key=lambda item: item.score, reverse=True)
    return tuple(matches)


def _text_simhash_fingerprint(
    text: str,
    mime_type: str,
) -> ContentFingerprint:
    tokens = _tokens(text)
    simhash = _simhash(tokens)
    return ContentFingerprint(
        fingerprint_id=TEXT_SIMHASH_FINGERPRINT_ID,
        algorithm=f"simhash-{TEXT_SIMHASH_BITS}",
        value=f"{simhash:016x}",
        media_type=mime_type,
        details={
            "token_count": len(tokens),
            "match_distance": TEXT_SIMHASH_MATCH_DISTANCE,
        },
    )


def _image_perceptual_fingerprint(
    content: bytes,
    mime_type: str,
) -> ContentFingerprint | None:
    try:
        image = create_image_perceptual_fingerprint(content, mime_type)
    except (WatermarkError, OSError, ValueError):
        return None
    details = image.to_dict()
    digest = hashlib.sha256(canonical_json(cast(JsonValue, details))).digest()
    return ContentFingerprint(
        fingerprint_id=IMAGE_PERCEPTUAL_FINGERPRINT_ID,
        algorithm="pact-image-perceptual-hashes",
        value=base64url_encode(digest),
        media_type=mime_type,
        details=details,
    )


def _extract_text(
    content: bytes,
    mime_type: str,
    canonicalization: CanonicalizationProfile,
) -> str | None:
    if mime_type.startswith("text/") or canonicalization is CanonicalizationProfile.TEXT_V1:
        try:
            return canonicalize_content(
                content,
                CanonicalizationProfile.TEXT_V1,
            ).decode("utf-8")
        except UnicodeError:
            return None
    if mime_type == "application/pdf":
        return _extract_pdf_text(content)
    if mime_type in {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/epub+zip",
    }:
        return _extract_zip_document_text(content)
    return None


def _extract_pdf_text(content: bytes) -> str | None:
    try:
        from pypdf import PdfReader
    except ImportError:
        return None
    try:
        reader = PdfReader(BytesIO(content))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:
        return None


def _extract_zip_document_text(content: bytes) -> str | None:
    try:
        archive = zipfile.ZipFile(BytesIO(content))
    except zipfile.BadZipFile:
        return None
    texts: list[str] = []
    with archive:
        names = archive.namelist()
        for name in names:
            if (
                name in _ZIP_TEXT_MEMBERS
                or name.startswith("ppt/slides/slide")
                and name.endswith(".xml")
            ):
                try:
                    texts.append(_xml_text(archive.read(name)))
                except (KeyError, ElementTree.ParseError, UnicodeDecodeError):
                    continue
    combined = "\n".join(item for item in texts if item)
    return combined or None


def _xml_text(content: bytes) -> str:
    root = ElementTree.fromstring(content)
    return " ".join(text.strip() for text in root.itertext() if text.strip())


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(_TOKEN_PATTERN.findall(text.lower()))


def _simhash(tokens: tuple[str, ...]) -> int:
    if not tokens:
        return 0
    weights = [0] * TEXT_SIMHASH_BITS
    for token in tokens:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        for bit in range(TEXT_SIMHASH_BITS):
            mask = 1 << bit
            weights[bit] += 1 if value & mask else -1
    result = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            result |= 1 << bit
    return result


def _compare_fingerprint(
    left: ContentFingerprint,
    right: ContentFingerprint,
) -> FingerprintMatch | None:
    if left.fingerprint_id != right.fingerprint_id:
        return None
    if left.fingerprint_id == EXACT_SHA256_FINGERPRINT_ID:
        if left.value == right.value:
            return FingerprintMatch(
                left.fingerprint_id,
                left.algorithm,
                1.0,
                "exact canonical content hash match",
            )
        return None
    if left.fingerprint_id == TEXT_SIMHASH_FINGERPRINT_ID:
        return _compare_text_simhash(left, right)
    if left.fingerprint_id == IMAGE_PERCEPTUAL_FINGERPRINT_ID:
        return _compare_image_perceptual(left, right)
    return None


def _compare_text_simhash(
    left: ContentFingerprint,
    right: ContentFingerprint,
) -> FingerprintMatch | None:
    try:
        distance = (int(left.value, 16) ^ int(right.value, 16)).bit_count()
    except ValueError:
        return None
    if distance > TEXT_SIMHASH_MATCH_DISTANCE:
        return None
    score = 1.0 - (distance / TEXT_SIMHASH_BITS)
    return FingerprintMatch(
        left.fingerprint_id,
        left.algorithm,
        score,
        f"text simhash distance {distance}",
    )


def _compare_image_perceptual(
    left: ContentFingerprint,
    right: ContentFingerprint,
) -> FingerprintMatch | None:
    if not isinstance(left.details, Mapping) or not isinstance(
        right.details, Mapping
    ):
        return None
    try:
        left_image = ImagePerceptualFingerprint.from_dict(dict(left.details))
        right_image = ImagePerceptualFingerprint.from_dict(dict(right.details))
        match = compare_image_perceptual_fingerprints(left_image, right_image)
    except WatermarkError:
        return None
    if not match.matched:
        return None
    return FingerprintMatch(
        left.fingerprint_id,
        left.algorithm,
        match.score,
        f"image perceptual hash score {match.score:.2f}",
    )
