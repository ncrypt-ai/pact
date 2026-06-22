"""Canonical serialization and content normalization."""

from enum import StrEnum
from typing import TypeAlias
from unicodedata import normalize

import rfc8785

JsonPrimitive: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = (
    JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
)


class ContentCanonicalizationError(ValueError):
    """Raised when content cannot be canonicalized under a profile."""


class CanonicalizationProfile(StrEnum):
    """Canonicalization profiles supported by the first manifest version."""

    BINARY_V1 = "pact.binary.v1"
    TEXT_V1 = "pact.text.v1"


def canonical_json(value: JsonValue) -> bytes:
    """Serialize an I-JSON-compatible value using RFC 8785 JCS."""

    return rfc8785.dumps(value)


def canonicalize_content(
    content: bytes,
    profile: CanonicalizationProfile,
) -> bytes:
    """Return stable bytes for content under the selected profile."""

    if profile is CanonicalizationProfile.BINARY_V1:
        return content

    if content.startswith(b"\xef\xbb\xbf"):
        raise ContentCanonicalizationError("UTF-8 BOM is not permitted")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContentCanonicalizationError(
            "text content must be valid UTF-8"
        ) from error

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalize("NFC", text).encode("utf-8")
