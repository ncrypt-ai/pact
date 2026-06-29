"""Plain-text carrier formats for signed PACT manifests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Self, cast
from uuid import UUID

from pact.canonical import (
    CanonicalizationProfile,
    ContentCanonicalizationError,
    JsonValue,
    canonical_json,
    canonicalize_content,
)
from pact.crypto import CryptographyError, base64url_decode, base64url_encode
from pact.manifest import Manifest, SignedManifest

if TYPE_CHECKING:
    from pact.watermarks.base import (
        TextWatermarkParameters,
        TextWatermarkPlugin,
    )

_VISIBLE_HEADER = "-----BEGIN PACT MANIFEST-----\n"
_VISIBLE_FOOTER = "\n-----END PACT MANIFEST-----\n"
_VISIBLE_LEGAL_NOTICE = (
    "PACT NOTICE: This embedded proof is provenance and usage-rights metadata. "
    "It is not legal advice, does not transfer copyright or license rights, "
    "and should be reviewed with the surrounding content and applicable law."
)
_VISIBLE_PATTERN = re.compile(
    r"\A-----BEGIN PACT MANIFEST-----\n(?P<manifest>\{.*\})\n"
    r"-----END PACT MANIFEST-----\n"
    r"(?:(?:PACT NOTICE: .*)\n)?\n",
    re.DOTALL,
)

_FRAME_START = "\u2060\u2063\u2060"
_FRAME_END = "\u2060\u2064\u2060"
_BIT_ZERO = "\u200b"
_BIT_ONE = "\u200c"
_FRAME_PATTERN = re.compile(
    re.escape(_FRAME_START)
    + r"(?P<bits>[\u200b\u200c]+)"
    + re.escape(_FRAME_END)
)


class CarrierError(ValueError):
    """Raised when carrier content is malformed or unsupported."""


class CarrierMode(StrEnum):
    """PACT carrier modes for text documents."""

    VISIBLE = "visible"
    INVISIBLE = "invisible"
    BOTH = "both"
    EXPERIMENTAL = "experimental"


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CarrierError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_text_bytes(value: bytes | str) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    try:
        return canonicalize_content(raw, CanonicalizationProfile.TEXT_V1)
    except ContentCanonicalizationError as error:
        raise CarrierError(str(error)) from error


def _checksum(payload: JsonValue) -> str:
    digest = hashlib.sha256(canonical_json(payload)).digest()
    return base64url_encode(digest[:4])


def _manifest_digest(manifest: Manifest) -> str:
    digest = hashlib.sha256(manifest.canonical_bytes()).digest()
    return base64url_encode(digest)


def _bits_from_bytes(value: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in value)


def _bytes_from_bits(value: str) -> bytes:
    if len(value) % 8 != 0:
        raise CarrierError("locator payload has an invalid bit length")
    return bytes(
        int(value[index : index + 8], 2) for index in range(0, len(value), 8)
    )


@dataclass(frozen=True, slots=True)
class InvisibleLocator:
    """The zero-width redundancy payload carried alongside a manifest."""

    claim_id: UUID
    registry_root_fingerprint: str
    manifest_digest: str
    checksum: str
    public_nonce: bytes | None = None
    version: str = "1"

    def __post_init__(self) -> None:
        if self.version != "1":
            raise CarrierError("unsupported locator version")
        try:
            base64url_decode(self.registry_root_fingerprint, length=32)
            base64url_decode(self.manifest_digest, length=32)
            base64url_decode(self.checksum, length=4)
        except CryptographyError as error:
            raise CarrierError(
                "locator digests must be SHA-256 base64url"
            ) from error
        if self.public_nonce is not None and len(self.public_nonce) != 32:
            raise CarrierError("locator public_nonce must be 32 bytes")
        if self.checksum != _checksum(cast(JsonValue, self._unsigned_dict())):
            raise CarrierError("locator checksum does not match payload")

    def _unsigned_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "version": self.version,
            "claim_id": str(self.claim_id),
            "registry_root_fingerprint": self.registry_root_fingerprint,
            "manifest_digest": self.manifest_digest,
        }
        if self.public_nonce is not None:
            result["public_nonce"] = base64url_encode(self.public_nonce)
        return result

    @property
    def nonce(self) -> bytes | None:
        """Backward-compatible alias for the disclosed locator nonce."""

        return self.public_nonce

    def to_dict(self) -> dict[str, object]:
        """Return the locator payload as a JSON-compatible mapping."""

        result = self._unsigned_dict()
        result["checksum"] = self.checksum
        return result

    def to_zero_width(self) -> str:
        """Serialize the locator to a framed zero-width payload."""

        payload = canonical_json(cast(JsonValue, self.to_dict()))
        bits = _bits_from_bytes(payload)
        encoded = bits.replace("0", _BIT_ZERO).replace("1", _BIT_ONE)
        return f"{_FRAME_START}{encoded}{_FRAME_END}"

    def matches_manifest(
        self,
        manifest: Manifest,
        public_nonce: bytes | None = None,
    ) -> bool:
        """Check whether a locator belongs to the provided manifest."""

        return (
            self.claim_id == manifest.claim_id
            and self.registry_root_fingerprint
            == manifest.registry_root_fingerprint
            and (
                public_nonce is None
                or self.public_nonce is None
                or self.public_nonce == public_nonce
            )
            and self.manifest_digest == _manifest_digest(manifest)
        )

    @classmethod
    def create(cls, manifest: Manifest, public_nonce: bytes | None) -> Self:
        """Create a locator from a manifest and optional disclosed nonce."""

        unsigned: dict[str, object] = {
            "version": "1",
            "claim_id": str(manifest.claim_id),
            "registry_root_fingerprint": manifest.registry_root_fingerprint,
            "manifest_digest": _manifest_digest(manifest),
        }
        if public_nonce is not None:
            unsigned["public_nonce"] = base64url_encode(public_nonce)
        return cls(
            claim_id=manifest.claim_id,
            registry_root_fingerprint=manifest.registry_root_fingerprint,
            manifest_digest=unsigned["manifest_digest"],
            checksum=_checksum(cast(JsonValue, unsigned)),
            public_nonce=public_nonce,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse a locator payload from its JSON-compatible mapping."""

        expected = {
            "version",
            "claim_id",
            "registry_root_fingerprint",
            "nonce",
            "public_nonce",
            "manifest_digest",
            "checksum",
        }
        unexpected = set(value) - expected
        if unexpected:
            raise CarrierError(
                f"unsupported locator fields: {sorted(unexpected)}"
            )
        claim_id = value.get("claim_id")
        version = value.get("version")
        public_nonce = value.get("public_nonce", value.get("nonce"))
        registry_root_fingerprint = value.get("registry_root_fingerprint")
        manifest_digest = value.get("manifest_digest")
        checksum = value.get("checksum")
        if not isinstance(claim_id, str):
            raise CarrierError("claim_id must be a string")
        if not isinstance(version, str):
            raise CarrierError("version must be a string")
        if public_nonce is not None and not isinstance(public_nonce, str):
            raise CarrierError("public_nonce must be a string")
        if not isinstance(registry_root_fingerprint, str):
            raise CarrierError("registry_root_fingerprint must be a string")
        if not isinstance(manifest_digest, str):
            raise CarrierError("manifest_digest must be a string")
        if not isinstance(checksum, str):
            raise CarrierError("checksum must be a string")
        try:
            nonce_bytes = (
                None
                if public_nonce is None
                else base64url_decode(public_nonce, length=32)
            )
        except CryptographyError as error:
            raise CarrierError(
                "public_nonce must be a 32-byte base64url value"
            ) from error
        return cls(
            claim_id=UUID(claim_id),
            registry_root_fingerprint=registry_root_fingerprint,
            manifest_digest=manifest_digest,
            checksum=checksum,
            public_nonce=nonce_bytes,
            version=version,
        )

    @classmethod
    def from_zero_width(cls, value: str) -> Self:
        """Parse a framed zero-width locator payload."""

        match = _FRAME_PATTERN.fullmatch(value)
        if match is None:
            raise CarrierError("locator frame is malformed")
        bits = (
            match.group("bits").replace(_BIT_ZERO, "0").replace(_BIT_ONE, "1")
        )
        payload = _bytes_from_bits(bits)
        try:
            parsed = json.loads(
                payload,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda constant: (_ for _ in ()).throw(
                    CarrierError(f"invalid JSON constant: {constant}")
                ),
            )
        except CarrierError:
            raise
        except json.JSONDecodeError as error:
            raise CarrierError("locator payload is not valid JSON") from error
        if not isinstance(parsed, Mapping):
            raise CarrierError("locator payload must be a JSON object")
        return cls.from_dict(cast(Mapping[str, object], parsed))


@dataclass(frozen=True, slots=True)
class TextCarrierExtraction:
    """Recovered content and metadata from a text carrier document."""

    content: bytes
    mode: CarrierMode
    signed_manifest: SignedManifest | None = None
    locator: InvisibleLocator | None = None


def _strip_locator(text: str) -> tuple[str, InvisibleLocator | None]:
    matches = list(_FRAME_PATTERN.finditer(text))
    if not matches:
        return text, None
    if len(matches) != 1:
        raise CarrierError("multiple locator frames are not supported")
    locator = InvisibleLocator.from_zero_width(matches[0].group(0))
    stripped = text[: matches[0].start()] + text[matches[0].end() :]
    return stripped, locator


def _strip_visible_block(text: str) -> tuple[str, SignedManifest | None]:
    if not text.startswith(_VISIBLE_HEADER):
        return text, None
    match = _VISIBLE_PATTERN.match(text)
    if match is None:
        raise CarrierError("visible manifest block is malformed")
    manifest = SignedManifest.from_json(
        match.group("manifest").encode("utf-8")
    )
    return text[match.end() :], manifest


def _strip_legal_notice(text: str) -> str:
    prefix = _VISIBLE_LEGAL_NOTICE + "\n\n"
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


def embed_text_carrier(
    content: bytes | str,
    signed: SignedManifest,
    *,
    nonce: bytes | None = None,
    mode: CarrierMode = CarrierMode.BOTH,
    secret: bytes | str | None = None,
    plugins: tuple[TextWatermarkPlugin, ...] = (),
    plugin_parameters: TextWatermarkParameters | None = None,
) -> bytes:
    """Embed a signed manifest in a plain-text carrier document."""

    if signed.manifest.canonicalization is not CanonicalizationProfile.TEXT_V1:
        raise CarrierError("text carriers require pact.text.v1 manifests")
    if mode is CarrierMode.EXPERIMENTAL:
        if nonce is None:
            raise CarrierError("experimental text carriers require a nonce")
        if secret is None:
            raise CarrierError("experimental text carriers require a secret")
        if not plugins:
            raise CarrierError(
                "experimental text carriers require at least one plugin"
            )
        from pact.watermarks.base import TextWatermarkParameters
        from pact.watermarks.textual import embed_experimental_text_carrier

        parameters = plugin_parameters or TextWatermarkParameters()
        embedded, _pipeline = embed_experimental_text_carrier(
            _canonical_text_bytes(content).decode("utf-8"),
            signed,
            nonce=nonce,
            secret=secret,
            plugins=plugins,
            parameters=parameters,
        )
        return embedded
    if mode not in {
        CarrierMode.VISIBLE,
        CarrierMode.INVISIBLE,
        CarrierMode.BOTH,
    }:
        raise CarrierError("unsupported text carrier mode")

    canonical_content = _canonical_text_bytes(content)
    body = canonical_content.decode("utf-8")
    manifest_json = signed.to_json().decode("utf-8")
    visible_block = (
        _VISIBLE_HEADER
        + manifest_json
        + _VISIBLE_FOOTER
        + _VISIBLE_LEGAL_NOTICE
        + "\n\n"
    )
    if mode is CarrierMode.VISIBLE:
        result = visible_block + body
    elif mode is CarrierMode.INVISIBLE:
        locator = InvisibleLocator.create(
            signed.manifest, nonce
        ).to_zero_width()
        result = _VISIBLE_LEGAL_NOTICE + "\n\n" + body + locator
    else:
        locator = InvisibleLocator.create(
            signed.manifest, nonce
        ).to_zero_width()
        result = (
            visible_block + body + locator
        )
    return result.encode("utf-8")


def extract_text_carrier(value: bytes | str) -> TextCarrierExtraction:
    """Extract the content and carrier metadata from a text document."""

    text = _canonical_text_bytes(value).decode("utf-8")
    without_locator, locator = _strip_locator(text)
    content, signed_manifest = _strip_visible_block(without_locator)
    content = _strip_legal_notice(content)
    if signed_manifest is not None and locator is not None:
        mode = CarrierMode.BOTH
    elif signed_manifest is not None:
        mode = CarrierMode.VISIBLE
    elif locator is not None:
        mode = CarrierMode.INVISIBLE
    else:
        raise CarrierError("text document does not contain a PACT carrier")
    return TextCarrierExtraction(
        content=content.encode("utf-8"),
        mode=mode,
        signed_manifest=signed_manifest,
        locator=locator,
    )
