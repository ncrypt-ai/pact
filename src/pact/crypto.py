"""Cryptographic primitives used by PACT identities and manifests."""

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Mapping
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from pact.canonical import (
    CanonicalizationProfile,
    JsonValue,
    canonical_json,
    canonicalize_content,
)

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class CryptographyError(ValueError):
    """Raised when encoded cryptographic material is invalid."""


def base64url_encode(value: bytes) -> str:
    """Encode bytes using unpadded RFC 4648 base64url."""

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str, *, length: int | None = None) -> bytes:
    """Strictly decode unpadded base64url, optionally enforcing length."""

    if not value or _BASE64URL.fullmatch(value) is None or "=" in value:
        raise CryptographyError("value is not unpadded base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as error:
        raise CryptographyError("value is not valid base64url") from error
    if length is not None and len(decoded) != length:
        raise CryptographyError(f"decoded value must be {length} bytes")
    return decoded


def public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Encode a P-256 public key as the minimal RFC 7517 JWK members."""

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise CryptographyError("public key must use the P-256 curve")
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(numbers.y.to_bytes(32, "big")),
    }


def public_key_from_jwk(
    value: Mapping[str, object],
) -> ec.EllipticCurvePublicKey:
    """Parse a minimal P-256 public JWK."""

    if value.get("kty") != "EC" or value.get("crv") != "P-256":
        raise CryptographyError("JWK must describe an EC P-256 public key")
    x = value.get("x")
    y = value.get("y")
    if not isinstance(x, str) or not isinstance(y, str):
        raise CryptographyError("JWK coordinates must be strings")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(base64url_decode(x, length=32), "big"),
        int.from_bytes(base64url_decode(y, length=32), "big"),
        ec.SECP256R1(),
    )
    try:
        return numbers.public_key()
    except ValueError as error:
        raise CryptographyError(
            "JWK point is not on the P-256 curve"
        ) from error


def jwk_thumbprint(value: Mapping[str, str]) -> str:
    """Return an RFC 7638 SHA-256 thumbprint for a P-256 JWK."""

    required: JsonValue = {
        "crv": value.get("crv", ""),
        "kty": value.get("kty", ""),
        "x": value.get("x", ""),
        "y": value.get("y", ""),
    }
    public_key_from_jwk(cast(Mapping[str, object], required))
    return base64url_encode(hashlib.sha256(canonical_json(required)).digest())


def create_content_commitment(
    content: bytes,
    profile: CanonicalizationProfile,
    nonce: bytes,
) -> bytes:
    """Bind canonical content using SHA-256(nonce || SHA-256(content))."""

    if len(nonce) != 32:
        raise CryptographyError("content commitment nonce must be 32 bytes")
    canonical = canonicalize_content(content, profile)
    content_digest = hashlib.sha256(canonical).digest()
    return hashlib.sha256(nonce + content_digest).digest()


def verify_content_commitment(
    content: bytes,
    profile: CanonicalizationProfile,
    nonce: bytes,
    expected: bytes,
) -> bool:
    """Verify a salted commitment using constant-time comparison."""

    actual = create_content_commitment(content, profile, nonce)
    return hmac.compare_digest(actual, expected)


def sign_es256(
    private_key: ec.EllipticCurvePrivateKey,
    payload: bytes,
) -> str:
    """Create a JWS-compatible fixed-width ES256 signature."""

    if not isinstance(private_key.curve, ec.SECP256R1):
        raise CryptographyError("private key must use the P-256 curve")
    der = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return base64url_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_es256(
    public_key: ec.EllipticCurvePublicKey,
    payload: bytes,
    signature: str,
) -> bool:
    """Verify a fixed-width ES256 signature."""

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise CryptographyError("public key must use the P-256 curve")
    raw = base64url_decode(signature, length=64)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    try:
        public_key.verify(
            encode_dss_signature(r, s),
            payload,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        return False
    return True
