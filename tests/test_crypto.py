import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pact.canonical import CanonicalizationProfile
from pact.crypto import (
    CryptographyError,
    base64url_decode,
    base64url_encode,
    create_content_commitment,
    jwk_thumbprint,
    public_jwk,
    public_key_from_jwk,
    sign_es256,
    verify_content_commitment,
    verify_es256,
)


def test_base64url_round_trip_and_length_check() -> None:
    value = b"\x00\xfftest"
    encoded = base64url_encode(value)

    assert "=" not in encoded
    assert base64url_decode(encoded, length=len(value)) == value

    with pytest.raises(CryptographyError, match="must be 7 bytes"):
        base64url_decode(encoded, length=7)


@pytest.mark.parametrize("value", ["", "bad=", "bad value", "a"])
def test_invalid_base64url_is_rejected(value: str) -> None:
    with pytest.raises(CryptographyError, match="base64url"):
        base64url_decode(value)


def test_public_jwk_round_trip_and_thumbprint() -> None:
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    jwk = public_jwk(private_key.public_key())
    restored = public_key_from_jwk(jwk)

    assert (
        restored.public_numbers() == private_key.public_key().public_numbers()
    )
    assert len(jwk_thumbprint(jwk)) == 43


def test_public_jwk_rejects_wrong_curve() -> None:
    key = ec.generate_private_key(ec.SECP384R1()).public_key()

    with pytest.raises(CryptographyError, match="P-256"):
        public_jwk(key)


@pytest.mark.parametrize(
    ("jwk", "message"),
    [
        ({"kty": "RSA", "crv": "P-256"}, "EC P-256"),
        ({"kty": "EC", "crv": "P-256", "x": 1, "y": 2}, "strings"),
        (
            {
                "kty": "EC",
                "crv": "P-256",
                "x": base64url_encode(bytes(32)),
                "y": base64url_encode(bytes(32)),
            },
            "not on",
        ),
    ],
)
def test_invalid_public_jwk_is_rejected(
    jwk: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(CryptographyError, match=message):
        public_key_from_jwk(jwk)


def test_content_commitment_is_salted_and_canonical() -> None:
    nonce = bytes(range(32))
    first = create_content_commitment(
        b"Cafe\xcc\x81\r\n",
        CanonicalizationProfile.TEXT_V1,
        nonce,
    )
    second = create_content_commitment(
        "Caf\xe9\n".encode(),
        CanonicalizationProfile.TEXT_V1,
        nonce,
    )

    assert first == second
    assert verify_content_commitment(
        "Caf\xe9\n".encode(),
        CanonicalizationProfile.TEXT_V1,
        nonce,
        first,
    )
    assert not verify_content_commitment(
        b"different",
        CanonicalizationProfile.TEXT_V1,
        nonce,
        first,
    )

    with pytest.raises(CryptographyError, match="32 bytes"):
        create_content_commitment(
            b"content",
            CanonicalizationProfile.BINARY_V1,
            b"short",
        )


def test_es256_signatures_are_fixed_width_and_verified() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signature = sign_es256(key, b"payload")

    assert len(base64url_decode(signature)) == 64
    assert verify_es256(key.public_key(), b"payload", signature)
    assert not verify_es256(key.public_key(), b"changed", signature)


def test_es256_rejects_other_curves_and_bad_signature_length() -> None:
    other = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(CryptographyError, match="P-256"):
        sign_es256(other, b"payload")
    with pytest.raises(CryptographyError, match="P-256"):
        verify_es256(other.public_key(), b"payload", "value")

    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(CryptographyError, match="64 bytes"):
        verify_es256(key.public_key(), b"payload", base64url_encode(b"short"))
