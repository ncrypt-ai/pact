import base64
import hashlib
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from keyring.errors import KeyringError

from pact.canonical import canonical_json
from pact.identity import (
    ClaimantIdentity,
    EncryptedFileIdentityStore,
    IdentityError,
    IdentityNotFoundError,
    IdentityStorageError,
    KeyringIdentityStore,
    normalize_registry_url,
)


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.error: KeyringError | None = None

    def get_password(self, service: str, username: str) -> str | None:
        if self.error is not None:
            raise self.error
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        if self.error is not None:
            raise self.error
        self.values[(service, username)] = password


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://EXAMPLE.com/registry/", "https://example.com/registry"),
        ("http://localhost:8000/", "http://localhost:8000"),
        ("http://127.0.0.1", "http://127.0.0.1"),
        ("http://[::1]/", "http://[::1]"),
    ],
)
def test_registry_url_normalization(value: str, expected: str) -> None:
    assert normalize_registry_url(value) == expected


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("example.com", "absolute HTTP"),
        ("http://example.com", "must use HTTPS"),
        ("https://user:pass@example.com", "must not contain credentials"),
        ("https://example.com?a=1", "query or fragment"),
        ("https://example.com#fragment", "query or fragment"),
    ],
)
def test_invalid_registry_urls_are_rejected(value: str, message: str) -> None:
    with pytest.raises(IdentityError, match=message):
        normalize_registry_url(value)


def test_identity_uses_p256_jwk_and_rfc7638_thumbprint() -> None:
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    identity = ClaimantIdentity("https://registry.example", private_key)

    assert identity.public_jwk.keys() == {"kty", "crv", "x", "y"}
    assert identity.public_jwk["kty"] == "EC"
    assert identity.public_jwk["crv"] == "P-256"
    expected = _base64url(
        hashlib.sha256(canonical_json(identity.public_jwk)).digest()
    )
    assert identity.key_id == expected


def test_identities_and_rotations_are_registry_scoped() -> None:
    first = ClaimantIdentity.generate("https://one.example")
    second = ClaimantIdentity.generate("https://two.example")
    rotated = first.rotate()

    assert first.key_id != second.key_id
    assert rotated.key_id != first.key_id
    assert rotated.registry_url == first.registry_url


def test_identity_rejects_non_p256_curve() -> None:
    with pytest.raises(IdentityError, match="P-256"):
        ClaimantIdentity(
            "https://registry.example",
            ec.generate_private_key(ec.SECP384R1()),
        )


def test_encrypted_pkcs8_round_trip_and_wrong_password() -> None:
    identity = ClaimantIdentity.generate("https://registry.example")
    exported = identity.export_pkcs8("correct horse")

    imported = ClaimantIdentity.import_pkcs8(
        identity.registry_url,
        exported,
        "correct horse",
    )
    assert imported.key_id == identity.key_id
    assert b"ENCRYPTED PRIVATE KEY" in exported

    with pytest.raises(IdentityError, match="invalid encrypted"):
        ClaimantIdentity.import_pkcs8(
            identity.registry_url,
            exported,
            "wrong password",
        )

    with pytest.raises(IdentityError, match="nonempty"):
        identity.export_pkcs8("")


def test_pkcs8_import_rejects_non_ec_key() -> None:
    private_key = rsa.generate_private_key(65537, 2048)
    value = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"password"),
    )

    with pytest.raises(IdentityError, match="not an EC"):
        ClaimantIdentity.import_pkcs8(
            "https://registry.example",
            value,
            "password",
        )


def test_encrypted_file_store_round_trip(tmp_path: Path) -> None:
    identity = ClaimantIdentity.generate("https://registry.example")
    store = EncryptedFileIdentityStore(tmp_path / "identities")

    with pytest.raises(IdentityNotFoundError):
        store.load(identity.registry_url, "password")

    store.save(identity, "password")
    loaded = store.load(identity.registry_url, "password")
    stored_file = next(store.directory.glob("*.p8"))

    assert loaded.key_id == identity.key_id
    assert stat.S_IMODE(stored_file.stat().st_mode) == 0o600
    assert not list(store.directory.glob(".pact-*"))


def test_keyring_store_round_trip_and_missing_identity() -> None:
    backend = MemoryKeyring()
    store = KeyringIdentityStore(backend)
    identity = ClaimantIdentity.generate("https://registry.example/")

    with pytest.raises(IdentityNotFoundError):
        store.load(identity.registry_url)

    store.save(identity)

    assert store.load("https://registry.example").key_id == identity.key_id


def test_keyring_store_wraps_backend_errors() -> None:
    backend = MemoryKeyring()
    backend.error = KeyringError("unavailable")
    store = KeyringIdentityStore(backend)
    identity = ClaimantIdentity.generate("https://registry.example")

    with pytest.raises(IdentityStorageError, match="storage failed"):
        store.save(identity)
    with pytest.raises(IdentityStorageError, match="lookup failed"):
        store.load(identity.registry_url)


def test_keyring_store_rejects_non_ec_material() -> None:
    backend = MemoryKeyring()
    store = KeyringIdentityStore(backend)
    private_key = rsa.generate_private_key(65537, 2048)
    value = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    backend.values[
        (store.service, store._account("https://registry.example"))
    ] = value

    with pytest.raises(IdentityStorageError, match="not an EC"):
        store.load("https://registry.example")


def test_keyring_store_rejects_invalid_material() -> None:
    backend = MemoryKeyring()
    store = KeyringIdentityStore(backend)
    backend.values[
        (store.service, store._account("https://registry.example"))
    ] = "not a key"

    with pytest.raises(IdentityStorageError, match="is invalid"):
        store.load("https://registry.example")


def test_keyring_store_uses_system_backend_by_default() -> None:
    store = KeyringIdentityStore()

    assert store.backend is not None
