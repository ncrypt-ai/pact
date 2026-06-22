"""Registry-scoped P-256 claimant identities and secure persistence."""

import base64
import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self
from urllib.parse import urlsplit, urlunsplit

import keyring
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from keyring.errors import KeyringError

from pact.canonical import JsonValue, canonical_json


class IdentityError(ValueError):
    """Raised when claimant identity data is invalid."""


class IdentityStorageError(RuntimeError):
    """Raised when claimant identity persistence fails."""


class IdentityNotFoundError(IdentityStorageError):
    """Raised when a registry has no stored claimant identity."""


class CredentialBackend(Protocol):
    """The subset of the keyring backend interface used by PACT."""

    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(
        self, service: str, username: str, password: str
    ) -> None: ...


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def normalize_registry_url(value: str) -> str:
    """Validate and normalize a registry base URL."""

    parsed = urlsplit(value)
    hostname = parsed.hostname
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme not in {"http", "https"} or hostname is None:
        raise IdentityError("registry URL must be an absolute HTTP(S) URL")
    if parsed.scheme == "http" and hostname not in local_hosts:
        raise IdentityError("non-local registry URLs must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise IdentityError("registry URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise IdentityError(
            "registry URL must not contain a query or fragment"
        )
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), path, "", ""))


@dataclass(frozen=True, slots=True)
class ClaimantIdentity:
    """A claimant signing key that is scoped to one registry."""

    registry_url: str
    private_key: ec.EllipticCurvePrivateKey

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "registry_url",
            normalize_registry_url(self.registry_url),
        )
        if not isinstance(self.private_key.curve, ec.SECP256R1):
            raise IdentityError("claimant keys must use the P-256 curve")

    @classmethod
    def generate(cls, registry_url: str) -> Self:
        """Generate a fresh registry-specific P-256 identity."""

        return cls(registry_url, ec.generate_private_key(ec.SECP256R1()))

    @property
    def public_jwk(self) -> dict[str, str]:
        """Return the claimant public key as a minimal P-256 JWK."""

        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url(numbers.x.to_bytes(32, "big")),
            "y": _base64url(numbers.y.to_bytes(32, "big")),
        }

    @property
    def key_id(self) -> str:
        """Return the RFC 7638 SHA-256 thumbprint for the public JWK."""

        jwk: JsonValue = self.public_jwk
        return _base64url(hashlib.sha256(canonical_json(jwk)).digest())

    def export_pkcs8(self, password: str) -> bytes:
        """Export the key as password-encrypted PKCS#8 PEM."""

        if not password:
            raise IdentityError("a nonempty export password is required")
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )

    @classmethod
    def import_pkcs8(
        cls,
        registry_url: str,
        value: bytes,
        password: str,
    ) -> Self:
        """Import a registry identity from encrypted PKCS#8 PEM."""

        try:
            key = serialization.load_pem_private_key(
                value,
                password=password.encode("utf-8"),
            )
        except (TypeError, ValueError) as error:
            raise IdentityError("invalid encrypted PKCS#8 identity") from error
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise IdentityError("claimant identity is not an EC private key")
        return cls(registry_url, key)

    def rotate(self) -> Self:
        """Generate a replacement key scoped to the same registry."""

        return type(self).generate(self.registry_url)


class EncryptedFileIdentityStore:
    """Password-encrypted PKCS#8 fallback identity storage."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path(self, registry_url: str) -> Path:
        normalized = normalize_registry_url(registry_url)
        name = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return self.directory / f"{name}.p8"

    def save(self, identity: ClaimantIdentity, password: str) -> None:
        """Atomically save an encrypted identity with private permissions."""

        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = identity.export_pkcs8(password)
        temporary = tempfile.NamedTemporaryFile(
            dir=self.directory,
            prefix=".pact-",
            delete=False,
        )
        temporary_path = Path(temporary.name)
        try:
            with temporary:
                os.chmod(temporary.name, 0o600)
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary.name, self._path(identity.registry_url))
        finally:
            temporary_path.unlink(missing_ok=True)

    def load(self, registry_url: str, password: str) -> ClaimantIdentity:
        """Load and decrypt the identity for a registry."""

        path = self._path(registry_url)
        if not path.is_file():
            raise IdentityNotFoundError("no identity exists for this registry")
        return ClaimantIdentity.import_pkcs8(
            registry_url,
            path.read_bytes(),
            password,
        )


class KeyringIdentityStore:
    """Claimant identity storage backed by the operating-system keyring."""

    service = "pact.claimant"

    def __init__(self, backend: CredentialBackend | None = None) -> None:
        self.backend = (
            backend if backend is not None else keyring.get_keyring()
        )

    @staticmethod
    def _account(registry_url: str) -> str:
        normalized = normalize_registry_url(registry_url)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def save(self, identity: ClaimantIdentity) -> None:
        """Save an unencrypted PEM inside the protected OS credential store."""

        value = identity.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        try:
            self.backend.set_password(
                self.service,
                self._account(identity.registry_url),
                value,
            )
        except KeyringError as error:
            raise IdentityStorageError(
                "OS credential storage failed"
            ) from error

    def load(self, registry_url: str) -> ClaimantIdentity:
        """Load an identity from the protected OS credential store."""

        try:
            value = self.backend.get_password(
                self.service,
                self._account(registry_url),
            )
        except KeyringError as error:
            raise IdentityStorageError(
                "OS credential lookup failed"
            ) from error
        if value is None:
            raise IdentityNotFoundError("no identity exists for this registry")
        try:
            key = serialization.load_pem_private_key(
                value.encode("ascii"), None
            )
        except (TypeError, ValueError) as error:
            raise IdentityStorageError(
                "stored claimant identity is invalid"
            ) from error
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise IdentityStorageError(
                "stored claimant identity is not an EC key"
            )
        return ClaimantIdentity(registry_url, key)
