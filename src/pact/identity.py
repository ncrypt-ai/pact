"""Registry-scoped P-256 claimant identities and secure persistence."""

import getpass
import hashlib
import hmac
import json
import os
import platform
import subprocess
import tempfile
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from socket import getfqdn, gethostname
from typing import Protocol, Self
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pact.crypto import jwk_thumbprint, public_jwk


class IdentityError(ValueError):
    """Raised when claimant identity data is invalid."""


class IdentityStorageError(RuntimeError):
    """Raised when claimant identity persistence fails."""


class IdentityNotFoundError(IdentityStorageError):
    """Raised when a registry has no stored claimant identity."""


class DeviceBindingError(IdentityStorageError):
    """Raised when local device continuity prevents identity creation."""


class CredentialBackend(Protocol):
    """The subset of the keyring backend interface used by PACT."""

    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(
        self, service: str, username: str, password: str
    ) -> None: ...


def _default_device_binding_dir() -> Path:
    configured = os.getenv("PACT_DEVICE_BINDING_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".pact" / "device-bindings"


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

        return public_jwk(self.private_key.public_key())

    @property
    def key_id(self) -> str:
        """Return the RFC 7638 SHA-256 thumbprint for the public JWK."""

        return jwk_thumbprint(self.public_jwk)

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


@dataclass(frozen=True, slots=True)
class DeviceIdentityBinding:
    """Local registry-scoped binding between one device and one claimant key."""

    registry_url: str
    device_fingerprint: str
    key_id: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-compatible binding record."""

        return asdict(self)


class LocalDeviceBindingStore:
    """Local continuity state limiting one claimant identity per registry."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or _default_device_binding_dir()

    def _path(self, registry_url: str) -> Path:
        normalized = normalize_registry_url(registry_url)
        name = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return self.directory / f"{name}.json"

    def fingerprint(self, registry_url: str) -> str:
        """Return a hardware-derived fingerprint scoped to one registry."""

        normalized = normalize_registry_url(registry_url)
        return hmac.new(
            _hardware_fingerprint_material(),
            normalized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def load(self, registry_url: str) -> DeviceIdentityBinding | None:
        """Load the local binding for a registry, if present."""

        path = self._path(registry_url)
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise DeviceBindingError(
                "local device identity binding is invalid JSON"
            ) from error
        if not isinstance(value, dict):
            raise DeviceBindingError(
                "local device identity binding must be an object"
            )
        try:
            registry = value["registry_url"]
            fingerprint = value["device_fingerprint"]
            key_id = value["key_id"]
        except KeyError as error:
            raise DeviceBindingError(
                "local device identity binding is missing required fields"
            ) from error
        if not all(
            isinstance(item, str) for item in (registry, fingerprint, key_id)
        ):
            raise DeviceBindingError(
                "local device identity binding fields must be strings"
            )
        return DeviceIdentityBinding(
            registry_url=registry,
            device_fingerprint=fingerprint,
            key_id=key_id,
        )

    def bind_new_identity(
        self, identity: ClaimantIdentity
    ) -> DeviceIdentityBinding:
        """Create the first local identity binding for a registry."""

        existing = self.load(identity.registry_url)
        if existing is not None:
            raise DeviceBindingError(
                "this device already has an identity for this registry; "
                "rotate the existing identity instead of creating a new one"
            )
        binding = DeviceIdentityBinding(
            registry_url=identity.registry_url,
            device_fingerprint=self.fingerprint(identity.registry_url),
            key_id=identity.key_id,
        )
        self._save(binding)
        return binding

    def ensure_can_create_identity(self, registry_url: str) -> None:
        """Raise if this device is already bound to the registry."""

        if self.load(registry_url) is not None:
            raise DeviceBindingError(
                "this device already has an identity for this registry; "
                "rotate the existing identity instead of creating a new one"
            )

    def ensure_can_rotate_identity(self, identity: ClaimantIdentity) -> None:
        """Raise if this device is bound to a different claimant key."""

        existing = self.load(identity.registry_url)
        if existing is not None and existing.key_id != identity.key_id:
            raise DeviceBindingError(
                "this device is bound to another identity for this registry"
            )

    def bind_imported_identity(
        self,
        identity: ClaimantIdentity,
    ) -> DeviceIdentityBinding:
        """Bind an imported identity unless this device is bound elsewhere."""

        existing = self.load(identity.registry_url)
        if existing is not None and existing.key_id != identity.key_id:
            raise DeviceBindingError(
                "this device is already bound to a different identity for "
                "this registry; rotate the existing identity instead"
            )
        if existing is not None:
            return existing
        binding = DeviceIdentityBinding(
            registry_url=identity.registry_url,
            device_fingerprint=self.fingerprint(identity.registry_url),
            key_id=identity.key_id,
        )
        self._save(binding)
        return binding

    def rotate_identity(
        self,
        current: ClaimantIdentity,
        replacement: ClaimantIdentity,
    ) -> DeviceIdentityBinding:
        """Update the key bound to this device while preserving fingerprint."""

        if current.registry_url != replacement.registry_url:
            raise DeviceBindingError(
                "replacement identity has another registry"
            )
        existing = self.load(current.registry_url)
        if existing is not None and existing.key_id != current.key_id:
            raise DeviceBindingError(
                "this device is bound to another identity for this registry"
            )
        binding = DeviceIdentityBinding(
            registry_url=current.registry_url,
            device_fingerprint=self.fingerprint(current.registry_url),
            key_id=replacement.key_id,
        )
        self._save(binding)
        return binding

    def _save(self, binding: DeviceIdentityBinding) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._path(binding.registry_url)
        temporary = tempfile.NamedTemporaryFile(
            dir=self.directory,
            prefix=".pact-binding-",
            delete=False,
        )
        temporary_path = Path(temporary.name)
        try:
            with temporary:
                os.chmod(temporary.name, 0o600)
                temporary.write(
                    json.dumps(
                        binding.to_dict(),
                        indent=2,
                        sort_keys=True,
                    ).encode("utf-8")
                )
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary.name, path)
        finally:
            temporary_path.unlink(missing_ok=True)


def _hardware_fingerprint_material() -> bytes:
    values = (
        ("machine-id", _machine_id()),
        ("platform-uuid", _platform_uuid()),
        ("disk-id", _disk_identifier()),
        ("mac-node", _mac_node()),
        ("hostname", gethostname()),
        ("fqdn", getfqdn()),
        ("user", getpass.getuser()),
        ("system", platform.system()),
        ("release", platform.release()),
        ("version", platform.version()),
        ("machine", platform.machine()),
    )
    material_values = {
        name: value
        for name, value in values
        if value is not None and value != ""
    }
    if not material_values:
        raise DeviceBindingError("could not derive a local device fingerprint")
    material = json.dumps(
        material_values,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def _machine_id() -> str | None:
    for path in (
        Path("/etc/machine-id"),
        Path("/var/lib/dbus/machine-id"),
    ):
        if path.is_file():
            value = path.read_text(encoding="utf-8", errors="ignore").strip()
            if value:
                return value
    return None


def _platform_uuid() -> str | None:
    if platform.system() == "Darwin":
        return _command_value(
            (
                "ioreg",
                "-rd1",
                "-c",
                "IOPlatformExpertDevice",
            ),
            "IOPlatformUUID",
        )
    if platform.system() == "Windows":
        return _command_value(
            (
                "reg",
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ),
            "MachineGuid",
        )
    return None


def _disk_identifier() -> str | None:
    system = platform.system()
    if system == "Darwin":
        return _command_value(
            ("diskutil", "info", "/"),
            "Volume UUID",
        )
    if system == "Windows":
        return _command_value(
            (
                "wmic",
                "csproduct",
                "get",
                "uuid",
            ),
            "UUID",
        )
    for path in (
        Path("/dev/disk/by-uuid"),
        Path("/dev/disk/by-id"),
    ):
        if path.is_dir():
            values = sorted(item.name for item in path.iterdir())
            if values:
                return ",".join(values[:8])
    return None


def _command_value(command: tuple[str, ...], marker: str) -> str | None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in completed.stdout.splitlines():
        if marker in line:
            value = line.split(marker, 1)[-1]
            value = value.replace("=", " ").replace('"', " ").strip()
            if value:
                return value.split()[-1]
    return None


def _mac_node() -> str | None:
    node = uuid.getnode()
    if node >> 40 & 1:
        return None
    return f"{node:012x}"


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
        if backend is not None:
            self.backend = backend
        else:
            try:
                import keyring
            except ImportError as error:
                raise IdentityStorageError(
                    "OS credential storage requires the keyring dependency"
                ) from error
            self.backend = keyring.get_keyring()

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
        except Exception as error:
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
        except Exception as error:
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
