"""Pact package."""

from importlib.metadata import version

from pact.canonical import (
    CanonicalizationProfile,
    ContentCanonicalizationError,
    canonical_json,
    canonicalize_content,
)
from pact.crypto import CryptographyError, base64url_decode, base64url_encode
from pact.identity import (
    ClaimantIdentity,
    EncryptedFileIdentityStore,
    IdentityError,
    IdentityNotFoundError,
    IdentityStorageError,
    KeyringIdentityStore,
    normalize_registry_url,
)
from pact.manifest import (
    ContentBinding,
    Manifest,
    ManifestError,
    ManifestSignature,
    SignedManifest,
    VerificationReport,
    sign_manifest,
    verify_manifest,
)
from pact.policy import (
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    PolicyError,
)

__all__ = [
    "CanonicalizationProfile",
    "ClaimantIdentity",
    "ContentBinding",
    "ContentCanonicalizationError",
    "CryptographyError",
    "EncryptedFileIdentityStore",
    "IdentityError",
    "IdentityNotFoundError",
    "IdentityStorageError",
    "KeyringIdentityStore",
    "Manifest",
    "ManifestError",
    "ManifestSignature",
    "Permission",
    "PermissionValue",
    "Policy",
    "PolicyEntry",
    "PolicyError",
    "SignedManifest",
    "VerificationReport",
    "__version__",
    "base64url_decode",
    "base64url_encode",
    "canonical_json",
    "canonicalize_content",
    "normalize_registry_url",
    "sign_manifest",
    "verify_manifest",
]

__version__ = version("pact")
