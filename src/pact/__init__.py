"""Pact package."""

from importlib.metadata import version

from pact.canonical import (
    CanonicalizationProfile,
    ContentCanonicalizationError,
    canonical_json,
    canonicalize_content,
)
from pact.carriers import (
    PACT_XML_NAMESPACE,
    CarrierError,
    CarrierMode,
    InvisibleLocator,
    StructuredCarrierExtraction,
    TextCarrierExtraction,
    embed_html_carrier,
    embed_text_carrier,
    embed_xml_carrier,
    extract_html_carrier,
    extract_text_carrier,
    extract_xml_carrier,
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
    "CarrierError",
    "CarrierMode",
    "ClaimantIdentity",
    "ContentBinding",
    "ContentCanonicalizationError",
    "CryptographyError",
    "EncryptedFileIdentityStore",
    "IdentityError",
    "IdentityNotFoundError",
    "IdentityStorageError",
    "InvisibleLocator",
    "KeyringIdentityStore",
    "Manifest",
    "ManifestError",
    "ManifestSignature",
    "Permission",
    "PermissionValue",
    "Policy",
    "PolicyEntry",
    "PolicyError",
    "PACT_XML_NAMESPACE",
    "SignedManifest",
    "StructuredCarrierExtraction",
    "TextCarrierExtraction",
    "VerificationReport",
    "__version__",
    "base64url_decode",
    "base64url_encode",
    "canonical_json",
    "canonicalize_content",
    "embed_html_carrier",
    "embed_text_carrier",
    "embed_xml_carrier",
    "extract_html_carrier",
    "extract_text_carrier",
    "extract_xml_carrier",
    "normalize_registry_url",
    "sign_manifest",
    "verify_manifest",
]

__version__ = version("pact")
