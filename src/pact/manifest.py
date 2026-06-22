"""PACT Manifest v1 construction, signing, parsing, and verification."""

import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pact.canonical import CanonicalizationProfile, JsonValue, canonical_json
from pact.crypto import (
    CryptographyError,
    base64url_decode,
    base64url_encode,
    create_content_commitment,
    jwk_thumbprint,
    public_key_from_jwk,
    sign_es256,
    verify_content_commitment,
    verify_es256,
)
from pact.identity import ClaimantIdentity, normalize_registry_url
from pact.policy import Policy

_MIME_TYPE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


class ManifestError(ValueError):
    """Raised when manifest data is malformed or inconsistent."""


def _validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{label} must be a string")
    try:
        base64url_decode(value, length=32)
    except CryptographyError as error:
        raise ManifestError(
            f"{label} must be a SHA-256 base64url value"
        ) from error
    return value


def _validate_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ManifestError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ManifestError(f"{label} must not contain credentials")
    return value


def _required_string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ManifestError(f"{key} must be a string")
    return result


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        raise ManifestError(f"{label} must be an array of strings")
    return tuple(cast(list[str], value))


@dataclass(frozen=True, slots=True)
class ContentBinding:
    """A salted commitment to canonical content."""

    nonce: str
    commitment: str
    algorithm: str = "sha256-nonce-sha256"

    def __post_init__(self) -> None:
        if self.algorithm != "sha256-nonce-sha256":
            raise ManifestError("unsupported content binding algorithm")
        _validate_digest(self.nonce, "nonce")
        _validate_digest(self.commitment, "commitment")

    @classmethod
    def create(
        cls,
        content: bytes,
        profile: CanonicalizationProfile,
        nonce: bytes | None = None,
    ) -> Self:
        """Create a fresh salted binding for canonical content."""

        nonce = secrets.token_bytes(32) if nonce is None else nonce
        commitment = create_content_commitment(content, profile, nonce)
        return cls(base64url_encode(nonce), base64url_encode(commitment))

    def verify(
        self,
        content: bytes,
        profile: CanonicalizationProfile,
    ) -> bool:
        """Verify content against this binding."""

        return verify_content_commitment(
            content,
            profile,
            base64url_decode(self.nonce, length=32),
            base64url_decode(self.commitment, length=32),
        )

    def to_dict(self) -> dict[str, str]:
        """Return the binding's wire representation."""

        return {
            "algorithm": self.algorithm,
            "nonce": self.nonce,
            "commitment": self.commitment,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse a binding from its wire representation."""

        return cls(
            nonce=_required_string(value, "nonce"),
            commitment=_required_string(value, "commitment"),
            algorithm=_required_string(value, "algorithm"),
        )


@dataclass(frozen=True, slots=True)
class Manifest:
    """The unsigned canonical PACT Manifest v1 payload."""

    claim_id: UUID
    registry_url: str
    registry_root_fingerprint: str
    claimant_key_id: str
    mime_type: str
    canonicalization: CanonicalizationProfile
    content_binding: ContentBinding
    policy: Policy
    carriers: tuple[str, ...] = ()
    watermarks: tuple[str, ...] = ()
    source_url: str | None = None
    licensing_url: str | None = None
    version: str = "1"

    def __post_init__(self) -> None:
        if self.version != "1":
            raise ManifestError("unsupported manifest version")
        object.__setattr__(
            self,
            "registry_url",
            normalize_registry_url(self.registry_url),
        )
        _validate_digest(
            self.registry_root_fingerprint,
            "registry_root_fingerprint",
        )
        _validate_digest(self.claimant_key_id, "claimant_key_id")
        if (
            not isinstance(self.mime_type, str)
            or _MIME_TYPE.fullmatch(self.mime_type) is None
        ):
            raise ManifestError("mime_type must be a valid media type")
        if any(
            not isinstance(value, str) or not value
            for value in self.carriers + self.watermarks
        ):
            raise ManifestError(
                "carrier and watermark identifiers cannot be blank"
            )
        if len(set(self.carriers)) != len(self.carriers):
            raise ManifestError("carrier identifiers must be unique")
        if len(set(self.watermarks)) != len(self.watermarks):
            raise ManifestError("watermark identifiers must be unique")
        if self.source_url is not None:
            _validate_url(self.source_url, "source_url")
        if self.licensing_url is not None:
            _validate_url(self.licensing_url, "licensing_url")

    @classmethod
    def create(
        cls,
        *,
        identity: ClaimantIdentity,
        registry_root_fingerprint: str,
        content: bytes,
        mime_type: str,
        canonicalization: CanonicalizationProfile,
        policy: Policy,
        carriers: tuple[str, ...] = (),
        watermarks: tuple[str, ...] = (),
        source_url: str | None = None,
        licensing_url: str | None = None,
        claim_id: UUID | None = None,
        nonce: bytes | None = None,
    ) -> Self:
        """Create an unsigned manifest and content commitment."""

        return cls(
            claim_id=uuid4() if claim_id is None else claim_id,
            registry_url=identity.registry_url,
            registry_root_fingerprint=registry_root_fingerprint,
            claimant_key_id=identity.key_id,
            mime_type=mime_type,
            canonicalization=canonicalization,
            content_binding=ContentBinding.create(
                content,
                canonicalization,
                nonce,
            ),
            policy=policy,
            carriers=carriers,
            watermarks=watermarks,
            source_url=source_url,
            licensing_url=licensing_url,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the canonical manifest data model."""

        result: dict[str, object] = {
            "version": self.version,
            "claim_id": str(self.claim_id),
            "registry_url": self.registry_url,
            "registry_root_fingerprint": self.registry_root_fingerprint,
            "claimant_key_id": self.claimant_key_id,
            "mime_type": self.mime_type,
            "canonicalization": self.canonicalization.value,
            "content_binding": self.content_binding.to_dict(),
            "policy": {
                "label": "cawg.training-mining",
                "entries": self.policy.to_dict(),
            },
            "carriers": list(self.carriers),
            "watermarks": list(self.watermarks),
        }
        if self.source_url is not None:
            result["source_url"] = self.source_url
        if self.licensing_url is not None:
            result["licensing_url"] = self.licensing_url
        return result

    def canonical_bytes(self) -> bytes:
        """Return the exact RFC 8785 bytes covered by the signature."""

        return canonical_json(cast(JsonValue, self.to_dict()))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse an unsigned manifest data model."""

        try:
            binding_value = value["content_binding"]
            policy_value = value["policy"]
            if not isinstance(binding_value, Mapping) or not isinstance(
                policy_value, Mapping
            ):
                raise ManifestError("binding and policy must be objects")
            binding = cast(Mapping[str, object], binding_value)
            policy_wrapper = cast(Mapping[str, object], policy_value)
            if policy_wrapper["label"] != "cawg.training-mining":
                raise ManifestError("unsupported policy label")
            entries_value = policy_wrapper["entries"]
            if not isinstance(entries_value, Mapping):
                raise ManifestError("policy entries must be an object")
            policy_entries = cast(Mapping[str, object], entries_value)
            source_url = value.get("source_url")
            licensing_url = value.get("licensing_url")
            if source_url is not None and not isinstance(source_url, str):
                raise ManifestError("source_url must be a string")
            if licensing_url is not None and not isinstance(
                licensing_url, str
            ):
                raise ManifestError("licensing_url must be a string")
            return cls(
                version=_required_string(value, "version"),
                claim_id=UUID(_required_string(value, "claim_id")),
                registry_url=_required_string(value, "registry_url"),
                registry_root_fingerprint=_required_string(
                    value, "registry_root_fingerprint"
                ),
                claimant_key_id=_required_string(value, "claimant_key_id"),
                mime_type=_required_string(value, "mime_type"),
                canonicalization=CanonicalizationProfile(
                    _required_string(value, "canonicalization")
                ),
                content_binding=ContentBinding.from_dict(binding),
                policy=Policy.from_dict(policy_entries),
                carriers=_string_list(value.get("carriers", []), "carriers"),
                watermarks=_string_list(
                    value.get("watermarks", []), "watermarks"
                ),
                source_url=source_url,
                licensing_url=licensing_url,
            )
        except ManifestError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise ManifestError("invalid manifest") from error


@dataclass(frozen=True, slots=True)
class ManifestSignature:
    """The claimant signature attached to a manifest."""

    key_id: str
    value: str
    algorithm: str = "ES256"

    def __post_init__(self) -> None:
        if self.algorithm != "ES256":
            raise ManifestError("unsupported signature algorithm")
        _validate_digest(self.key_id, "signature key_id")
        try:
            base64url_decode(self.value, length=64)
        except CryptographyError as error:
            raise ManifestError(
                "signature must be a 64-byte ES256 value"
            ) from error

    def to_dict(self) -> dict[str, str]:
        """Return the signature wire representation."""

        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse a signature wire representation."""

        return cls(
            key_id=_required_string(value, "key_id"),
            value=_required_string(value, "value"),
            algorithm=_required_string(value, "algorithm"),
        )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class SignedManifest:
    """A manifest and its detached claimant signature."""

    manifest: Manifest
    signature: ManifestSignature

    def __post_init__(self) -> None:
        if self.signature.key_id != self.manifest.claimant_key_id:
            raise ManifestError("signature key does not match claimant key")

    def to_dict(self) -> dict[str, object]:
        """Return the signed envelope data model."""

        return {
            "manifest": self.manifest.to_dict(),
            "signature": self.signature.to_dict(),
        }

    def to_json(self) -> bytes:
        """Serialize the signed envelope as canonical RFC 8785 JSON."""

        return canonical_json(cast(JsonValue, self.to_dict()))

    @classmethod
    def from_json(cls, value: bytes | str) -> Self:
        """Strictly parse and validate a signed manifest JSON envelope."""

        try:
            parsed = json.loads(
                value,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda constant: (_ for _ in ()).throw(
                    ManifestError(f"invalid JSON constant: {constant}")
                ),
            )
            if not isinstance(parsed, Mapping):
                raise ManifestError("signed manifest must be a JSON object")
            manifest_value = parsed["manifest"]
            signature_value = parsed["signature"]
            if not isinstance(manifest_value, Mapping) or not isinstance(
                signature_value, Mapping
            ):
                raise ManifestError("manifest and signature must be objects")
            manifest = cast(Mapping[str, object], manifest_value)
            signature = cast(Mapping[str, object], signature_value)
            return cls(
                Manifest.from_dict(manifest),
                ManifestSignature.from_dict(signature),
            )
        except ManifestError:
            raise
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise ManifestError("invalid signed manifest JSON") from error


def sign_manifest(
    manifest: Manifest,
    identity: ClaimantIdentity,
) -> SignedManifest:
    """Sign a manifest with its registry-scoped claimant identity."""

    if manifest.registry_url != identity.registry_url:
        raise ManifestError("identity belongs to a different registry")
    if manifest.claimant_key_id != identity.key_id:
        raise ManifestError("identity does not match the manifest claimant")
    signature = ManifestSignature(
        key_id=identity.key_id,
        value=sign_es256(identity.private_key, manifest.canonical_bytes()),
    )
    return SignedManifest(manifest, signature)


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Independent results for claimant signature and content binding."""

    signature_valid: bool
    key_id_valid: bool
    content_binding_valid: bool | None
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Whether every check requested by the caller succeeded."""

        return (
            self.signature_valid
            and self.key_id_valid
            and self.content_binding_valid is not False
        )


def verify_manifest(
    signed: SignedManifest,
    claimant_public_jwk: Mapping[str, object],
    content: bytes | None = None,
) -> VerificationReport:
    """Verify claimant identity, signature, and optional bound content."""

    errors: list[str] = []
    try:
        public_key = public_key_from_jwk(claimant_public_jwk)
        key_id_valid = (
            jwk_thumbprint(cast(Mapping[str, str], claimant_public_jwk))
            == signed.manifest.claimant_key_id
        )
    except CryptographyError:
        return VerificationReport(
            signature_valid=False,
            key_id_valid=False,
            content_binding_valid=None if content is None else False,
            errors=("claimant public key is invalid",),
        )

    if not key_id_valid:
        errors.append("claimant key identifier does not match")
    signature_valid = verify_es256(
        public_key,
        signed.manifest.canonical_bytes(),
        signed.signature.value,
    )
    if not signature_valid:
        errors.append("claimant signature is invalid")

    content_binding_valid: bool | None = None
    if content is not None:
        content_binding_valid = signed.manifest.content_binding.verify(
            content,
            signed.manifest.canonicalization,
        )
        if not content_binding_valid:
            errors.append("content binding does not match")

    return VerificationReport(
        signature_valid,
        key_id_valid,
        content_binding_valid,
        tuple(errors),
    )
