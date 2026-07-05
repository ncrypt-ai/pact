"""PACT Manifest v1 construction, signing, parsing, and verification."""

import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
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


class ClaimMeaning(StrEnum):
    """Explicit meanings a claimant attaches to one signed manifest."""

    SIGNED_BY = "signed_by"
    CREATED_BY = "created_by"
    OWNED_BY = "owned_by"
    LICENSED_BY = "licensed_by"
    TRAINING_RESTRICTION = "training_restriction"
    SUSPECTED_TRAINING_USE = "suspected_training_use"


class VerificationVerdict(StrEnum):
    CONTENT_VERIFIED = "content_verified"
    SIGNATURE_ONLY = "signature_only"
    PRIVATE_CONTENT_UNCHECKED = "private_content_unchecked"
    CONTENT_MISMATCH = "content_mismatch"
    SIGNATURE_INVALID = "signature_invalid"


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


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ManifestError(f"{label} must be a string")
    if not value.strip():
        raise ManifestError(f"{label} must not be blank")
    return value


def _claim_meaning_list(value: object) -> tuple[ClaimMeaning, ...]:
    items = _string_list(value, "claim_meanings")
    try:
        meanings = tuple(ClaimMeaning(item) for item in items)
    except ValueError as error:
        raise ManifestError("unsupported claim meaning") from error
    if len(set(meanings)) != len(meanings):
        raise ManifestError("claim meanings must be unique")
    return meanings


def _reject_unknown_fields(
    value: Mapping[str, object],
    allowed: set[str],
    label: str,
) -> None:
    unexpected = set(value) - allowed
    if unexpected:
        raise ManifestError(
            f"unsupported {label} fields: {sorted(unexpected)}"
        )


@dataclass(frozen=True, slots=True)
class C2PAAction:
    """One C2PA-style action entry claimed by the manifest signer."""

    action: str
    description: str | None = None
    when: str | None = None
    parameters: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, str) or not self.action.strip():
            raise ManifestError("action must be a nonempty string")
        if self.description is not None:
            _optional_string(self.description, "action description")
        if self.when is not None:
            _optional_string(self.when, "action when")
        if self.parameters is not None and not isinstance(
            self.parameters, Mapping
        ):
            raise ManifestError("action parameters must be an object")

    def to_dict(self) -> dict[str, object]:
        """Return this action using C2PA action field names."""

        result: dict[str, object] = {"action": self.action}
        if self.description is not None:
            result["description"] = self.description
        if self.when is not None:
            result["when"] = self.when
        if self.parameters is not None:
            result["parameters"] = dict(self.parameters)
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse one C2PA-style action from manifest JSON."""

        _reject_unknown_fields(
            value,
            {"action", "description", "when", "parameters"},
            "action",
        )
        parameters = value.get("parameters")
        if parameters is not None and not isinstance(parameters, Mapping):
            raise ManifestError("action parameters must be an object")
        return cls(
            action=_required_string(value, "action"),
            description=_optional_string(
                value.get("description"),
                "action description",
            ),
            when=_optional_string(value.get("when"), "action when"),
            parameters=None
            if parameters is None
            else cast(Mapping[str, object], parameters),
        )


def _action_list(value: object) -> tuple[C2PAAction, ...]:
    if not isinstance(value, Mapping):
        raise ManifestError("actions must be a C2PA actions object")
    action_map = cast(Mapping[str, object], value)
    _reject_unknown_fields(action_map, {"actions"}, "actions")
    items = action_map.get("actions", [])
    if not isinstance(items, list):
        raise ManifestError("actions must contain an actions array")
    actions = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ManifestError("actions must contain objects")
        actions.append(C2PAAction.from_dict(cast(Mapping[str, object], item)))
    return tuple(actions)


@dataclass(frozen=True, slots=True)
class C2PAIngredient:
    """One C2PA-style source asset used by this manifest."""

    claim_id: str
    registry_url: str | None = None
    title: str | None = None
    format: str | None = None
    relationship: str = "parentOf"

    def __post_init__(self) -> None:
        if not isinstance(self.claim_id, str) or not self.claim_id.strip():
            raise ManifestError(
                "ingredient claim_id must be a nonempty string"
            )
        if self.registry_url is not None:
            _validate_url(self.registry_url, "ingredient registry_url")
        if self.title is not None:
            _optional_string(self.title, "ingredient title")
        if self.format is not None:
            _optional_string(self.format, "ingredient format")
        if (
            not isinstance(self.relationship, str)
            or not self.relationship.strip()
        ):
            raise ManifestError("ingredient relationship must be nonempty")

    def to_dict(self) -> dict[str, object]:
        """Return this ingredient using C2PA ingredient-style field names."""

        result: dict[str, object] = {
            "claim_id": self.claim_id,
            "relationship": self.relationship,
        }
        if self.registry_url is not None:
            result["registry_url"] = self.registry_url
        if self.title is not None:
            result["title"] = self.title
        if self.format is not None:
            result["format"] = self.format
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse one C2PA-style ingredient from manifest JSON."""

        _reject_unknown_fields(
            value,
            {"claim_id", "registry_url", "title", "format", "relationship"},
            "ingredient",
        )
        registry_url = value.get("registry_url")
        title = value.get("title")
        media_format = value.get("format")
        relationship = value.get("relationship", "parentOf")
        if registry_url is not None and not isinstance(registry_url, str):
            raise ManifestError("ingredient registry_url must be a string")
        if title is not None and not isinstance(title, str):
            raise ManifestError("ingredient title must be a string")
        if media_format is not None and not isinstance(media_format, str):
            raise ManifestError("ingredient format must be a string")
        if not isinstance(relationship, str):
            raise ManifestError("ingredient relationship must be a string")
        return cls(
            claim_id=_required_string(value, "claim_id"),
            registry_url=registry_url,
            title=title,
            format=media_format,
            relationship=relationship,
        )


def _ingredient_list(value: object) -> tuple[C2PAIngredient, ...]:
    if not isinstance(value, Mapping):
        raise ManifestError("ingredients must be a C2PA ingredients object")
    ingredient_map = cast(Mapping[str, object], value)
    _reject_unknown_fields(ingredient_map, {"ingredients"}, "ingredients")
    items = ingredient_map.get("ingredients", [])
    if not isinstance(items, list):
        raise ManifestError("ingredients must contain an ingredients array")
    ingredients = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ManifestError("ingredients must contain objects")
        ingredients.append(
            C2PAIngredient.from_dict(cast(Mapping[str, object], item))
        )
    return tuple(ingredients)


@dataclass(frozen=True, slots=True)
class ContentFingerprint:
    """A public exact or perceptual fingerprint carried by the manifest."""

    fingerprint_id: str
    algorithm: str
    value: str
    media_type: str | None = None
    details: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.fingerprint_id, str)
            or not self.fingerprint_id.strip()
        ):
            raise ManifestError("fingerprint_id must be a nonempty string")
        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise ManifestError("fingerprint algorithm must be nonempty")
        if not isinstance(self.value, str) or not self.value.strip():
            raise ManifestError("fingerprint value must be nonempty")
        if self.media_type is not None:
            _optional_string(self.media_type, "fingerprint media_type")
        if self.details is not None:
            if not isinstance(self.details, Mapping):
                raise ManifestError("fingerprint details must be an object")
            try:
                canonical_json(cast(JsonValue, dict(self.details)))
            except Exception as error:
                raise ManifestError(
                    "fingerprint details must be JSON-serializable"
                ) from error

    def to_dict(self) -> dict[str, object]:
        """Return the fingerprint wire representation."""

        result: dict[str, object] = {
            "fingerprint_id": self.fingerprint_id,
            "algorithm": self.algorithm,
            "value": self.value,
        }
        if self.media_type is not None:
            result["media_type"] = self.media_type
        if self.details is not None:
            result["details"] = dict(self.details)
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse one content fingerprint from manifest JSON."""

        _reject_unknown_fields(
            value,
            {
                "fingerprint_id",
                "algorithm",
                "value",
                "media_type",
                "details",
            },
            "fingerprint",
        )
        media_type = value.get("media_type")
        details = value.get("details")
        if media_type is not None and not isinstance(media_type, str):
            raise ManifestError("fingerprint media_type must be a string")
        if details is not None and not isinstance(details, Mapping):
            raise ManifestError("fingerprint details must be an object")
        return cls(
            fingerprint_id=_required_string(value, "fingerprint_id"),
            algorithm=_required_string(value, "algorithm"),
            value=_required_string(value, "value"),
            media_type=media_type,
            details=None
            if details is None
            else cast(Mapping[str, object], details),
        )


def _fingerprint_list(value: object) -> tuple[ContentFingerprint, ...]:
    if not isinstance(value, list):
        raise ManifestError("fingerprints must be an array")
    fingerprints = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ManifestError("fingerprints must contain objects")
        fingerprints.append(
            ContentFingerprint.from_dict(cast(Mapping[str, object], item))
        )
    return tuple(fingerprints)


@dataclass(frozen=True, slots=True)
class ContentBinding:
    """A nonce-bound commitment to canonical content."""

    commitment: str
    algorithm: str = "sha256-nonce-sha256"
    public_nonce: str | None = None

    def __post_init__(self) -> None:
        if self.algorithm != "sha256-nonce-sha256":
            raise ManifestError("unsupported content binding algorithm")
        _validate_digest(self.commitment, "commitment")
        if self.public_nonce is not None:
            try:
                base64url_decode(self.public_nonce, length=32)
            except CryptographyError as error:
                raise ManifestError(
                    "public_nonce must be a 32-byte base64url value"
                ) from error

    @classmethod
    def create(
        cls,
        content: bytes,
        profile: CanonicalizationProfile,
        nonce: bytes,
        *,
        disclose_nonce: bool = True,
    ) -> Self:
        """Create a fresh nonce-bound binding for canonical content."""

        commitment = create_content_commitment(content, profile, nonce)
        return cls(
            base64url_encode(commitment),
            public_nonce=base64url_encode(nonce) if disclose_nonce else None,
        )

    @property
    def publicly_verifiable(self) -> bool:
        """Whether this binding includes the nonce needed for public checks."""

        return self.public_nonce is not None

    def public_nonce_bytes(self) -> bytes | None:
        """Return the disclosed content-verification nonce, if present."""

        if self.public_nonce is None:
            return None
        return base64url_decode(self.public_nonce, length=32)

    def verify(
        self,
        content: bytes,
        profile: CanonicalizationProfile,
        nonce: bytes,
    ) -> bool:
        """Verify content against this binding."""

        return verify_content_commitment(
            content,
            profile,
            nonce,
            base64url_decode(self.commitment, length=32),
        )

    def to_dict(self) -> dict[str, str]:
        """Return the binding's wire representation."""

        result = {
            "algorithm": self.algorithm,
            "commitment": self.commitment,
        }
        if self.public_nonce is not None:
            result["public_nonce"] = self.public_nonce
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse a binding from its wire representation."""

        _reject_unknown_fields(
            value,
            {"algorithm", "commitment", "public_nonce"},
            "content binding",
        )
        public_nonce = value.get("public_nonce")
        if public_nonce is not None and not isinstance(public_nonce, str):
            raise ManifestError("public_nonce must be a string")
        return cls(
            commitment=_required_string(value, "commitment"),
            algorithm=_required_string(value, "algorithm"),
            public_nonce=public_nonce,
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
    claim_meanings: tuple[ClaimMeaning, ...] = (
        ClaimMeaning.SIGNED_BY,
        ClaimMeaning.TRAINING_RESTRICTION,
    )
    carriers: tuple[str, ...] = ()
    watermarks: tuple[str, ...] = ()
    actions: tuple[C2PAAction, ...] = ()
    ingredients: tuple[C2PAIngredient, ...] = ()
    fingerprints: tuple[ContentFingerprint, ...] = ()
    source_url: str | None = None
    licensing_url: str | None = None
    version: str = "1"

    def __post_init__(self) -> None:
        try:
            object.__setattr__(
                self,
                "claim_meanings",
                tuple(ClaimMeaning(item) for item in self.claim_meanings),
            )
        except ValueError as error:
            raise ManifestError("unsupported claim meaning") from error
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
        if not self.claim_meanings:
            raise ManifestError("claim_meanings must not be empty")
        if len(set(self.claim_meanings)) != len(self.claim_meanings):
            raise ManifestError("claim meanings must be unique")
        if len(set(self.carriers)) != len(self.carriers):
            raise ManifestError("carrier identifiers must be unique")
        if len(set(self.watermarks)) != len(self.watermarks):
            raise ManifestError("watermark identifiers must be unique")
        object.__setattr__(
            self,
            "actions",
            tuple(
                item
                if isinstance(item, C2PAAction)
                else C2PAAction.from_dict(cast(Mapping[str, object], item))
                for item in self.actions
            ),
        )
        object.__setattr__(
            self,
            "ingredients",
            tuple(
                item
                if isinstance(item, C2PAIngredient)
                else C2PAIngredient.from_dict(cast(Mapping[str, object], item))
                for item in self.ingredients
            ),
        )
        object.__setattr__(
            self,
            "fingerprints",
            tuple(
                item
                if isinstance(item, ContentFingerprint)
                else ContentFingerprint.from_dict(
                    cast(Mapping[str, object], item)
                )
                for item in self.fingerprints
            ),
        )
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
        claim_meanings: tuple[ClaimMeaning, ...] = (
            ClaimMeaning.SIGNED_BY,
            ClaimMeaning.TRAINING_RESTRICTION,
        ),
        carriers: tuple[str, ...] = (),
        watermarks: tuple[str, ...] = (),
        actions: tuple[C2PAAction, ...] = (),
        ingredients: tuple[C2PAIngredient, ...] = (),
        fingerprints: tuple[ContentFingerprint, ...] = (),
        source_url: str | None = None,
        licensing_url: str | None = None,
        claim_id: UUID | None = None,
        nonce: bytes,
        disclose_nonce: bool = True,
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
                disclose_nonce=disclose_nonce,
            ),
            policy=policy,
            claim_meanings=claim_meanings,
            carriers=carriers,
            watermarks=watermarks,
            actions=actions,
            ingredients=ingredients,
            fingerprints=fingerprints,
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
            "claim_meanings": [item.value for item in self.claim_meanings],
            "carriers": list(self.carriers),
            "watermarks": list(self.watermarks),
            "actions": {"actions": [item.to_dict() for item in self.actions]},
            "ingredients": {
                "ingredients": [item.to_dict() for item in self.ingredients]
            },
        }
        if self.fingerprints:
            result["fingerprints"] = [
                item.to_dict() for item in self.fingerprints
            ]
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
            _reject_unknown_fields(
                value,
                {
                    "version",
                    "claim_id",
                    "registry_url",
                    "registry_root_fingerprint",
                    "claimant_key_id",
                    "mime_type",
                    "canonicalization",
                    "content_binding",
                    "policy",
                    "claim_meanings",
                    "carriers",
                    "watermarks",
                    "actions",
                    "ingredients",
                    "fingerprints",
                    "source_url",
                    "licensing_url",
                },
                "manifest",
            )
            binding_value = value["content_binding"]
            policy_value = value["policy"]
            if not isinstance(binding_value, Mapping) or not isinstance(
                policy_value, Mapping
            ):
                raise ManifestError("binding and policy must be objects")
            binding = cast(Mapping[str, object], binding_value)
            policy_wrapper = cast(Mapping[str, object], policy_value)
            _reject_unknown_fields(
                policy_wrapper,
                {"label", "entries"},
                "policy",
            )
            if policy_wrapper["label"] != "cawg.training-mining":
                raise ManifestError("unsupported policy label")
            entries_value = policy_wrapper["entries"]
            if not isinstance(entries_value, Mapping):
                raise ManifestError("policy entries must be an object")
            policy_entries = cast(Mapping[str, object], entries_value)
            source_url = value.get("source_url")
            licensing_url = value.get("licensing_url")
            claim_meanings_value = value.get(
                "claim_meanings",
                [ClaimMeaning.SIGNED_BY.value],
            )
            actions_value = value.get("actions", {"actions": []})
            ingredients_value = value.get(
                "ingredients",
                {"ingredients": []},
            )
            fingerprints_value = value.get("fingerprints", [])
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
                claim_meanings=_claim_meaning_list(claim_meanings_value),
                carriers=_string_list(value["carriers"], "carriers"),
                watermarks=_string_list(value["watermarks"], "watermarks"),
                actions=_action_list(actions_value),
                ingredients=_ingredient_list(ingredients_value),
                fingerprints=_fingerprint_list(fingerprints_value),
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

        _reject_unknown_fields(
            value,
            {"algorithm", "key_id", "value"},
            "signature",
        )
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
            parsed_value = cast(Mapping[str, object], parsed)
            _reject_unknown_fields(
                parsed_value,
                {"manifest", "signature"},
                "signed manifest",
            )
            manifest_value = parsed_value["manifest"]
            signature_value = parsed_value["signature"]
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
    content_binding_checked: bool
    public_nonce_available: bool
    errors: tuple[str, ...]

    @property
    def policy_valid(self) -> bool:
        return not self.errors

    @property
    def overall_verdict(self) -> VerificationVerdict:
        if not self.signature_valid or not self.key_id_valid:
            return VerificationVerdict.SIGNATURE_INVALID
        if self.content_binding_valid is True:
            return VerificationVerdict.CONTENT_VERIFIED
        if self.content_binding_valid is False:
            return VerificationVerdict.CONTENT_MISMATCH
        if not self.public_nonce_available:
            return VerificationVerdict.PRIVATE_CONTENT_UNCHECKED
        return VerificationVerdict.SIGNATURE_ONLY

    @property
    def valid(self) -> bool:
        """Whether every check requested by the caller succeeded."""

        return (
            self.signature_valid
            and self.key_id_valid
            and self.content_binding_valid is not False
            and not self.errors
        )

    @property
    def claim_signature_valid(self) -> bool:
        """Whether the claimant key id and manifest signature are valid."""

        return self.signature_valid and self.key_id_valid

    @property
    def content_claim_valid(self) -> bool:
        return (
            self.claim_signature_valid and self.content_binding_valid is True
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "signature_valid": self.signature_valid,
            "key_id_valid": self.key_id_valid,
            "content_binding_valid": self.content_binding_valid,
            "content_binding_checked": self.content_binding_checked,
            "public_nonce_available": self.public_nonce_available,
            "policy_valid": self.policy_valid,
            "overall_verdict": self.overall_verdict.value,
            "valid": self.valid,
            "errors": list(self.errors),
        }


def verify_manifest(
    signed: SignedManifest,
    claimant_public_jwk: Mapping[str, object],
    content: bytes | None = None,
    nonce: bytes | None = None,
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
            content_binding_checked=False,
            public_nonce_available=(
                signed.manifest.content_binding.public_nonce is not None
            ),
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

    public_nonce = signed.manifest.content_binding.public_nonce_bytes()
    public_nonce_available = public_nonce is not None
    if nonce is not None and public_nonce is not None:
        if not hmac.compare_digest(nonce, public_nonce):
            errors.append("supplied nonce does not match public nonce")

    verification_nonce = nonce or public_nonce
    content_binding_valid: bool | None = None
    content_binding_checked = False
    if content is not None and verification_nonce is None:
        content_binding_valid = False
        errors.append("content binding nonce is required")
    elif content is not None:
        assert verification_nonce is not None
        content_binding_checked = True
        content_binding_valid = signed.manifest.content_binding.verify(
            content,
            signed.manifest.canonicalization,
            verification_nonce,
        )
        if not content_binding_valid:
            errors.append("content binding does not match")

    return VerificationReport(
        signature_valid,
        key_id_valid,
        content_binding_valid,
        content_binding_checked,
        public_nonce_available,
        tuple(errors),
    )
