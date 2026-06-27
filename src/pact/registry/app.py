"""Registry trust, replay-challenge, certificate, and state-management logic."""

import hashlib
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Self, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pact.canonical import JsonValue, canonical_json
from pact.crypto import (
    base64url_encode,
    jwk_thumbprint,
    public_key_from_jwk,
    sign_es256,
    verify_es256,
)
from pact.identity import ClaimantIdentity, normalize_registry_url
from pact.manifest import SignedManifest, verify_manifest
from pact.privacy import PrivacyAuditError, audit_registry_claim_payload
from pact.registry.store import (
    RegistryEvent,
    RegistryEventType,
    RegistryStore,
    RegistryStoreError,
)
from pact.watermarks.base import TrustMarkLocator


class RegistryError(ValueError):
    """Raised when registry mutation input or state is invalid."""


def _optional_http_url(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RegistryError(f"{field_name} must be a URL string")
    stripped = value.strip()
    if not stripped:
        return None
    parsed = urlsplit(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RegistryError(f"{field_name} must be an HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise RegistryError(f"{field_name} must not contain credentials")
    return stripped


class ChallengePurpose(StrEnum):
    """Replay-challenge purpose labels."""

    PROFILE_REGISTRATION = "profile_registration"
    PROFILE_UPDATE = "profile_update"
    CERTIFICATE_ISSUANCE = "certificate_issuance"
    CLAIM_REGISTRATION = "claim_registration"
    KEY_ROTATION = "key_rotation"
    CLAIM_REVOCATION = "claim_revocation"
    DOMAIN_VERIFICATION = "domain_verification"
    DISPUTE_OPEN = "dispute_open"
    DISPUTE_RESOLUTION = "dispute_resolution"


class DisputeStatus(StrEnum):
    """Public registry dispute states."""

    OPEN = "open"
    UPHELD = "upheld"
    REJECTED = "rejected"


class TrustLabel(StrEnum):
    """Derived registry evidence labels."""

    UNVERIFIED = "unverified"
    UNAUTHENTICATED_DEVICE = "unauthenticated_device"
    HOSTED_ACCOUNT = "hosted_account"
    DEVICE_ATTESTED = "device_attested"
    DOMAIN_VERIFIED = "domain_verified"
    THIRD_PARTY_ATTESTED = "third_party_attested"
    DOCUMENTED_RIGHTS = "documented_rights"
    DISPUTED = "disputed"
    REVOKED = "revoked"


class TrustTier(StrEnum):
    """Ordered claimant assurance tiers used by verification reports."""

    UNAUTHENTICATED_DEVICE = "unauthenticated_device"
    HOSTED_ACCOUNT = "hosted_account"
    DOMAIN_VERIFIED = "domain_verified"
    THIRD_PARTY_ATTESTED = "third_party_attested"


class VerificationLabel(StrEnum):
    """Evidence-based public verification labels."""

    VERIFIED_CLAIM = "verified_claim"
    PARTIAL_MATCH = "partial_match"
    UNTRUSTED_CLAIM = "untrusted_claim"
    DISPUTED = "disputed"
    REVOKED = "revoked"
    INCONCLUSIVE = "inconclusive"


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _isoformat(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat()


def _parse_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RegistryError(
            f"{label} must be a valid ISO 8601 string"
        ) from error
    if parsed.tzinfo is None:
        raise RegistryError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + (8 - byte.bit_length())
    return bits


@dataclass(frozen=True, slots=True)
class MutationChallenge:
    """Server-issued replay and proof-of-work challenge."""

    registry_url: str
    challenge_id: UUID
    purpose: ChallengePurpose
    issued_at: datetime
    expires_at: datetime
    challenge_nonce: str
    difficulty: int = 12
    bound_key_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "registry_url",
            normalize_registry_url(self.registry_url),
        )
        if self.difficulty < 0 or self.difficulty > 255:
            raise RegistryError(
                "challenge difficulty must be between 0 and 255"
            )

    @classmethod
    def create(
        cls,
        registry_url: str,
        purpose: ChallengePurpose,
        *,
        ttl: timedelta = timedelta(minutes=5),
        difficulty: int = 12,
        bound_key_id: str | None = None,
    ) -> Self:
        issued_at = _utc_now()
        return cls(
            registry_url=registry_url,
            challenge_id=uuid4(),
            purpose=purpose,
            issued_at=issued_at,
            expires_at=issued_at + ttl,
            challenge_nonce=base64url_encode(uuid4().bytes + uuid4().bytes),
            difficulty=difficulty,
            bound_key_id=bound_key_id,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Self:
        """Parse a persisted challenge payload."""

        try:
            registry_url = value["registry_url"]
            challenge_id = value["challenge_id"]
            purpose = value["purpose"]
            challenge_nonce = value["challenge_nonce"]
            difficulty = value["difficulty"]
        except KeyError as error:
            raise RegistryError(
                "stored challenge is missing required fields"
            ) from error

        if not isinstance(registry_url, str):
            raise RegistryError(
                "stored challenge registry_url must be a string"
            )
        if not isinstance(challenge_id, str):
            raise RegistryError("stored challenge_id must be a string")
        if not isinstance(purpose, str):
            raise RegistryError("stored challenge purpose must be a string")
        if not isinstance(challenge_nonce, str):
            raise RegistryError("stored challenge_nonce must be a string")
        if not isinstance(difficulty, int):
            raise RegistryError(
                "stored challenge difficulty must be an integer"
            )

        bound_key_id = value.get("bound_key_id")
        if bound_key_id is not None and not isinstance(bound_key_id, str):
            raise RegistryError(
                "stored challenge bound_key_id must be a string"
            )

        return cls(
            registry_url=registry_url,
            challenge_id=UUID(challenge_id),
            purpose=ChallengePurpose(purpose),
            issued_at=_parse_datetime(value.get("issued_at"), "issued_at"),
            expires_at=_parse_datetime(value.get("expires_at"), "expires_at"),
            challenge_nonce=challenge_nonce,
            difficulty=difficulty,
            bound_key_id=bound_key_id,
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible challenge payload."""

        result: dict[str, object] = {
            "registry_url": self.registry_url,
            "challenge_id": str(self.challenge_id),
            "purpose": self.purpose.value,
            "issued_at": _isoformat(self.issued_at),
            "expires_at": _isoformat(self.expires_at),
            "challenge_nonce": self.challenge_nonce,
            "difficulty": self.difficulty,
        }
        if self.bound_key_id is not None:
            result["bound_key_id"] = self.bound_key_id
        return result

    def canonical_bytes(self) -> bytes:
        """Return the canonical bytes covered by the client signature."""

        return canonical_json(self.to_dict())

    def verify_solution(self, solution: int) -> bool:
        """Validate a proof-of-work integer against this challenge."""

        if solution < 0:
            return False
        digest = hashlib.sha256(
            self.canonical_bytes() + b":" + str(solution).encode("ascii")
        ).digest()
        return _leading_zero_bits(digest) >= self.difficulty


@dataclass(frozen=True, slots=True)
class MutationRequest:
    """Claimant-signed mutation request paired with a replay challenge."""

    challenge_id: UUID
    claimant_public_jwk: dict[str, str]
    proof_of_work_solution: int
    payload: dict[str, object]
    signature: str

    @property
    def claimant_key_id(self) -> str:
        """Return the RFC 7638 thumbprint for the claimant public JWK."""

        return jwk_thumbprint(self.claimant_public_jwk)

    def signed_bytes(self, challenge: MutationChallenge) -> bytes:
        """Return the canonical bytes signed by the claimant."""

        return canonical_json(
            cast(
                JsonValue,
                {
                    "challenge": challenge.to_dict(),
                    "claimant_public_jwk": self.claimant_public_jwk,
                    "proof_of_work_solution": self.proof_of_work_solution,
                    "payload": self.payload,
                },
            )
        )

    @classmethod
    def create(
        cls,
        identity: ClaimantIdentity,
        challenge: MutationChallenge,
        *,
        payload: dict[str, object],
        proof_of_work_solution: int,
    ) -> Self:
        signed_bytes = canonical_json(
            cast(
                JsonValue,
                {
                    "challenge": challenge.to_dict(),
                    "claimant_public_jwk": identity.public_jwk,
                    "proof_of_work_solution": proof_of_work_solution,
                    "payload": payload,
                },
            )
        )
        return cls(
            challenge_id=challenge.challenge_id,
            claimant_public_jwk=identity.public_jwk,
            proof_of_work_solution=proof_of_work_solution,
            payload=payload,
            signature=sign_es256(identity.private_key, signed_bytes),
        )


@dataclass(frozen=True, slots=True)
class KeyRotationRequest:
    """Old/new co-signed key rotation request."""

    challenge_id: UUID
    current_public_jwk: dict[str, str]
    replacement_public_jwk: dict[str, str]
    proof_of_work_solution: int
    payload: dict[str, object]
    current_signature: str
    replacement_signature: str

    @property
    def current_key_id(self) -> str:
        return jwk_thumbprint(self.current_public_jwk)

    @property
    def replacement_key_id(self) -> str:
        return jwk_thumbprint(self.replacement_public_jwk)

    def signed_bytes(self, challenge: MutationChallenge) -> bytes:
        return canonical_json(
            cast(
                JsonValue,
                {
                    "challenge": challenge.to_dict(),
                    "current_public_jwk": self.current_public_jwk,
                    "replacement_public_jwk": self.replacement_public_jwk,
                    "proof_of_work_solution": self.proof_of_work_solution,
                    "payload": self.payload,
                },
            )
        )

    @classmethod
    def create(
        cls,
        current_identity: ClaimantIdentity,
        replacement_identity: ClaimantIdentity,
        challenge: MutationChallenge,
        *,
        payload: dict[str, object],
        proof_of_work_solution: int,
    ) -> Self:
        signed_bytes = canonical_json(
            cast(
                JsonValue,
                {
                    "challenge": challenge.to_dict(),
                    "current_public_jwk": current_identity.public_jwk,
                    "replacement_public_jwk": replacement_identity.public_jwk,
                    "proof_of_work_solution": proof_of_work_solution,
                    "payload": payload,
                },
            )
        )
        return cls(
            challenge_id=challenge.challenge_id,
            current_public_jwk=current_identity.public_jwk,
            replacement_public_jwk=replacement_identity.public_jwk,
            proof_of_work_solution=proof_of_work_solution,
            payload=payload,
            current_signature=sign_es256(
                current_identity.private_key, signed_bytes
            ),
            replacement_signature=sign_es256(
                replacement_identity.private_key, signed_bytes
            ),
        )


@dataclass(frozen=True, slots=True)
class RegistryCertificateAuthority:
    """Offline root and online intermediate registry CA material."""

    registry_url: str
    root_certificate_pem: bytes
    root_private_key_pem: bytes | None
    intermediate_certificate_pem: bytes
    intermediate_private_key_pem: bytes

    @property
    def root_fingerprint(self) -> str:
        """Return the SHA-256 fingerprint of the root certificate."""

        certificate = x509.load_pem_x509_certificate(self.root_certificate_pem)
        return base64url_encode(
            hashlib.sha256(
                certificate.public_bytes(serialization.Encoding.DER)
            ).digest()
        )

    @classmethod
    def initialize(
        cls,
        registry_url: str,
        *,
        root_common_name: str = "PACT Offline Root CA",
        intermediate_common_name: str = "PACT Online Intermediate CA",
        root_private_key_password: str | None = None,
    ) -> Self:
        registry_url = normalize_registry_url(registry_url)
        now = _utc_now()
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, root_common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, registry_url),
            ]
        )
        root_certificate = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    root_key.public_key()
                ),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )

        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_name = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, intermediate_common_name
                ),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, registry_url),
            ]
        )
        intermediate_certificate = (
            x509.CertificateBuilder()
            .subject_name(intermediate_name)
            .issuer_name(root_certificate.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    intermediate_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    root_key.public_key()
                ),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        return cls(
            registry_url=registry_url,
            root_certificate_pem=root_certificate.public_bytes(
                serialization.Encoding.PEM
            ),
            root_private_key_pem=root_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(
                    root_private_key_password.encode("utf-8")
                )
                if root_private_key_password
                else serialization.NoEncryption(),
            ),
            intermediate_certificate_pem=intermediate_certificate.public_bytes(
                serialization.Encoding.PEM
            ),
            intermediate_private_key_pem=intermediate_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    def issue_claimant_certificate(
        self,
        claimant_public_jwk: Mapping[str, object],
        *,
        common_name: str,
        valid_days: int = 30,
    ) -> tuple[bytes, bytes]:
        """Issue a claimant end-entity certificate and return its chain."""

        if valid_days < 1:
            raise RegistryError("valid_days must be positive")
        intermediate_key = cast(
            ec.EllipticCurvePrivateKey,
            serialization.load_pem_private_key(
                self.intermediate_private_key_pem,
                password=None,
            ),
        )
        intermediate_certificate = x509.load_pem_x509_certificate(
            self.intermediate_certificate_pem
        )
        claimant_public_key = public_key_from_jwk(claimant_public_jwk)
        now = _utc_now()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
                )
            )
            .issuer_name(intermediate_certificate.subject)
            .public_key(claimant_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=valid_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(claimant_public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    intermediate_key.public_key()
                ),
                critical=False,
            )
            .sign(intermediate_key, hashes.SHA256())
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        chain_pem = certificate_pem + self.intermediate_certificate_pem
        return certificate_pem, chain_pem

    def online_material(self) -> Self:
        """Return the subset of CA material required by the online service."""

        return type(self)(
            registry_url=self.registry_url,
            root_certificate_pem=self.root_certificate_pem,
            root_private_key_pem=None,
            intermediate_certificate_pem=self.intermediate_certificate_pem,
            intermediate_private_key_pem=self.intermediate_private_key_pem,
        )


@dataclass(frozen=True, slots=True)
class ClaimantProfile:
    """Public registry claimant profile state."""

    key_id: str
    public_jwk: dict[str, str]
    created_at: datetime
    display_name: str | None = None
    replacement_key_id: str | None = None
    verified_domains: tuple[str, ...] = ()
    hosted_account: bool = False
    device_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class RegisteredClaim:
    """A registered signed manifest and its current registry state."""

    claim_id: UUID
    claimant_key_id: str
    registered_at: datetime
    signed_manifest: SignedManifest
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class DisputeRecord:
    """A public dispute thread attached to a claim."""

    dispute_id: UUID
    claim_id: UUID
    opened_by_key_id: str
    opened_at: datetime
    reason: str
    misuse_url: str | None = None
    status: DisputeStatus = DisputeStatus.OPEN
    resolved_at: datetime | None = None
    resolution_note: str | None = None
    resolved_by_key_id: str | None = None


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    """Materialized public registry state derived from the event log."""

    last_sequence: int
    profiles: dict[str, ClaimantProfile]
    claims: dict[UUID, RegisteredClaim]
    disputes: dict[UUID, DisputeRecord]
    certificate_counts: dict[str, int]
    rotation_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class EvidenceProfile:
    """Derived evidence summary for a claimant profile."""

    key_age_days: int
    active_claim_count: int
    revoked_claim_count: int
    verified_domains: tuple[str, ...]
    certificate_count: int
    rotation_count: int
    open_disputes: int
    upheld_disputes: int
    rejected_disputes: int
    hosted_account: bool = False
    device_continuity: bool = False
    hardware_attested: bool = False
    third_party_attested: bool = False
    documented_rights: bool = False

    @property
    def trust_tier(self) -> TrustTier:
        """Return the strongest derived claimant assurance tier."""

        if self.third_party_attested:
            return TrustTier.THIRD_PARTY_ATTESTED
        if self.verified_domains:
            return TrustTier.DOMAIN_VERIFIED
        if self.hosted_account:
            return TrustTier.HOSTED_ACCOUNT
        return TrustTier.UNAUTHENTICATED_DEVICE

    @property
    def trust_labels(self) -> tuple[TrustLabel, ...]:
        labels: list[TrustLabel] = []
        if self.hosted_account:
            labels.append(TrustLabel.HOSTED_ACCOUNT)
        else:
            labels.append(TrustLabel.UNAUTHENTICATED_DEVICE)
        if self.hardware_attested:
            labels.append(TrustLabel.DEVICE_ATTESTED)
        if self.verified_domains:
            labels.append(TrustLabel.DOMAIN_VERIFIED)
        if self.third_party_attested:
            labels.append(TrustLabel.THIRD_PARTY_ATTESTED)
        if self.documented_rights:
            labels.append(TrustLabel.DOCUMENTED_RIGHTS)
        if self.open_disputes or self.upheld_disputes:
            labels.append(TrustLabel.DISPUTED)
        if self.revoked_claim_count:
            labels.append(TrustLabel.REVOKED)
        return tuple(labels)


@dataclass(frozen=True, slots=True)
class ClaimVerificationReport:
    """Registry-centered verification result for one signed claim."""

    claim_id: UUID
    label: VerificationLabel
    trust_tier: TrustTier
    trust_labels: tuple[TrustLabel, ...]
    registry_included: bool
    manifest_signature_valid: bool
    content_binding_valid: bool | None
    revoked: bool
    disputed: bool
    open_disputes: int
    upheld_disputes: int
    claim_meanings: tuple[str, ...]
    evidence: dict[str, object]
    errors: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        """Whether the claim is currently verified by registry evidence."""

        return self.label is VerificationLabel.VERIFIED_CLAIM

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible verification report."""

        return {
            "claim_id": str(self.claim_id),
            "label": self.label.value,
            "trust_tier": self.trust_tier.value,
            "trust_labels": [label.value for label in self.trust_labels],
            "registry_included": self.registry_included,
            "manifest_signature_valid": self.manifest_signature_valid,
            "content_binding_valid": self.content_binding_valid,
            "revoked": self.revoked,
            "disputed": self.disputed,
            "open_disputes": self.open_disputes,
            "upheld_disputes": self.upheld_disputes,
            "claim_meanings": list(self.claim_meanings),
            "evidence": self.evidence,
            "errors": list(self.errors),
        }


class RegistryService:
    """Core registry mutation and public-state logic."""

    def __init__(
        self,
        registry_url: str,
        *,
        store: RegistryStore,
        certificate_authority: RegistryCertificateAuthority,
        admin_public_jwks: tuple[Mapping[str, object], ...] = (),
    ) -> None:
        self.registry_url = normalize_registry_url(registry_url)
        self.store = store
        self.certificate_authority = certificate_authority
        self._snapshot_lock = threading.RLock()
        self._snapshot: RegistrySnapshot | None = None
        self._admin_key_ids = {
            jwk_thumbprint(cast(Mapping[str, str], dict(value)))
            for value in admin_public_jwks
        }

    def issue_challenge(
        self,
        purpose: ChallengePurpose,
        *,
        bound_key_id: str | None = None,
        ttl: timedelta = timedelta(minutes=5),
        difficulty: int = 12,
    ) -> MutationChallenge:
        """Issue and persist a replay challenge."""

        self.store.purge_expired_challenges(_utc_now())

        challenge = MutationChallenge.create(
            self.registry_url,
            purpose,
            ttl=ttl,
            difficulty=difficulty,
            bound_key_id=bound_key_id,
        )

        self.store.save_challenge(
            challenge_id=challenge.challenge_id,
            expires_at=challenge.expires_at,
            challenge=challenge.to_dict(),
        )

        return challenge

    def _event_time(self, event: RegistryEvent) -> datetime:
        return event.occurred_at.astimezone(UTC)

    def _append_event(
        self,
        event_type: RegistryEventType,
        actor_key_id: str | None,
        data: dict[str, object],
    ) -> RegistryEvent:
        event = self.store.append(event_type, actor_key_id, data)

        with self._snapshot_lock:
            self._snapshot = None

        return event

    def _current_snapshot(self) -> RegistrySnapshot:
        latest_sequence = self.store.latest_sequence()

        with self._snapshot_lock:
            snapshot = self._snapshot
            if (
                snapshot is not None
                and snapshot.last_sequence == latest_sequence
            ):
                return snapshot

            snapshot = self._build_snapshot()
            self._snapshot = snapshot
            return snapshot

    def _build_snapshot(self) -> RegistrySnapshot:
        profiles: dict[str, ClaimantProfile] = {}
        claims: dict[UUID, RegisteredClaim] = {}
        disputes: dict[UUID, DisputeRecord] = {}
        certificate_counts: dict[str, int] = {}
        rotation_counts: dict[str, int] = {}
        last_sequence = 0

        for event in self.store.list_events():
            last_sequence = event.sequence
            data = event.data

            if event.event_type is RegistryEventType.PROFILE_REGISTERED:
                key_id = cast(str, data["key_id"])
                public_jwk_value = data["public_jwk"]
                if not isinstance(public_jwk_value, dict):
                    raise RegistryStoreError(
                        "stored public_jwk must be an object"
                    )

                profiles[key_id] = ClaimantProfile(
                    key_id=key_id,
                    public_jwk=cast(dict[str, str], public_jwk_value),
                    created_at=self._event_time(event),
                    display_name=cast(str | None, data.get("display_name")),
                    hosted_account=bool(data.get("hosted_account", False)),
                    device_fingerprint=cast(
                        str | None,
                        data.get("device_fingerprint"),
                    ),
                )

            elif event.event_type is RegistryEventType.PROFILE_UPDATED:
                key_id = cast(str, data["key_id"])
                current = profiles[key_id]

                profiles[key_id] = ClaimantProfile(
                    key_id=current.key_id,
                    public_jwk=current.public_jwk,
                    created_at=current.created_at,
                    display_name=cast(str | None, data.get("display_name")),
                    replacement_key_id=current.replacement_key_id,
                    verified_domains=current.verified_domains,
                    hosted_account=current.hosted_account,
                    device_fingerprint=current.device_fingerprint,
                )

            elif event.event_type is RegistryEventType.DOMAIN_VERIFIED:
                key_id = cast(str, data["key_id"])
                domain = cast(str, data["domain"])
                current = profiles[key_id]

                profiles[key_id] = ClaimantProfile(
                    key_id=current.key_id,
                    public_jwk=current.public_jwk,
                    created_at=current.created_at,
                    display_name=current.display_name,
                    replacement_key_id=current.replacement_key_id,
                    verified_domains=tuple(
                        sorted({*current.verified_domains, domain})
                    ),
                    hosted_account=current.hosted_account,
                    device_fingerprint=current.device_fingerprint,
                )

            elif event.event_type is RegistryEventType.KEY_ROTATED:
                current_key_id = cast(str, data["current_key_id"])
                replacement_key_id = cast(str, data["replacement_key_id"])
                replacement_public_jwk = data["replacement_public_jwk"]

                if not isinstance(replacement_public_jwk, dict):
                    raise RegistryStoreError(
                        "stored replacement_public_jwk must be an object"
                    )

                current = profiles[current_key_id]

                profiles[current_key_id] = ClaimantProfile(
                    key_id=current.key_id,
                    public_jwk=current.public_jwk,
                    created_at=current.created_at,
                    display_name=current.display_name,
                    replacement_key_id=replacement_key_id,
                    verified_domains=current.verified_domains,
                    hosted_account=current.hosted_account,
                    device_fingerprint=current.device_fingerprint,
                )

                profiles[replacement_key_id] = ClaimantProfile(
                    key_id=replacement_key_id,
                    public_jwk=cast(dict[str, str], replacement_public_jwk),
                    created_at=self._event_time(event),
                    display_name=current.display_name,
                    verified_domains=current.verified_domains,
                    hosted_account=current.hosted_account,
                    device_fingerprint=current.device_fingerprint,
                )

                rotation_counts[current_key_id] = (
                    rotation_counts.get(current_key_id, 0) + 1
                )
                rotation_counts[replacement_key_id] = (
                    rotation_counts.get(replacement_key_id, 0) + 1
                )

            elif event.event_type is RegistryEventType.CERTIFICATE_ISSUED:
                if event.actor_key_id is not None:
                    certificate_counts[event.actor_key_id] = (
                        certificate_counts.get(event.actor_key_id, 0) + 1
                    )

            elif event.event_type is RegistryEventType.CLAIM_REGISTERED:
                claim_id = UUID(cast(str, data["claim_id"]))
                signed_manifest_json = cast(str, data["signed_manifest_json"])

                claims[claim_id] = RegisteredClaim(
                    claim_id=claim_id,
                    claimant_key_id=cast(str, data["claimant_key_id"]),
                    registered_at=self._event_time(event),
                    signed_manifest=SignedManifest.from_json(
                        signed_manifest_json
                    ),
                )

            elif event.event_type is RegistryEventType.CLAIM_REVOKED:
                claim_id = UUID(cast(str, data["claim_id"]))
                current = claims[claim_id]

                claims[claim_id] = RegisteredClaim(
                    claim_id=current.claim_id,
                    claimant_key_id=current.claimant_key_id,
                    registered_at=current.registered_at,
                    signed_manifest=current.signed_manifest,
                    revoked_at=self._event_time(event),
                    revocation_reason=cast(str, data["reason"]),
                )

            elif event.event_type is RegistryEventType.DISPUTE_OPENED:
                dispute_id = UUID(cast(str, data["dispute_id"]))

                disputes[dispute_id] = DisputeRecord(
                    dispute_id=dispute_id,
                    claim_id=UUID(cast(str, data["claim_id"])),
                    opened_by_key_id=cast(str, data["opened_by_key_id"]),
                    opened_at=self._event_time(event),
                    reason=cast(str, data["reason"]),
                    misuse_url=cast(str | None, data.get("misuse_url")),
                )

            elif event.event_type is RegistryEventType.DISPUTE_RESOLVED:
                dispute_id = UUID(cast(str, data["dispute_id"]))
                current = disputes[dispute_id]

                disputes[dispute_id] = DisputeRecord(
                    dispute_id=current.dispute_id,
                    claim_id=current.claim_id,
                    opened_by_key_id=current.opened_by_key_id,
                    opened_at=current.opened_at,
                    reason=current.reason,
                    misuse_url=current.misuse_url,
                    status=DisputeStatus(cast(str, data["status"])),
                    resolved_at=self._event_time(event),
                    resolution_note=cast(str, data["resolution_note"]),
                    resolved_by_key_id=cast(str, data["resolved_by_key_id"]),
                )

        return RegistrySnapshot(
            last_sequence=last_sequence,
            profiles=profiles,
            claims=claims,
            disputes=disputes,
            certificate_counts=certificate_counts,
            rotation_counts=rotation_counts,
        )

    def _load_profiles(self) -> dict[str, ClaimantProfile]:
        return self._current_snapshot().profiles

    def _load_claims(self) -> dict[UUID, RegisteredClaim]:
        return self._current_snapshot().claims

    def _load_disputes(self) -> dict[UUID, DisputeRecord]:
        return self._current_snapshot().disputes

    def _consume_challenge(
        self,
        request_challenge_id: UUID,
        purpose: ChallengePurpose,
    ) -> MutationChallenge:
        stored = self.store.take_challenge(request_challenge_id)

        if stored is None:
            raise RegistryError("challenge is unknown or already consumed")

        challenge = MutationChallenge.from_dict(stored)

        if challenge.purpose is not purpose:
            raise RegistryError("challenge purpose does not match request")

        if challenge.expires_at < _utc_now():
            raise RegistryError("challenge has expired")

        return challenge

    def _consume_verified_request(
        self,
        request: MutationRequest,
        purpose: ChallengePurpose,
    ) -> MutationChallenge:
        challenge = self._consume_challenge(request.challenge_id, purpose)
        if (
            challenge.bound_key_id is not None
            and request.claimant_key_id != challenge.bound_key_id
        ):
            raise RegistryError(
                "challenge is bound to a different claimant key"
            )
        if not challenge.verify_solution(request.proof_of_work_solution):
            raise RegistryError("proof-of-work solution is invalid")
        try:
            public_key = public_key_from_jwk(request.claimant_public_jwk)
        except ValueError as error:
            raise RegistryError("claimant public JWK is invalid") from error
        if not verify_es256(
            public_key, request.signed_bytes(challenge), request.signature
        ):
            raise RegistryError("mutation request signature is invalid")
        return challenge

    def _consume_verified_rotation_request(
        self,
        request: KeyRotationRequest,
    ) -> MutationChallenge:
        challenge = self._consume_challenge(
            request.challenge_id,
            ChallengePurpose.KEY_ROTATION,
        )
        if (
            challenge.bound_key_id is not None
            and request.current_key_id != challenge.bound_key_id
        ):
            raise RegistryError(
                "rotation challenge is bound to a different claimant key"
            )
        if not challenge.verify_solution(request.proof_of_work_solution):
            raise RegistryError("proof-of-work solution is invalid")
        signed_bytes = request.signed_bytes(challenge)
        current_key = public_key_from_jwk(request.current_public_jwk)
        replacement_key = public_key_from_jwk(request.replacement_public_jwk)
        if not verify_es256(
            current_key, signed_bytes, request.current_signature
        ):
            raise RegistryError("current-key rotation signature is invalid")
        if not verify_es256(
            replacement_key, signed_bytes, request.replacement_signature
        ):
            raise RegistryError(
                "replacement-key rotation signature is invalid"
            )
        return challenge

    def get_profile(self, key_id: str) -> ClaimantProfile:
        """Return the current public profile for one claimant key."""

        profiles = self._load_profiles()
        try:
            return profiles[key_id]
        except KeyError as error:
            raise RegistryError("claimant profile does not exist") from error

    def get_claim(self, claim_id: UUID) -> RegisteredClaim:
        """Return one registered claim."""

        claims = self._load_claims()
        try:
            return claims[claim_id]
        except KeyError as error:
            raise RegistryError("registered claim does not exist") from error

    def list_claims(
        self,
        *,
        claimant_key_id: str | None = None,
    ) -> tuple[RegisteredClaim, ...]:
        """Return registered claims, optionally filtered by claimant key."""

        claims = sorted(
            self._load_claims().values(),
            key=lambda claim: claim.registered_at,
            reverse=True,
        )
        if claimant_key_id is None:
            return tuple(claims)
        return tuple(
            claim
            for claim in claims
            if claim.claimant_key_id == claimant_key_id
        )

    def find_claim_by_watermark_locator(
        self,
        locator: TrustMarkLocator,
    ) -> RegisteredClaim | None:
        """Resolve a decoded image watermark locator to one registered claim."""

        matches = [
            claim
            for claim in self._load_claims().values()
            if locator.matches_claim(
                claim.claim_id,
                claim.signed_manifest.manifest.registry_root_fingerprint,
            )
        ]
        if not matches:
            return None
        if len(matches) > 1:
            raise RegistryError("watermark locator matched multiple claims")
        return matches[0]

    def get_dispute(self, dispute_id: UUID) -> DisputeRecord:
        """Return one dispute record."""

        disputes = self._load_disputes()
        try:
            return disputes[dispute_id]
        except KeyError as error:
            raise RegistryError("dispute does not exist") from error

    def list_disputes(
        self,
        *,
        claim_id: UUID | None = None,
        claimant_key_id: str | None = None,
    ) -> tuple[DisputeRecord, ...]:
        """Return disputes, optionally filtered by claim or claim owner."""

        snapshot = self._current_snapshot()

        disputes = sorted(
            snapshot.disputes.values(),
            key=lambda dispute: dispute.opened_at,
            reverse=True,
        )

        if claim_id is not None:
            disputes = [
                dispute for dispute in disputes if dispute.claim_id == claim_id
            ]

        if claimant_key_id is not None:
            disputes = [
                dispute
                for dispute in disputes
                if snapshot.claims[dispute.claim_id].claimant_key_id
                == claimant_key_id
            ]

        return tuple(disputes)

    def register_profile(self, request: MutationRequest) -> ClaimantProfile:
        """Register a new pseudonymous claimant profile."""

        self._consume_verified_request(
            request,
            ChallengePurpose.PROFILE_REGISTRATION,
        )
        profiles = self._load_profiles()
        if request.claimant_key_id in profiles:
            raise RegistryError("claimant profile already exists")
        device_fingerprint = request.payload.get("device_fingerprint")
        if not isinstance(device_fingerprint, str) or not device_fingerprint:
            raise RegistryError("device_fingerprint must be a nonempty string")
        if any(
            profile.device_fingerprint == device_fingerprint
            for profile in profiles.values()
        ):
            raise RegistryError(
                "this device is already registered to another claimant profile"
            )
        display_name = request.payload.get("display_name")
        if display_name is not None and not isinstance(display_name, str):
            raise RegistryError("display_name must be a string")
        hosted_account = request.payload.get("hosted_account", False)
        if not isinstance(hosted_account, bool):
            raise RegistryError("hosted_account must be a boolean")
        self._append_event(
            RegistryEventType.PROFILE_REGISTERED,
            request.claimant_key_id,
            {
                "key_id": request.claimant_key_id,
                "public_jwk": request.claimant_public_jwk,
                "display_name": display_name,
                "hosted_account": hosted_account,
                "device_fingerprint": device_fingerprint,
            },
        )
        self._append_claimant_certificate(request.claimant_public_jwk)
        return self.get_profile(request.claimant_key_id)

    def update_profile(self, request: MutationRequest) -> ClaimantProfile:
        """Update public claimant profile metadata."""

        self._consume_verified_request(
            request,
            ChallengePurpose.PROFILE_UPDATE,
        )
        self.get_profile(request.claimant_key_id)
        display_name = request.payload.get("display_name")
        if display_name is not None and not isinstance(display_name, str):
            raise RegistryError("display_name must be a string")
        if isinstance(display_name, str) and not display_name.strip():
            display_name = None
        self._append_event(
            RegistryEventType.PROFILE_UPDATED,
            request.claimant_key_id,
            {
                "key_id": request.claimant_key_id,
                "display_name": display_name,
            },
        )
        return self.get_profile(request.claimant_key_id)

    def _append_claimant_certificate(
        self,
        claimant_public_jwk: Mapping[str, object],
        *,
        valid_days: int = 30,
    ) -> tuple[bytes, bytes]:
        key_id = jwk_thumbprint(cast(Mapping[str, str], claimant_public_jwk))
        certificate_pem, chain_pem = (
            self.certificate_authority.issue_claimant_certificate(
                claimant_public_jwk,
                common_name=key_id,
                valid_days=valid_days,
            )
        )
        self._append_event(
            RegistryEventType.CERTIFICATE_ISSUED,
            key_id,
            {
                "key_id": key_id,
                "certificate_pem": certificate_pem.decode("ascii"),
                "chain_pem": chain_pem.decode("ascii"),
            },
        )
        return certificate_pem, chain_pem

    def issue_claimant_certificate(
        self,
        request: MutationRequest,
        *,
        valid_days: int = 30,
    ) -> tuple[bytes, bytes]:
        """Issue a claimant certificate after private-key possession proof."""

        self._consume_verified_request(
            request,
            ChallengePurpose.CERTIFICATE_ISSUANCE,
        )
        self.get_profile(request.claimant_key_id)
        return self._append_claimant_certificate(
            request.claimant_public_jwk,
            valid_days=valid_days,
        )

    def register_claim(self, request: MutationRequest) -> RegisteredClaim:
        """Register a signed manifest under the claimant's public profile."""

        self._consume_verified_request(
            request,
            ChallengePurpose.CLAIM_REGISTRATION,
        )
        self.get_profile(request.claimant_key_id)
        try:
            audit_registry_claim_payload(request.payload).require_passed()
        except PrivacyAuditError as error:
            raise RegistryError(
                f"claim registration failed privacy audit: {error}"
            ) from error
        manifest_json = request.payload.get("signed_manifest_json")
        if not isinstance(manifest_json, str):
            raise RegistryError("signed_manifest_json must be a string")
        signed_manifest = SignedManifest.from_json(manifest_json)
        if signed_manifest.manifest.registry_url != self.registry_url:
            raise RegistryError("manifest belongs to a different registry")
        if signed_manifest.manifest.claimant_key_id != request.claimant_key_id:
            raise RegistryError(
                "manifest claimant key does not match request signer"
            )
        verification = verify_manifest(
            signed_manifest,
            request.claimant_public_jwk,
        )
        if not verification.valid:
            raise RegistryError("signed manifest verification failed")
        claims = self._load_claims()
        if signed_manifest.manifest.claim_id in claims:
            raise RegistryError("claim is already registered")
        self._append_event(
            RegistryEventType.CLAIM_REGISTERED,
            request.claimant_key_id,
            {
                "claim_id": str(signed_manifest.manifest.claim_id),
                "claimant_key_id": request.claimant_key_id,
                "signed_manifest_json": manifest_json,
            },
        )
        return self.get_claim(signed_manifest.manifest.claim_id)

    def rotate_key(self, request: KeyRotationRequest) -> ClaimantProfile:
        """Rotate a claimant key using old/new co-signed proof."""

        self._consume_verified_rotation_request(request)
        current_profile = self.get_profile(request.current_key_id)
        if current_profile.replacement_key_id is not None:
            raise RegistryError(
                "current claimant key has already been rotated"
            )
        profiles = self._load_profiles()
        if request.replacement_key_id in profiles:
            raise RegistryError("replacement claimant key already exists")
        self._append_event(
            RegistryEventType.KEY_ROTATED,
            request.current_key_id,
            {
                "current_key_id": request.current_key_id,
                "replacement_key_id": request.replacement_key_id,
                "replacement_public_jwk": request.replacement_public_jwk,
            },
        )
        return self.get_profile(request.current_key_id)

    def revoke_claim(self, request: MutationRequest) -> RegisteredClaim:
        """Revoke a previously registered claim."""

        self._consume_verified_request(
            request,
            ChallengePurpose.CLAIM_REVOCATION,
        )
        claim_id_value = request.payload.get("claim_id")
        reason = request.payload.get("reason")
        if not isinstance(claim_id_value, str):
            raise RegistryError("claim_id must be a string")
        if not isinstance(reason, str) or not reason:
            raise RegistryError("reason must be a nonempty string")
        claim = self.get_claim(UUID(claim_id_value))
        if claim.claimant_key_id != request.claimant_key_id:
            raise RegistryError("only the claimant may revoke this claim")
        if claim.revoked_at is not None:
            raise RegistryError("claim is already revoked")
        self._append_event(
            RegistryEventType.CLAIM_REVOKED,
            request.claimant_key_id,
            {
                "claim_id": claim_id_value,
                "reason": reason,
            },
        )
        return self.get_claim(UUID(claim_id_value))

    def verify_domain(
        self,
        request: MutationRequest,
    ) -> ClaimantProfile:
        """Record a verified domain for a claimant profile."""

        self._consume_verified_request(
            request,
            ChallengePurpose.DOMAIN_VERIFICATION,
        )
        domain = request.payload.get("domain")
        if not isinstance(domain, str) or "." not in domain:
            raise RegistryError("domain must be a plausible hostname")
        self.get_profile(request.claimant_key_id)
        self._append_event(
            RegistryEventType.DOMAIN_VERIFIED,
            request.claimant_key_id,
            {
                "key_id": request.claimant_key_id,
                "domain": domain.lower(),
            },
        )
        return self.get_profile(request.claimant_key_id)

    def open_dispute(self, request: MutationRequest) -> DisputeRecord:
        """Open a dispute on a registered claim."""

        self._consume_verified_request(
            request,
            ChallengePurpose.DISPUTE_OPEN,
        )
        claim_id_value = request.payload.get("claim_id")
        reason = request.payload.get("reason")
        if not isinstance(claim_id_value, str):
            raise RegistryError("claim_id must be a string")
        if not isinstance(reason, str) or not reason:
            raise RegistryError("reason must be a nonempty string")
        misuse_url = _optional_http_url(
            request.payload.get("misuse_url"),
            "misuse_url",
        )
        self.get_claim(UUID(claim_id_value))
        dispute_id = uuid4()
        self._append_event(
            RegistryEventType.DISPUTE_OPENED,
            request.claimant_key_id,
            {
                "dispute_id": str(dispute_id),
                "claim_id": claim_id_value,
                "opened_by_key_id": request.claimant_key_id,
                "reason": reason,
                "misuse_url": misuse_url,
            },
        )
        return self.get_dispute(dispute_id)

    def resolve_dispute(self, request: MutationRequest) -> DisputeRecord:
        """Resolve a dispute as an authorized registry admin."""

        self._consume_verified_request(
            request,
            ChallengePurpose.DISPUTE_RESOLUTION,
        )
        if request.claimant_key_id not in self._admin_key_ids:
            raise RegistryError("only a registry admin may resolve disputes")
        dispute_id_value = request.payload.get("dispute_id")
        status_value = request.payload.get("status")
        resolution_note = request.payload.get("resolution_note")
        if not isinstance(dispute_id_value, str):
            raise RegistryError("dispute_id must be a string")
        if not isinstance(status_value, str):
            raise RegistryError("status must be a string")
        if not isinstance(resolution_note, str) or not resolution_note:
            raise RegistryError("resolution_note must be a nonempty string")
        dispute = self.get_dispute(UUID(dispute_id_value))
        if dispute.status is not DisputeStatus.OPEN:
            raise RegistryError("dispute is already resolved")
        status = DisputeStatus(status_value)
        if status is DisputeStatus.OPEN:
            raise RegistryError("resolved disputes cannot remain open")
        self._append_event(
            RegistryEventType.DISPUTE_RESOLVED,
            request.claimant_key_id,
            {
                "dispute_id": dispute_id_value,
                "status": status.value,
                "resolution_note": resolution_note,
                "resolved_by_key_id": request.claimant_key_id,
            },
        )
        return self.get_dispute(UUID(dispute_id_value))

    def evidence_profile(self, key_id: str) -> EvidenceProfile:
        """Summarize public evidence attached to one claimant profile."""

        snapshot = self._current_snapshot()

        try:
            profile = snapshot.profiles[key_id]
        except KeyError as error:
            raise RegistryError("claimant profile does not exist") from error

        relevant_claims = [
            claim
            for claim in snapshot.claims.values()
            if claim.claimant_key_id == key_id
        ]

        claimant_disputes = [
            dispute
            for dispute in snapshot.disputes.values()
            if snapshot.claims[dispute.claim_id].claimant_key_id == key_id
        ]

        now = _utc_now()

        return EvidenceProfile(
            key_age_days=max(0, (now - profile.created_at).days),
            active_claim_count=sum(
                claim.revoked_at is None for claim in relevant_claims
            ),
            revoked_claim_count=sum(
                claim.revoked_at is not None for claim in relevant_claims
            ),
            verified_domains=profile.verified_domains,
            certificate_count=snapshot.certificate_counts.get(key_id, 0),
            rotation_count=snapshot.rotation_counts.get(key_id, 0),
            open_disputes=sum(
                dispute.status is DisputeStatus.OPEN
                for dispute in claimant_disputes
            ),
            upheld_disputes=sum(
                dispute.status is DisputeStatus.UPHELD
                for dispute in claimant_disputes
            ),
            rejected_disputes=sum(
                dispute.status is DisputeStatus.REJECTED
                for dispute in claimant_disputes
            ),
            hosted_account=profile.hosted_account,
        )

    def verify_claim(
        self,
        claim_id: UUID,
        *,
        content: bytes | None = None,
        nonce: bytes | None = None,
    ) -> ClaimVerificationReport:
        """Verify one claim using registry evidence, not C2PA alone."""

        claim = self.get_claim(claim_id)
        profile = self.get_profile(claim.claimant_key_id)
        evidence_profile = self.evidence_profile(claim.claimant_key_id)
        claim_disputes = [
            dispute
            for dispute in self._load_disputes().values()
            if dispute.claim_id == claim.claim_id
        ]
        open_disputes = sum(
            dispute.status is DisputeStatus.OPEN for dispute in claim_disputes
        )
        upheld_disputes = sum(
            dispute.status is DisputeStatus.UPHELD
            for dispute in claim_disputes
        )
        manifest_report = verify_manifest(
            claim.signed_manifest,
            profile.public_jwk,
            content,
            nonce,
        )
        disputed = open_disputes > 0 or upheld_disputes > 0
        if claim.revoked_at is not None:
            label = VerificationLabel.REVOKED
        elif disputed:
            label = VerificationLabel.DISPUTED
        elif manifest_report.valid:
            label = VerificationLabel.VERIFIED_CLAIM
        elif manifest_report.signature_valid and manifest_report.key_id_valid:
            label = VerificationLabel.PARTIAL_MATCH
        else:
            label = VerificationLabel.UNTRUSTED_CLAIM
        return ClaimVerificationReport(
            claim_id=claim.claim_id,
            label=label,
            trust_tier=evidence_profile.trust_tier,
            trust_labels=evidence_profile.trust_labels,
            registry_included=True,
            manifest_signature_valid=manifest_report.signature_valid
            and manifest_report.key_id_valid,
            content_binding_valid=manifest_report.content_binding_valid,
            revoked=claim.revoked_at is not None,
            disputed=disputed,
            open_disputes=open_disputes,
            upheld_disputes=upheld_disputes,
            claim_meanings=tuple(
                meaning.value
                for meaning in claim.signed_manifest.manifest.claim_meanings
            ),
            evidence={
                "claimant_key_id": claim.claimant_key_id,
                "registered_at": _isoformat(claim.registered_at),
                "revoked_at": None
                if claim.revoked_at is None
                else _isoformat(claim.revoked_at),
                "revocation_reason": claim.revocation_reason,
                "profile_display_name": profile.display_name,
                "verified_domains": list(profile.verified_domains),
                "hosted_account": profile.hosted_account,
                "active_claim_count": evidence_profile.active_claim_count,
                "revoked_claim_count": evidence_profile.revoked_claim_count,
                "certificate_count": evidence_profile.certificate_count,
                "rotation_count": evidence_profile.rotation_count,
                "watermarks": list(claim.signed_manifest.manifest.watermarks),
                "carriers": list(claim.signed_manifest.manifest.carriers),
                "manifest_errors": list(manifest_report.errors),
            },
            errors=manifest_report.errors,
        )
