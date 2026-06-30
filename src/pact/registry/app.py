"""Registry trust, replay-challenge, certificate, and state-management logic."""

import hashlib
import ipaddress
import random
import socket
import struct
import threading
from collections.abc import Callable, Mapping
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
    base64url_decode,
    base64url_encode,
    jwk_thumbprint,
    public_key_from_jwk,
    sign_es256,
    verify_es256,
)
from pact.identity import ClaimantIdentity, normalize_registry_url
from pact.manifest import SignedManifest, verify_manifest
from pact.oprf import (
    DEVICE_BINDING_TOKEN_PREFIX,
    device_oprf_server_scalar,
    evaluate_device_oprf,
)
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


def _observed_domain(value: str | None) -> str | None:
    if value is None:
        return None
    hostname = urlsplit(value).hostname
    return None if hostname is None else hostname.rstrip(".").lower()


def _highest_report_label(
    reports: tuple["AvoidanceReport", ...] | list["AvoidanceReport"],
) -> "AvoidanceReportLabel | None":
    rank = {
        AvoidanceReportLabel.INSUFFICIENT_EVIDENCE: 0,
        AvoidanceReportLabel.FALSE_POSITIVE: 0,
        AvoidanceReportLabel.POSSIBLE_AVOIDANCE: 1,
        AvoidanceReportLabel.EMBEDDED_REFERENCE_REMOVED: 2,
        AvoidanceReportLabel.FINGERPRINT_WEAKENED_OR_REMOVED: 2,
        AvoidanceReportLabel.LIKELY_DERIVED_STRIPPED: 3,
        AvoidanceReportLabel.EXACT_CONTENT_REPOST: 4,
    }
    labels = [report.report_label for report in reports]
    if not labels:
        return None
    return max(labels, key=lambda label: rank[label])


def _validated_device_binding_token(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RegistryError("device_fingerprint must be a nonempty string")
    if not value.startswith(DEVICE_BINDING_TOKEN_PREFIX):
        raise RegistryError(
            "device_fingerprint must be a pact-device-binding-v2 token"
        )
    try:
        base64url_decode(
            value.removeprefix(DEVICE_BINDING_TOKEN_PREFIX),
            length=32,
        )
    except ValueError as error:
        raise RegistryError(
            "device_fingerprint token digest must be 32 bytes of base64url"
        ) from error
    return value


class ChallengePurpose(StrEnum):
    """Replay-challenge purpose labels."""

    PROFILE_REGISTRATION = "profile_registration"
    PROFILE_UPDATE = "profile_update"
    CERTIFICATE_ISSUANCE = "certificate_issuance"
    CLAIM_REGISTRATION = "claim_registration"
    KEY_ROTATION = "key_rotation"
    CLAIM_REVOCATION = "claim_revocation"
    DOMAIN_VERIFICATION = "domain_verification"
    ACCOUNT_AUTHORIZATION = "account_authorization"
    HOSTED_ACCOUNT_AUTHORIZATION = "hosted_account_authorization"
    THIRD_PARTY_ATTESTATION = "third_party_attestation"
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

    CONTENT_CLAIM_VERIFIED = "content_claim_verified"
    CLAIM_VERIFIED_CONTENT_UNCHECKED = "claim_verified_content_unchecked"
    CLAIM_VERIFIED_CONTENT_PRIVATE = "claim_verified_content_private"
    CONTENT_MISMATCH = "content_mismatch"
    CLAIM_REFERENCE_FOUND = "claim_reference_found"
    UNREGISTERED_SIGNED_CLAIM = "unregistered_signed_claim"
    INVALID_CLAIM_SIGNATURE = "invalid_claim_signature"
    DISPUTED = "disputed"
    REVOKED = "revoked"
    INCONCLUSIVE = "inconclusive"


class AvoidanceReportLabel(StrEnum):
    """Human/community evidence labels for possible provenance avoidance."""

    POSSIBLE_AVOIDANCE = "possible_avoidance"
    LIKELY_DERIVED_STRIPPED = "likely_derived_stripped"
    EXACT_CONTENT_REPOST = "exact_content_repost"
    EMBEDDED_REFERENCE_REMOVED = "embedded_reference_removed"
    FINGERPRINT_WEAKENED_OR_REMOVED = "fingerprint_weakened_or_removed"
    FALSE_POSITIVE = "false_positive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class AvoidanceReportStatus(StrEnum):
    """Lifecycle state for provenance avoidance reports."""

    SUBMITTED = "submitted"
    AUTO_TRIAGED = "auto_triaged"
    OWNER_REVIEW_REQUESTED = "owner_review_requested"
    OWNER_CONFIRMED = "owner_confirmed"
    COMMUNITY_CORROBORATED = "community_corroborated"
    REJECTED = "rejected"
    ABUSE_FLAGGED = "abuse_flagged"


class SpreadStatus(StrEnum):
    """Public aggregate spread signal for one public-verification claim."""

    NO_REPORTS = "no_reports"
    REPORTS_RECEIVED = "reports_received"
    MULTIPLE_SIGHTINGS = "multiple_sightings"
    OWNER_CONFIRMED_SPREAD = "owner_confirmed_spread"
    HIGH_CONFIDENCE_SPREAD = "high_confidence_spread"


class OwnerReportAction(StrEnum):
    """Owner review actions for reported possible avoidance."""

    CONFIRM_DERIVED_UNAUTHORIZED = "confirm_derived_unauthorized"
    MARK_AUTHORIZED_REUSE = "mark_authorized_reuse"
    REJECT_NOT_RELATED = "reject_not_related"
    ESCALATE_TO_DISPUTE = "escalate_to_dispute"


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


def _normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        raise RegistryError("domain must be a hostname string")
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain:
        raise RegistryError("domain must be a plausible hostname")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise RegistryError("domain must be a hostname, not an IP address")
    labels = domain.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise RegistryError("domain must be a plausible hostname")
        try:
            label.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise RegistryError(
                "domain must be a plausible hostname"
            ) from error
    return domain


def domain_verification_txt_name(domain: str) -> str:
    """Return the DNS TXT owner name used for domain verification."""

    return f"_pact-challenge.{_normalize_domain(domain)}"


def domain_verification_txt_value(
    registry_url: str,
    claimant_key_id: str,
    domain: str,
) -> str:
    """Return the TXT value that proves domain control for one claimant."""

    normalized_registry_url = normalize_registry_url(registry_url)
    normalized_domain = _normalize_domain(domain)
    digest = hashlib.sha256(
        canonical_json(
            cast(
                JsonValue,
                {
                    "domain": normalized_domain,
                    "claimant_key_id": claimant_key_id,
                    "registry_url": normalized_registry_url,
                },
            )
        )
    ).digest()
    return f"pact-domain-verification={base64url_encode(digest)}"


def _system_resolvers() -> tuple[str, ...]:
    resolvers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    resolvers.append(parts[1])
    except OSError:
        pass
    return tuple(resolvers or ["1.1.1.1", "8.8.8.8"])


def _dns_name_wire(name: str) -> bytes:
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna")
        if len(encoded) > 63:
            raise RegistryError("domain label is too long")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def _skip_dns_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise RegistryError("DNS response was truncated")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def resolve_dns_txt(name: str, *, timeout: float = 3.0) -> tuple[str, ...]:
    """Resolve TXT records using the system recursive DNS resolvers."""

    query_id = random.randrange(0, 65536)
    query = (
        struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        + _dns_name_wire(name)
        + struct.pack("!HH", 16, 1)
    )
    errors: list[Exception] = []
    for resolver in _system_resolvers():
        family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (resolver, 53))
                packet, _address = sock.recvfrom(4096)
        except OSError as error:
            errors.append(error)
            continue
        if len(packet) < 12:
            continue
        (
            response_id,
            flags,
            question_count,
            answer_count,
            _authority_count,
            _additional_count,
        ) = struct.unpack("!HHHHHH", packet[:12])
        if response_id != query_id or flags & 0x000F:
            continue
        offset = 12
        for _index in range(question_count):
            offset = _skip_dns_name(packet, offset) + 4
        records: list[str] = []
        for _index in range(answer_count):
            offset = _skip_dns_name(packet, offset)
            if offset + 10 > len(packet):
                raise RegistryError("DNS response was truncated")
            record_type, _class, _ttl, data_length = struct.unpack(
                "!HHIH", packet[offset : offset + 10]
            )
            offset += 10
            data = packet[offset : offset + data_length]
            offset += data_length
            if record_type != 16:
                continue
            parts: list[str] = []
            data_offset = 0
            while data_offset < len(data):
                text_length = data[data_offset]
                data_offset += 1
                parts.append(
                    data[data_offset : data_offset + text_length].decode(
                        "utf-8", errors="replace"
                    )
                )
                data_offset += text_length
            records.append("".join(parts))
        return tuple(records)
    if errors:
        raise RegistryError(f"DNS TXT lookup failed for {name}: {errors[-1]}")
    return ()


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
        """Serialize the challenge issued to a claimant."""

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
        """Canonical bytes covered by the client signature."""

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
    device_fingerprint: str
    display_name: str | None = None
    replacement_key_id: str | None = None
    verified_domains: tuple[str, ...] = ()
    hosted_account: bool = False
    third_party_attested: bool = False
    documented_rights: bool = False


HostedAccountVerifier = Callable[[str, Mapping[str, object]], bool]


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

    def to_public_dict(
        self,
        *,
        claim_dispute_count: int,
        reporter_credibility: dict[str, object],
    ) -> dict[str, object]:
        return {
            "dispute_id": str(self.dispute_id),
            "claim_id": str(self.claim_id),
            "opened_by_key_id": self.opened_by_key_id,
            "opened_at": _isoformat(self.opened_at),
            "reason": self.reason,
            "misuse_url": self.misuse_url,
            "status": self.status.value,
            "resolved_at": None
            if self.resolved_at is None
            else _isoformat(self.resolved_at),
            "resolution_note": self.resolution_note,
            "claim_dispute_count": claim_dispute_count,
            "reporter_credibility": reporter_credibility,
        }


@dataclass(frozen=True, slots=True)
class AvoidanceReport:
    """Evidence intake for possible provenance or fingerprint avoidance."""

    report_id: UUID
    claim_id: UUID
    reporter_key_id: str | None
    reporter_type: str
    observed_url: str | None
    observed_domain: str | None
    observed_at: datetime
    submitted_at: datetime
    evidence_type: str
    evidence_digest: str
    evidence_manifest_digest: str | None
    report_label: AvoidanceReportLabel
    status: AvoidanceReportStatus
    reverse_lookup_score: float | None
    reverse_lookup_evidence: tuple[dict[str, object], ...]
    description: str | None
    public_note: str | None
    owner_visible: bool = True
    public_visible: bool = False

    def to_public_dict(
        self,
        *,
        reporter_credibility: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "report_id": str(self.report_id),
            "claim_id": str(self.claim_id),
            "reporter_key_id": self.reporter_key_id,
            "reporter_type": self.reporter_type,
            "observed_domain": self.observed_domain,
            "observed_at": _isoformat(self.observed_at),
            "submitted_at": _isoformat(self.submitted_at),
            "evidence_type": self.evidence_type,
            "report_label": self.report_label.value,
            "status": self.status.value,
            "reverse_lookup_score": self.reverse_lookup_score,
            "description": self.description,
            "public_note": self.public_note,
            "reporter_credibility": reporter_credibility or {},
        }


@dataclass(frozen=True, slots=True)
class ReportEvidence:
    """Stored evidence object metadata for an avoidance report."""

    evidence_id: UUID
    report_id: UUID
    kind: str
    digest: str
    mime_type: str | None
    storage_uri: str | None
    redacted_storage_uri: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class SpreadSummary:
    """Public aggregate report state for one claim."""

    claim_id: UUID
    status: SpreadStatus
    report_count: int
    public_report_count: int
    domain_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    owner_confirmed: bool
    highest_confidence: AvoidanceReportLabel | None

    def to_dict(self) -> dict[str, object]:
        """Serialize public spread-report state."""

        return {
            "claim_id": str(self.claim_id),
            "status": self.status.value,
            "report_count": self.report_count,
            "public_report_count": self.public_report_count,
            "domain_count": self.domain_count,
            "first_seen": None
            if self.first_seen is None
            else _isoformat(self.first_seen),
            "last_seen": None
            if self.last_seen is None
            else _isoformat(self.last_seen),
            "owner_confirmed": self.owner_confirmed,
            "highest_confidence": None
            if self.highest_confidence is None
            else self.highest_confidence.value,
        }


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    """Materialized public registry state derived from the event log."""

    last_sequence: int
    profiles: dict[str, ClaimantProfile]
    claims: dict[UUID, RegisteredClaim]
    disputes: dict[UUID, DisputeRecord]
    avoidance_reports: dict[UUID, AvoidanceReport]
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
    content_binding_checked: bool
    public_nonce_available: bool
    revoked: bool
    disputed: bool
    open_disputes: int
    upheld_disputes: int
    claim_meanings: tuple[str, ...]
    evidence: dict[str, object]
    errors: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        """Whether registry evidence verifies this exact content claim."""

        return self.label is VerificationLabel.CONTENT_CLAIM_VERIFIED

    @property
    def claim_verified(self) -> bool:
        """Whether registry evidence verifies the signed claim itself."""

        return self.label in {
            VerificationLabel.CONTENT_CLAIM_VERIFIED,
            VerificationLabel.CLAIM_VERIFIED_CONTENT_UNCHECKED,
            VerificationLabel.CLAIM_VERIFIED_CONTENT_PRIVATE,
        }

    @property
    def registry_claim_valid(self) -> bool:
        return (
            self.registry_included
            and self.manifest_signature_valid
            and not self.revoked
            and not self.errors
        )

    @property
    def policy_valid(self) -> bool:
        return not self.errors

    @property
    def overall_verdict(self) -> str:
        if self.revoked:
            return "revoked"
        if self.disputed:
            return "disputed"
        if not self.manifest_signature_valid:
            return "signature_invalid"
        if self.content_binding_valid is True:
            return "content_verified"
        if self.content_binding_valid is False:
            return "content_mismatch"
        if not self.public_nonce_available:
            return "private_content_unchecked"
        return "signature_only"

    def to_dict(self) -> dict[str, object]:
        """Serialize the registry verification report."""

        return {
            "claim_id": str(self.claim_id),
            "label": self.label.value,
            "trust_tier": self.trust_tier.value,
            "trust_labels": [label.value for label in self.trust_labels],
            "registry_included": self.registry_included,
            "registry_claim_valid": self.registry_claim_valid,
            "manifest_signature_valid": self.manifest_signature_valid,
            "content_binding_valid": self.content_binding_valid,
            "content_binding_checked": self.content_binding_checked,
            "public_nonce_available": self.public_nonce_available,
            "policy_valid": self.policy_valid,
            "overall_verdict": self.overall_verdict,
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
        dns_txt_resolver: Callable[[str], tuple[str, ...]] = resolve_dns_txt,
        hosted_account_verifier: HostedAccountVerifier | None = None,
        oprf_server_secret: bytes | None = None,
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
        self._dns_txt_resolver = dns_txt_resolver
        self._hosted_account_verifier = hosted_account_verifier
        self._oprf_server_secret = (
            oprf_server_secret
            if oprf_server_secret is not None
            else hashlib.sha256(
                b"PACT development OPRF fallback v1\0"
                + certificate_authority.intermediate_private_key_pem
            ).digest()
        )

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

    def evaluate_device_binding_oprf(
        self,
        blinded_point: Mapping[str, object],
    ) -> dict[str, str]:
        """Evaluate a blinded device-binding OPRF point."""

        server_scalar = device_oprf_server_scalar(
            registry_url=self.registry_url,
            registry_root_fingerprint=self.certificate_authority.root_fingerprint,
            server_secret=self._oprf_server_secret,
        )
        return evaluate_device_oprf(
            blinded_point,
            server_scalar=server_scalar,
        )

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
        avoidance_reports: dict[UUID, AvoidanceReport] = {}
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
                    third_party_attested=bool(
                        data.get("third_party_attested", False)
                    ),
                    documented_rights=bool(
                        data.get("documented_rights", False)
                    ),
                    device_fingerprint=_validated_device_binding_token(
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
                    third_party_attested=current.third_party_attested,
                    documented_rights=current.documented_rights,
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
                    third_party_attested=current.third_party_attested,
                    documented_rights=current.documented_rights,
                    device_fingerprint=current.device_fingerprint,
                )

            elif event.event_type is RegistryEventType.ACCOUNT_AUTHORIZED:
                key_id = cast(str, data["key_id"])
                current = profiles[key_id]

                profiles[key_id] = ClaimantProfile(
                    key_id=current.key_id,
                    public_jwk=current.public_jwk,
                    created_at=current.created_at,
                    display_name=current.display_name,
                    replacement_key_id=current.replacement_key_id,
                    verified_domains=current.verified_domains,
                    hosted_account=current.hosted_account
                    or bool(data.get("hosted_account", False)),
                    third_party_attested=current.third_party_attested
                    or bool(data.get("third_party_attested", False)),
                    documented_rights=current.documented_rights
                    or bool(data.get("documented_rights", False)),
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
                    third_party_attested=current.third_party_attested,
                    documented_rights=current.documented_rights,
                    device_fingerprint=current.device_fingerprint,
                )

                profiles[replacement_key_id] = ClaimantProfile(
                    key_id=replacement_key_id,
                    public_jwk=cast(dict[str, str], replacement_public_jwk),
                    created_at=self._event_time(event),
                    display_name=current.display_name,
                    verified_domains=current.verified_domains,
                    hosted_account=current.hosted_account,
                    third_party_attested=current.third_party_attested,
                    documented_rights=current.documented_rights,
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

            elif (
                event.event_type
                is RegistryEventType.AVOIDANCE_REPORT_SUBMITTED
            ):
                report_id = UUID(cast(str, data["report_id"]))
                observed_at = _parse_datetime(
                    data.get("observed_at"),
                    "observed_at",
                )
                score_value = data.get("reverse_lookup_score")
                if score_value is not None and not isinstance(
                    score_value, int | float
                ):
                    raise RegistryStoreError(
                        "reverse_lookup_score must be numeric or null"
                    )
                evidence_value = data.get("reverse_lookup_evidence", [])
                if not isinstance(evidence_value, list):
                    raise RegistryStoreError(
                        "reverse_lookup_evidence must be a list"
                    )
                avoidance_reports[report_id] = AvoidanceReport(
                    report_id=report_id,
                    claim_id=UUID(cast(str, data["claim_id"])),
                    reporter_key_id=cast(
                        str | None,
                        data.get("reporter_key_id"),
                    ),
                    reporter_type=cast(str, data["reporter_type"]),
                    observed_url=cast(str | None, data.get("observed_url")),
                    observed_domain=cast(
                        str | None,
                        data.get("observed_domain"),
                    ),
                    observed_at=observed_at,
                    submitted_at=self._event_time(event),
                    evidence_type=cast(str, data["evidence_type"]),
                    evidence_digest=cast(str, data["evidence_digest"]),
                    evidence_manifest_digest=cast(
                        str | None,
                        data.get("evidence_manifest_digest"),
                    ),
                    report_label=AvoidanceReportLabel(
                        cast(str, data["report_label"])
                    ),
                    status=AvoidanceReportStatus(cast(str, data["status"])),
                    reverse_lookup_score=None
                    if score_value is None
                    else float(score_value),
                    reverse_lookup_evidence=tuple(
                        cast(dict[str, object], item)
                        for item in evidence_value
                        if isinstance(item, dict)
                    ),
                    description=cast(str | None, data.get("description")),
                    public_note=cast(str | None, data.get("public_note")),
                    owner_visible=bool(data.get("owner_visible", True)),
                    public_visible=bool(data.get("public_visible", False)),
                )

            elif event.event_type in {
                RegistryEventType.AVOIDANCE_REPORT_TRIAGED,
                RegistryEventType.AVOIDANCE_REPORT_OWNER_CONFIRMED,
                RegistryEventType.AVOIDANCE_REPORT_REJECTED,
                RegistryEventType.AVOIDANCE_REPORT_PUBLICLY_LISTED,
            }:
                report_id = UUID(cast(str, data["report_id"]))
                current = avoidance_reports[report_id]
                status_value = data.get("status", current.status.value)
                label_value = data.get(
                    "report_label", current.report_label.value
                )
                avoidance_reports[report_id] = AvoidanceReport(
                    report_id=current.report_id,
                    claim_id=current.claim_id,
                    reporter_key_id=current.reporter_key_id,
                    reporter_type=current.reporter_type,
                    observed_url=current.observed_url,
                    observed_domain=current.observed_domain,
                    observed_at=current.observed_at,
                    submitted_at=current.submitted_at,
                    evidence_type=current.evidence_type,
                    evidence_digest=current.evidence_digest,
                    evidence_manifest_digest=current.evidence_manifest_digest,
                    report_label=AvoidanceReportLabel(cast(str, label_value)),
                    status=AvoidanceReportStatus(cast(str, status_value)),
                    reverse_lookup_score=current.reverse_lookup_score,
                    reverse_lookup_evidence=current.reverse_lookup_evidence,
                    description=current.description,
                    public_note=cast(
                        str | None,
                        data.get("public_note", current.public_note),
                    ),
                    owner_visible=bool(
                        data.get("owner_visible", current.owner_visible)
                    ),
                    public_visible=bool(
                        data.get("public_visible", current.public_visible)
                    ),
                )

        return RegistrySnapshot(
            last_sequence=last_sequence,
            profiles=profiles,
            claims=claims,
            disputes=disputes,
            avoidance_reports=avoidance_reports,
            certificate_counts=certificate_counts,
            rotation_counts=rotation_counts,
        )

    def _load_profiles(self) -> dict[str, ClaimantProfile]:
        return self._current_snapshot().profiles

    def _load_claims(self) -> dict[UUID, RegisteredClaim]:
        return self._current_snapshot().claims

    def _load_disputes(self) -> dict[UUID, DisputeRecord]:
        return self._current_snapshot().disputes

    def _load_avoidance_reports(self) -> dict[UUID, AvoidanceReport]:
        return self._current_snapshot().avoidance_reports

    def claim_allows_public_reporting(
        self,
        claim: RegisteredClaim,
    ) -> bool:
        """Check whether a claim opted into public spread reporting."""

        return (
            claim.signed_manifest.manifest.content_binding.public_nonce
            is not None
            and claim.revoked_at is None
        )

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

    def dispute_reporter_credibility(self, key_id: str) -> dict[str, object]:
        disputes = [
            dispute
            for dispute in self._load_disputes().values()
            if dispute.opened_by_key_id == key_id
        ]
        return {
            "reporter_key_id": key_id,
            "submitted_dispute_count": len(disputes),
            "open_dispute_count": sum(
                dispute.status is DisputeStatus.OPEN for dispute in disputes
            ),
            "upheld_dispute_count": sum(
                dispute.status is DisputeStatus.UPHELD for dispute in disputes
            ),
            "rejected_dispute_count": sum(
                dispute.status is DisputeStatus.REJECTED
                for dispute in disputes
            ),
        }

    def public_dispute_dict(self, dispute: DisputeRecord) -> dict[str, object]:
        claim_count = sum(
            item.claim_id == dispute.claim_id
            for item in self._load_disputes().values()
        )
        return dispute.to_public_dict(
            claim_dispute_count=claim_count,
            reporter_credibility=self.dispute_reporter_credibility(
                dispute.opened_by_key_id
            ),
        )

    def get_avoidance_report(self, report_id: UUID) -> AvoidanceReport:
        """Return one possible provenance avoidance report."""

        reports = self._load_avoidance_reports()
        try:
            return reports[report_id]
        except KeyError as error:
            raise RegistryError("avoidance report does not exist") from error

    def public_avoidance_report_dict(
        self,
        report: AvoidanceReport,
    ) -> dict[str, object]:
        credibility: dict[str, object] = {}
        if report.reporter_key_id is not None:
            credibility = self.dispute_reporter_credibility(
                report.reporter_key_id
            )
        return report.to_public_dict(reporter_credibility=credibility)

    def list_avoidance_reports(
        self,
        *,
        claim_id: UUID | None = None,
        public_only: bool = True,
    ) -> tuple[AvoidanceReport, ...]:
        """Return avoidance reports, optionally filtered by claim."""

        reports = sorted(
            self._load_avoidance_reports().values(),
            key=lambda report: report.submitted_at,
            reverse=True,
        )
        if claim_id is not None:
            reports = [
                report for report in reports if report.claim_id == claim_id
            ]
        if public_only:
            reports = [report for report in reports if report.public_visible]
        return tuple(reports)

    def spread_summary(self, claim_id: UUID) -> SpreadSummary:
        """Return public aggregate spread-report state for a claim."""

        self.get_claim(claim_id)
        reports = self.list_avoidance_reports(claim_id=claim_id)
        domains = {
            report.observed_domain
            for report in reports
            if report.observed_domain is not None
        }
        owner_confirmed = any(
            report.status is AvoidanceReportStatus.OWNER_CONFIRMED
            for report in reports
        )
        public_count = sum(1 for report in reports if report.public_visible)
        highest = _highest_report_label(reports)
        if not reports:
            status = SpreadStatus.NO_REPORTS
        elif owner_confirmed:
            status = SpreadStatus.OWNER_CONFIRMED_SPREAD
        elif highest in {
            AvoidanceReportLabel.LIKELY_DERIVED_STRIPPED,
            AvoidanceReportLabel.EXACT_CONTENT_REPOST,
        }:
            status = SpreadStatus.HIGH_CONFIDENCE_SPREAD
        elif len(reports) > 1 or len(domains) > 1:
            status = SpreadStatus.MULTIPLE_SIGHTINGS
        else:
            status = SpreadStatus.REPORTS_RECEIVED
        seen_dates = [report.observed_at for report in reports]
        return SpreadSummary(
            claim_id=claim_id,
            status=status,
            report_count=len(reports),
            public_report_count=public_count,
            domain_count=len(domains),
            first_seen=min(seen_dates) if seen_dates else None,
            last_seen=max(seen_dates) if seen_dates else None,
            owner_confirmed=owner_confirmed,
            highest_confidence=highest,
        )

    def submit_avoidance_report(
        self,
        *,
        claim_id: UUID,
        evidence_type: str,
        evidence_digest: str,
        report_label: AvoidanceReportLabel = AvoidanceReportLabel.POSSIBLE_AVOIDANCE,
        reporter_key_id: str | None = None,
        reporter_type: str = "anonymous",
        observed_url: str | None = None,
        observed_at: datetime | None = None,
        evidence_manifest_digest: str | None = None,
        reverse_lookup_score: float | None = None,
        reverse_lookup_evidence: tuple[dict[str, object], ...] = (),
        description: str | None = None,
        public_note: str | None = None,
    ) -> AvoidanceReport:
        """Record possible provenance/fingerprint avoidance for a public claim."""

        claim = self.get_claim(claim_id)
        if not self.claim_allows_public_reporting(claim):
            raise RegistryError(
                "avoidance reports are only available for claims with public "
                "content verification enabled"
            )
        evidence_type = evidence_type.strip()
        evidence_digest = evidence_digest.strip()
        if not evidence_type:
            raise RegistryError("evidence_type must be a nonempty string")
        if not evidence_digest:
            raise RegistryError("evidence_digest must be a nonempty string")
        if reporter_key_id is not None and not reporter_key_id.strip():
            raise RegistryError("reporter_key_id must be nonempty when set")
        reporter_type = reporter_type.strip() or "anonymous"
        observed_url = _optional_http_url(observed_url, "observed_url")
        description = None if description is None else description.strip()
        if description == "":
            description = None
        public_note = None if public_note is None else public_note.strip()
        if public_note == "":
            public_note = None
        if reverse_lookup_score is not None and not (
            0 <= reverse_lookup_score <= 1
        ):
            raise RegistryError("reverse_lookup_score must be between 0 and 1")
        report_id = uuid4()
        self._append_event(
            RegistryEventType.AVOIDANCE_REPORT_SUBMITTED,
            reporter_key_id,
            {
                "report_id": str(report_id),
                "claim_id": str(claim_id),
                "reporter_key_id": reporter_key_id,
                "reporter_type": reporter_type,
                "observed_url": observed_url,
                "observed_domain": _observed_domain(observed_url),
                "observed_at": _isoformat(observed_at or _utc_now()),
                "evidence_type": evidence_type,
                "evidence_digest": evidence_digest,
                "evidence_manifest_digest": evidence_manifest_digest,
                "report_label": report_label.value,
                "status": AvoidanceReportStatus.SUBMITTED.value,
                "reverse_lookup_score": reverse_lookup_score,
                "reverse_lookup_evidence": list(reverse_lookup_evidence),
                "description": description,
                "public_note": public_note,
                "owner_visible": True,
                "public_visible": False,
            },
        )
        return self.get_avoidance_report(report_id)

    def register_profile(self, request: MutationRequest) -> ClaimantProfile:
        """Register a new pseudonymous claimant profile."""

        self._consume_verified_request(
            request,
            ChallengePurpose.PROFILE_REGISTRATION,
        )
        profiles = self._load_profiles()
        if request.claimant_key_id in profiles:
            raise RegistryError("claimant profile already exists")
        device_fingerprint = _validated_device_binding_token(
            request.payload.get("device_fingerprint")
        )
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
        if hosted_account:
            raise RegistryError(
                "hosted_account requires registry administrator authorization"
            )
        self._append_event(
            RegistryEventType.PROFILE_REGISTERED,
            request.claimant_key_id,
            {
                "key_id": request.claimant_key_id,
                "public_jwk": request.claimant_public_jwk,
                "display_name": display_name,
                "hosted_account": False,
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
        """Record a verified domain after live DNS TXT proof."""

        self._consume_verified_request(
            request,
            ChallengePurpose.DOMAIN_VERIFICATION,
        )
        domain = _normalize_domain(request.payload.get("domain"))
        self.get_profile(request.claimant_key_id)
        expected = domain_verification_txt_value(
            self.registry_url,
            request.claimant_key_id,
            domain,
        )
        supplied = request.payload.get("txt_value")
        if supplied is not None and supplied != expected:
            raise RegistryError("domain verification TXT value is invalid")
        txt_name = domain_verification_txt_name(domain)
        records = self._dns_txt_resolver(txt_name)
        if expected not in records:
            raise RegistryError(
                f"DNS TXT record {txt_name} must contain {expected}"
            )
        self._append_event(
            RegistryEventType.DOMAIN_VERIFIED,
            request.claimant_key_id,
            {
                "key_id": request.claimant_key_id,
                "domain": domain,
                "txt_name": txt_name,
                "txt_value": expected,
            },
        )
        return self.get_profile(request.claimant_key_id)

    def authorize_hosted_account(
        self,
        request: MutationRequest,
    ) -> ClaimantProfile:
        """Record registry-admin hosted-account authorization evidence."""

        self._consume_verified_request(
            request,
            ChallengePurpose.ACCOUNT_AUTHORIZATION,
        )
        if request.claimant_key_id not in self._admin_key_ids:
            raise RegistryError(
                "only a registry admin may authorize hosted account trust"
            )
        target_key_id = request.payload.get("target_key_id")
        if not isinstance(target_key_id, str) or not target_key_id:
            raise RegistryError("target_key_id must be a nonempty string")
        self.get_profile(target_key_id)
        provider = request.payload.get("provider")
        if provider is not None and not isinstance(provider, str):
            raise RegistryError("provider must be a string")
        note = request.payload.get("note")
        if note is not None and not isinstance(note, str):
            raise RegistryError("note must be a string")
        self._append_event(
            RegistryEventType.ACCOUNT_AUTHORIZED,
            request.claimant_key_id,
            {
                "key_id": target_key_id,
                "authorized_by_key_id": request.claimant_key_id,
                "hosted_account": True,
                "third_party_attested": False,
                "documented_rights": False,
                "provider": provider or self.registry_url,
                "method": "admin_approval",
                "note": note,
            },
        )
        return self.get_profile(target_key_id)

    def complete_hosted_account_login(
        self,
        request: MutationRequest,
    ) -> ClaimantProfile:
        """Record hosted-account evidence from a registry-host login flow."""

        self._consume_verified_request(
            request,
            ChallengePurpose.HOSTED_ACCOUNT_AUTHORIZATION,
        )
        self.get_profile(request.claimant_key_id)
        if self._hosted_account_verifier is None:
            raise RegistryError(
                "hosted account login verification is not configured"
            )
        if not self._hosted_account_verifier(
            request.claimant_key_id,
            request.payload,
        ):
            raise RegistryError("hosted account login verification failed")
        provider = request.payload.get("provider")
        if provider is not None and not isinstance(provider, str):
            raise RegistryError("provider must be a string")
        self._append_event(
            RegistryEventType.ACCOUNT_AUTHORIZED,
            request.claimant_key_id,
            {
                "key_id": request.claimant_key_id,
                "authorized_by_key_id": request.claimant_key_id,
                "hosted_account": True,
                "third_party_attested": False,
                "documented_rights": False,
                "provider": provider or self.registry_url,
                "method": "hosted_login",
            },
        )
        return self.get_profile(request.claimant_key_id)

    def attest_third_party_account(
        self,
        request: MutationRequest,
    ) -> ClaimantProfile:
        """Record independent third-party attestation evidence."""

        self._consume_verified_request(
            request,
            ChallengePurpose.THIRD_PARTY_ATTESTATION,
        )
        target_key_id = request.payload.get("target_key_id")
        if not isinstance(target_key_id, str) or not target_key_id:
            raise RegistryError("target_key_id must be a nonempty string")
        if target_key_id == request.claimant_key_id:
            raise RegistryError(
                "third-party attestation requires an independent signer"
            )
        self.get_profile(target_key_id)
        self.get_profile(request.claimant_key_id)
        documented_rights = request.payload.get("documented_rights", False)
        if not isinstance(documented_rights, bool):
            raise RegistryError("documented_rights must be a boolean")
        provider = request.payload.get("provider")
        if provider is not None and not isinstance(provider, str):
            raise RegistryError("provider must be a string")
        note = request.payload.get("note")
        if note is not None and not isinstance(note, str):
            raise RegistryError("note must be a string")
        self._append_event(
            RegistryEventType.ACCOUNT_AUTHORIZED,
            request.claimant_key_id,
            {
                "key_id": target_key_id,
                "authorized_by_key_id": request.claimant_key_id,
                "hosted_account": False,
                "third_party_attested": True,
                "documented_rights": documented_rights,
                "provider": provider,
                "method": "third_party_attestation",
                "note": note,
            },
        )
        return self.get_profile(target_key_id)

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
            device_continuity=bool(profile.device_fingerprint),
            third_party_attested=profile.third_party_attested,
            documented_rights=profile.documented_rights,
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
        claim_signature_valid = (
            manifest_report.signature_valid and manifest_report.key_id_valid
        )
        if claim.revoked_at is not None:
            label = VerificationLabel.REVOKED
        elif disputed:
            label = VerificationLabel.DISPUTED
        elif not claim_signature_valid:
            label = VerificationLabel.INVALID_CLAIM_SIGNATURE
        elif manifest_report.content_binding_valid is True:
            label = VerificationLabel.CONTENT_CLAIM_VERIFIED
        elif (
            manifest_report.content_binding_valid is False
            and content is not None
        ):
            label = VerificationLabel.CONTENT_MISMATCH
        elif content is None:
            label = VerificationLabel.CLAIM_VERIFIED_CONTENT_UNCHECKED
        elif not manifest_report.public_nonce_available and nonce is None:
            label = VerificationLabel.CLAIM_VERIFIED_CONTENT_PRIVATE
        else:
            label = VerificationLabel.INCONCLUSIVE
        return ClaimVerificationReport(
            claim_id=claim.claim_id,
            label=label,
            trust_tier=evidence_profile.trust_tier,
            trust_labels=evidence_profile.trust_labels,
            registry_included=True,
            manifest_signature_valid=claim_signature_valid,
            content_binding_valid=manifest_report.content_binding_valid,
            content_binding_checked=manifest_report.content_binding_checked,
            public_nonce_available=manifest_report.public_nonce_available,
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
                "third_party_attested": profile.third_party_attested,
                "documented_rights": profile.documented_rights,
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
