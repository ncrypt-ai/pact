from io import BytesIO
from pathlib import Path
from uuid import UUID

from PIL import Image

from pact import (
    CanonicalizationProfile,
    ChallengePurpose,
    ClaimantIdentity,
    FileRegistryStore,
    Manifest,
    MutationRequest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    RegistryCertificateAuthority,
    RegistryService,
    TrustMarkLocator,
    decode_image_soft_binding,
    embed_image_soft_binding,
    sign_manifest,
    verify_image_soft_binding,
)
from pact.registry.app import RegisteredClaim
from pact.watermarks.base import ImageWatermarkBackend

ROOT_FINGERPRINT = "A" * 43
CLAIM_ID = UUID("018f7f79-7b42-7c00-8000-000000000123")


class StubBackend(ImageWatermarkBackend):
    def __init__(self) -> None:
        self.bits: str | None = None

    def capacity_bits(self) -> int:
        return 96

    def embed_bits(
        self,
        image_bytes: bytes,
        mime_type: str,
        payload_bits: str,
        *,
        strength: float,
    ) -> bytes:
        del image_bytes, mime_type, strength
        self.bits = payload_bits
        return b"watermarked"

    def decode_bits(
        self,
        image_bytes: bytes,
        mime_type: str,
    ) -> tuple[str | None, int | None]:
        del image_bytes, mime_type
        return self.bits, 1


def solve_pow(challenge) -> int:
    solution = 0
    while not challenge.verify_solution(solution):
        solution += 1
    return solution


def make_png_bytes() -> bytes:
    image = Image.new("RGB", (32, 32), "white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def make_service(tmp_path: Path) -> RegistryService:
    registry_url = "https://registry.example"
    authority = RegistryCertificateAuthority.initialize(registry_url)
    return RegistryService(
        registry_url,
        store=FileRegistryStore(tmp_path),
        certificate_authority=authority,
    )


def register_profile(service: RegistryService, identity: ClaimantIdentity) -> None:
    challenge = service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={"display_name": "Alice"},
        proof_of_work_solution=solve_pow(challenge),
    )
    service.register_profile(request)


def register_claim(service: RegistryService, identity: ClaimantIdentity) -> RegisteredClaim:
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=make_png_bytes(),
        mime_type="image/png",
        canonicalization=CanonicalizationProfile.BINARY_V1,
        policy=Policy(
            (
                PolicyEntry(
                    Permission.GENERATIVE_TRAINING,
                    PermissionValue.NOT_ALLOWED,
                ),
            )
        ),
        claim_id=CLAIM_ID,
        watermarks=("pact.trustmark.image.v1",),
        nonce=b"\x01" * 32,
    )
    signed = sign_manifest(manifest, identity)
    challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REGISTRATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={"signed_manifest_json": signed.to_json().decode("utf-8")},
        proof_of_work_solution=solve_pow(challenge),
    )
    return service.register_claim(request)


def test_trustmark_locator_round_trip_and_match() -> None:
    locator = TrustMarkLocator.create(CLAIM_ID, ROOT_FINGERPRINT)

    assert locator.matches_claim(CLAIM_ID, ROOT_FINGERPRINT)
    assert TrustMarkLocator.from_payload_bits(locator.to_payload_bits()) == locator
    assert TrustMarkLocator.from_dict(locator.to_dict()) == locator


def test_embed_and_decode_image_soft_binding_with_stub_backend() -> None:
    backend = StubBackend()

    embedded = embed_image_soft_binding(
        make_png_bytes(),
        "image/png",
        claim_id=CLAIM_ID,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        backend=backend,
    )

    assert embedded.image_bytes == b"watermarked"
    decoded = decode_image_soft_binding(
        b"watermarked",
        "image/png",
        backend=backend,
    )
    assert decoded.detected is True
    assert decoded.locator == embedded.locator


def test_verify_image_soft_binding_resolves_registered_claim(
    tmp_path: Path,
) -> None:
    service = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    claim = register_claim(service, identity)
    backend = StubBackend()
    embedded = embed_image_soft_binding(
        make_png_bytes(),
        "image/png",
        claim_id=claim.claim_id,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        backend=backend,
    )

    verification = verify_image_soft_binding(
        embedded.image_bytes,
        "image/png",
        registry_service=service,
        backend=backend,
    )

    assert verification.detected is True
    assert verification.claim is not None
    assert verification.claim.claim_id == claim.claim_id
