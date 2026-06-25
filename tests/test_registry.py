from pathlib import Path

import pytest

from pact import (
    CanonicalizationProfile,
    ChallengePurpose,
    ClaimantIdentity,
    DisputeStatus,
    FileRegistryStore,
    KeyRotationRequest,
    Manifest,
    MutationRequest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    RegistryCertificateAuthority,
    RegistryError,
    RegistryEventType,
    RegistryService,
    SignedManifest,
    TrustLabel,
    merkle_root,
    sign_manifest,
)


def solve_pow(challenge) -> int:
    solution = 0
    while not challenge.verify_solution(solution):
        solution += 1
    return solution


def make_signed_manifest(identity: ClaimantIdentity) -> SignedManifest:
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint="A" * 43,
        content=b"hello world",
        mime_type="text/plain",
        canonicalization=CanonicalizationProfile.TEXT_V1,
        policy=Policy(
            (
                PolicyEntry(
                    Permission.GENERATIVE_TRAINING,
                    PermissionValue.NOT_ALLOWED,
                ),
            )
        ),
        nonce=b"\x01" * 32,
    )
    return sign_manifest(manifest, identity)


def make_service(tmp_path: Path) -> tuple[RegistryService, ClaimantIdentity]:
    registry_url = "https://registry.example"
    admin_identity = ClaimantIdentity.generate(registry_url)
    authority = RegistryCertificateAuthority.initialize(registry_url)
    service = RegistryService(
        registry_url,
        store=FileRegistryStore(tmp_path),
        certificate_authority=authority,
        admin_public_jwks=(admin_identity.public_jwk,),
    )
    return service, admin_identity


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


def test_merkle_root_requires_leaves() -> None:
    with pytest.raises(Exception, match="zero leaves"):
        merkle_root([])


def test_registry_store_appends_events_and_batches(tmp_path: Path) -> None:
    store = FileRegistryStore(tmp_path)

    event = store.append(
        RegistryEventType.PROFILE_REGISTERED,
        "key-1",
        {"key_id": "key-1", "public_jwk": {"kty": "EC"}},
    )

    assert event.sequence == 1
    assert len(store.list_events()) == 1
    batches = store.list_batches()
    assert len(batches) == 1
    assert batches[0].first_sequence == 1
    assert batches[0].last_sequence == 1


def test_registry_profile_claim_certificate_and_domain_flow(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)

    profile = service.get_profile(identity.key_id)
    assert profile.display_name == "Alice"

    cert_challenge = service.issue_challenge(
        ChallengePurpose.CERTIFICATE_ISSUANCE,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    cert_request = MutationRequest.create(
        identity,
        cert_challenge,
        payload={},
        proof_of_work_solution=solve_pow(cert_challenge),
    )
    certificate_pem, chain_pem = service.issue_claimant_certificate(cert_request)
    assert b"BEGIN CERTIFICATE" in certificate_pem
    assert chain_pem.startswith(certificate_pem)

    signed_manifest = make_signed_manifest(identity)
    claim_challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REGISTRATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    claim_request = MutationRequest.create(
        identity,
        claim_challenge,
        payload={"signed_manifest_json": signed_manifest.to_json().decode("utf-8")},
        proof_of_work_solution=solve_pow(claim_challenge),
    )
    claim = service.register_claim(claim_request)
    assert claim.claimant_key_id == identity.key_id

    domain_challenge = service.issue_challenge(
        ChallengePurpose.DOMAIN_VERIFICATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    domain_request = MutationRequest.create(
        identity,
        domain_challenge,
        payload={"domain": "example.com"},
        proof_of_work_solution=solve_pow(domain_challenge),
    )
    updated_profile = service.verify_domain(domain_request)
    assert updated_profile.verified_domains == ("example.com",)

    evidence = service.evidence_profile(identity.key_id)
    assert evidence.active_claim_count == 1
    assert evidence.certificate_count == 1
    assert TrustLabel.DOMAIN_VERIFIED in evidence.trust_labels
    assert TrustLabel.PLATFORM_VERIFIED in evidence.trust_labels


def test_registry_rejects_replayed_challenge(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    challenge = service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={},
        proof_of_work_solution=solve_pow(challenge),
    )

    service.register_profile(request)
    with pytest.raises(RegistryError, match="already consumed"):
        service.register_profile(request)


def test_registry_key_rotation_requires_old_and_new_signatures(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    current_identity = ClaimantIdentity.generate(service.registry_url)
    replacement_identity = current_identity.rotate()
    register_profile(service, current_identity)

    challenge = service.issue_challenge(
        ChallengePurpose.KEY_ROTATION,
        difficulty=4,
        bound_key_id=current_identity.key_id,
    )
    request = KeyRotationRequest.create(
        current_identity,
        replacement_identity,
        challenge,
        payload={"reason": "rotate"},
        proof_of_work_solution=solve_pow(challenge),
    )

    profile = service.rotate_key(request)
    assert profile.replacement_key_id == replacement_identity.key_id
    replacement_profile = service.get_profile(replacement_identity.key_id)
    assert replacement_profile.display_name == "Alice"


def test_registry_revocation_and_disputes(tmp_path: Path) -> None:
    service, admin_identity = make_service(tmp_path)
    claimant_identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, claimant_identity)
    register_profile(service, admin_identity)

    signed_manifest = make_signed_manifest(claimant_identity)
    claim_challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REGISTRATION,
        difficulty=4,
        bound_key_id=claimant_identity.key_id,
    )
    claim_request = MutationRequest.create(
        claimant_identity,
        claim_challenge,
        payload={"signed_manifest_json": signed_manifest.to_json().decode("utf-8")},
        proof_of_work_solution=solve_pow(claim_challenge),
    )
    claim = service.register_claim(claim_request)

    dispute_challenge = service.issue_challenge(
        ChallengePurpose.DISPUTE_OPEN,
        difficulty=4,
    )
    dispute_request = MutationRequest.create(
        admin_identity,
        dispute_challenge,
        payload={"claim_id": str(claim.claim_id), "reason": "possible conflict"},
        proof_of_work_solution=solve_pow(dispute_challenge),
    )
    dispute = service.open_dispute(dispute_request)
    assert dispute.status is DisputeStatus.OPEN

    resolve_challenge = service.issue_challenge(
        ChallengePurpose.DISPUTE_RESOLUTION,
        difficulty=4,
        bound_key_id=admin_identity.key_id,
    )
    resolve_request = MutationRequest.create(
        admin_identity,
        resolve_challenge,
        payload={
            "dispute_id": str(dispute.dispute_id),
            "status": "rejected",
            "resolution_note": "insufficient evidence",
        },
        proof_of_work_solution=solve_pow(resolve_challenge),
    )
    resolved = service.resolve_dispute(resolve_request)
    assert resolved.status is DisputeStatus.REJECTED

    revoke_challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REVOCATION,
        difficulty=4,
        bound_key_id=claimant_identity.key_id,
    )
    revoke_request = MutationRequest.create(
        claimant_identity,
        revoke_challenge,
        payload={"claim_id": str(claim.claim_id), "reason": "withdrawn"},
        proof_of_work_solution=solve_pow(revoke_challenge),
    )
    revoked = service.revoke_claim(revoke_request)
    assert revoked.revoked_at is not None
    assert revoked.revocation_reason == "withdrawn"

    evidence = service.evidence_profile(claimant_identity.key_id)
    assert evidence.active_claim_count == 0
    assert evidence.revoked_claim_count == 1
    assert evidence.rejected_disputes == 1
