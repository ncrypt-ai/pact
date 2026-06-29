from pathlib import Path

import pytest

from pact import (
    AvoidanceReportLabel,
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
    SpreadStatus,
    TrustLabel,
    TrustTier,
    VerificationLabel,
    domain_verification_txt_name,
    domain_verification_txt_value,
    merkle_root,
    sign_manifest,
)
from pact.oprf import (
    device_binding_input,
    device_binding_oprf_token,
    format_device_binding_token,
)
from pact.registry.store import SqliteRegistryStore


def device_binding_token(identity: ClaimantIdentity) -> str:
    return format_device_binding_token(identity.key_id)


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


def make_private_signed_manifest(
    identity: ClaimantIdentity,
) -> SignedManifest:
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint="A" * 43,
        content=b"private hello",
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
        nonce=b"\x02" * 32,
        disclose_nonce=False,
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
        dns_txt_resolver=lambda _name: (),
    )
    return service, admin_identity


def register_profile(
    service: RegistryService, identity: ClaimantIdentity
) -> None:
    challenge = service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={
            "display_name": "Alice",
            "device_fingerprint": device_binding_token(identity),
        },
        proof_of_work_solution=solve_pow(challenge),
    )
    service.register_profile(request)


def test_device_binding_oprf_token_is_deterministic_and_registry_scoped(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path / "one")
    other_service, _other_admin = make_service(tmp_path / "two")
    local_input = device_binding_input(
        local_secret=b"local-secret",
        registry_root_fingerprint=service.certificate_authority.root_fingerprint,
        device_fingerprint="local-browser-fingerprint",
    )
    other_input = device_binding_input(
        local_secret=b"local-secret",
        registry_root_fingerprint=other_service.certificate_authority.root_fingerprint,
        device_fingerprint="local-browser-fingerprint",
    )

    first = device_binding_oprf_token(
        local_input=local_input,
        evaluator=service.evaluate_device_binding_oprf,
    )
    second = device_binding_oprf_token(
        local_input=local_input,
        evaluator=service.evaluate_device_binding_oprf,
    )
    other = device_binding_oprf_token(
        local_input=other_input,
        evaluator=other_service.evaluate_device_binding_oprf,
    )

    assert first == second
    assert first.startswith("pact-device-binding-v2.")
    assert other != first


def register_claim(
    service: RegistryService,
    identity: ClaimantIdentity,
) -> SignedManifest:
    signed_manifest = make_signed_manifest(identity)
    claim_challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REGISTRATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    claim_request = MutationRequest.create(
        identity,
        claim_challenge,
        payload={
            "signed_manifest_json": signed_manifest.to_json().decode("utf-8")
        },
        proof_of_work_solution=solve_pow(claim_challenge),
    )
    service.register_claim(claim_request)
    return signed_manifest


def register_signed_claim(
    service: RegistryService,
    identity: ClaimantIdentity,
    signed_manifest: SignedManifest,
) -> None:
    claim_challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REGISTRATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    claim_request = MutationRequest.create(
        identity,
        claim_challenge,
        payload={
            "signed_manifest_json": signed_manifest.to_json().decode("utf-8")
        },
        proof_of_work_solution=solve_pow(claim_challenge),
    )
    service.register_claim(claim_request)


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


def test_registry_profile_claim_certificate_and_domain_flow(
    tmp_path: Path,
) -> None:
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
    certificate_pem, chain_pem = service.issue_claimant_certificate(
        cert_request
    )
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
        payload={
            "signed_manifest_json": signed_manifest.to_json().decode("utf-8")
        },
        proof_of_work_solution=solve_pow(claim_challenge),
    )
    claim = service.register_claim(claim_request)
    assert claim.claimant_key_id == identity.key_id

    domain_challenge = service.issue_challenge(
        ChallengePurpose.DOMAIN_VERIFICATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    txt_name = domain_verification_txt_name("example.com")
    txt_value = domain_verification_txt_value(
        service.registry_url,
        identity.key_id,
        "example.com",
    )
    service._dns_txt_resolver = lambda name: (  # noqa: SLF001
        (txt_value,) if name == txt_name else ()
    )
    domain_request = MutationRequest.create(
        identity,
        domain_challenge,
        payload={"domain": "example.com", "txt_value": txt_value},
        proof_of_work_solution=solve_pow(domain_challenge),
    )
    updated_profile = service.verify_domain(domain_request)
    assert updated_profile.verified_domains == ("example.com",)

    evidence = service.evidence_profile(identity.key_id)
    assert evidence.active_claim_count == 1
    assert evidence.certificate_count == 2
    assert evidence.trust_tier is TrustTier.DOMAIN_VERIFIED
    assert TrustLabel.DOMAIN_VERIFIED in evidence.trust_labels


def test_domain_verification_requires_dns_txt_proof(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)

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

    with pytest.raises(RegistryError, match="DNS TXT record"):
        service.verify_domain(domain_request)

    evidence = service.evidence_profile(identity.key_id)
    assert evidence.trust_tier is TrustTier.UNAUTHENTICATED_DEVICE
    assert TrustLabel.DOMAIN_VERIFIED not in evidence.trust_labels


def test_profile_certificate_does_not_raise_trust_tier(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)

    evidence = service.evidence_profile(identity.key_id)

    assert evidence.certificate_count == 1
    assert evidence.trust_tier is TrustTier.UNAUTHENTICATED_DEVICE
    assert evidence.trust_labels == (TrustLabel.UNAUTHENTICATED_DEVICE,)


def test_profile_registration_cannot_self_assert_hosted_account(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    challenge = service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={
            "display_name": "Alice",
            "hosted_account": True,
            "device_fingerprint": device_binding_token(identity),
        },
        proof_of_work_solution=solve_pow(challenge),
    )

    with pytest.raises(RegistryError, match="administrator authorization"):
        service.register_profile(request)


def test_profile_registration_requires_device_binding_token(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
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

    with pytest.raises(RegistryError, match="device_fingerprint"):
        service.register_profile(request)


def test_profile_registration_rejects_legacy_device_fingerprint(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    challenge = service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={"device_fingerprint": "test-device"},
        proof_of_work_solution=solve_pow(challenge),
    )

    with pytest.raises(RegistryError, match="pact-device-binding-v2"):
        service.register_profile(request)


def test_admin_account_authorization_raises_trust_tier(tmp_path: Path) -> None:
    service, admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)

    challenge = service.issue_challenge(
        ChallengePurpose.ACCOUNT_AUTHORIZATION,
        difficulty=4,
        bound_key_id=admin_identity.key_id,
    )
    request = MutationRequest.create(
        admin_identity,
        challenge,
        payload={
            "target_key_id": identity.key_id,
            "provider": "registry.example",
            "note": "Test account authorization.",
        },
        proof_of_work_solution=solve_pow(challenge),
    )

    profile = service.authorize_hosted_account(request)
    evidence = service.evidence_profile(identity.key_id)

    assert profile.hosted_account is True
    assert profile.third_party_attested is False
    assert profile.documented_rights is False
    assert evidence.trust_tier is TrustTier.HOSTED_ACCOUNT
    assert TrustLabel.HOSTED_ACCOUNT in evidence.trust_labels
    assert TrustLabel.THIRD_PARTY_ATTESTED not in evidence.trust_labels


def test_non_admin_cannot_authorize_account_trust(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    other_identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    register_profile(service, other_identity)

    challenge = service.issue_challenge(
        ChallengePurpose.ACCOUNT_AUTHORIZATION,
        difficulty=4,
        bound_key_id=other_identity.key_id,
    )
    request = MutationRequest.create(
        other_identity,
        challenge,
        payload={"target_key_id": identity.key_id, "hosted_account": True},
        proof_of_work_solution=solve_pow(challenge),
    )

    with pytest.raises(RegistryError, match="only a registry admin"):
        service.authorize_hosted_account(request)


def test_hosted_login_raises_hosted_account_trust_tier(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    service._hosted_account_verifier = (  # noqa: SLF001
        lambda _key_id, payload: payload.get("login_token") == "ok"
    )
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)

    challenge = service.issue_challenge(
        ChallengePurpose.HOSTED_ACCOUNT_AUTHORIZATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={"login_token": "ok"},
        proof_of_work_solution=solve_pow(challenge),
    )

    profile = service.complete_hosted_account_login(request)
    evidence = service.evidence_profile(identity.key_id)

    assert profile.hosted_account is True
    assert evidence.trust_tier is TrustTier.HOSTED_ACCOUNT
    assert TrustLabel.HOSTED_ACCOUNT in evidence.trust_labels


def test_third_party_attestation_is_independent_trust_tier(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    attester_identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    register_profile(service, attester_identity)

    challenge = service.issue_challenge(
        ChallengePurpose.THIRD_PARTY_ATTESTATION,
        difficulty=4,
        bound_key_id=attester_identity.key_id,
    )
    request = MutationRequest.create(
        attester_identity,
        challenge,
        payload={
            "target_key_id": identity.key_id,
            "documented_rights": True,
            "provider": "Example Attester",
        },
        proof_of_work_solution=solve_pow(challenge),
    )

    profile = service.attest_third_party_account(request)
    evidence = service.evidence_profile(identity.key_id)

    assert profile.hosted_account is False
    assert profile.third_party_attested is True
    assert profile.documented_rights is True
    assert evidence.trust_tier is TrustTier.THIRD_PARTY_ATTESTED
    assert TrustLabel.THIRD_PARTY_ATTESTED in evidence.trust_labels
    assert TrustLabel.DOCUMENTED_RIGHTS in evidence.trust_labels


def test_registry_claim_verification_report_for_current_claim(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    signed_manifest = register_claim(service, identity)

    report = service.verify_claim(
        signed_manifest.manifest.claim_id,
        content=b"hello world",
        nonce=b"\x01" * 32,
    )

    assert report.label is VerificationLabel.CONTENT_CLAIM_VERIFIED
    assert report.verified is True
    assert report.claim_verified is True
    assert report.registry_included is True
    assert report.manifest_signature_valid is True
    assert report.content_binding_valid is True
    assert report.content_binding_checked is True
    assert report.public_nonce_available is True
    assert report.trust_tier is TrustTier.UNAUTHENTICATED_DEVICE
    assert report.claim_meanings == ("signed_by", "training_restriction")
    assert report.to_dict()["label"] == "content_claim_verified"


def test_registry_claim_only_is_not_content_verified(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    signed_manifest = register_claim(service, identity)

    report = service.verify_claim(signed_manifest.manifest.claim_id)

    assert report.label is VerificationLabel.CLAIM_VERIFIED_CONTENT_UNCHECKED
    assert report.verified is False
    assert report.claim_verified is True
    assert report.content_binding_valid is None
    assert report.content_binding_checked is False


def test_registry_claim_verification_reports_partial_content_match(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    signed_manifest = register_claim(service, identity)

    report = service.verify_claim(
        signed_manifest.manifest.claim_id,
        content=b"changed",
        nonce=b"\x01" * 32,
    )

    assert report.label is VerificationLabel.CONTENT_MISMATCH
    assert report.verified is False
    assert report.claim_verified is False
    assert report.content_binding_valid is False


def test_avoidance_reports_require_public_nonce_claim(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    signed_manifest = register_claim(service, identity)

    report = service.submit_avoidance_report(
        claim_id=signed_manifest.manifest.claim_id,
        evidence_type="submitted_file",
        evidence_digest="sha256-example",
        report_label=AvoidanceReportLabel.LIKELY_DERIVED_STRIPPED,
        observed_url="https://example.com/repost",
        reverse_lookup_score=0.87,
        description="Looks cropped and stripped.",
    )
    spread = service.spread_summary(signed_manifest.manifest.claim_id)

    assert report.status.value == "submitted"
    assert report.observed_domain == "example.com"
    assert spread.status is SpreadStatus.HIGH_CONFIDENCE_SPREAD
    assert spread.report_count == 1
    assert spread.domain_count == 1
    assert spread.highest_confidence is (
        AvoidanceReportLabel.LIKELY_DERIVED_STRIPPED
    )


def test_avoidance_reports_reject_private_nonce_claim(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    signed_manifest = make_private_signed_manifest(identity)
    register_signed_claim(service, identity, signed_manifest)

    with pytest.raises(RegistryError, match="public content verification"):
        service.submit_avoidance_report(
            claim_id=signed_manifest.manifest.claim_id,
            evidence_type="submitted_file",
            evidence_digest="sha256-example",
        )


def test_registry_rejects_claim_payload_private_fields(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    register_profile(service, identity)
    signed_manifest = make_signed_manifest(identity)
    challenge = service.issue_challenge(
        ChallengePurpose.CLAIM_REGISTRATION,
        difficulty=4,
        bound_key_id=identity.key_id,
    )
    request = MutationRequest.create(
        identity,
        challenge,
        payload={
            "signed_manifest_json": signed_manifest.to_json().decode("utf-8"),
            "content": "hello world",
        },
        proof_of_work_solution=solve_pow(challenge),
    )

    with pytest.raises(RegistryError, match="privacy audit"):
        service.register_claim(request)


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
        payload={"device_fingerprint": device_binding_token(identity)},
        proof_of_work_solution=solve_pow(challenge),
    )

    service.register_profile(request)
    with pytest.raises(RegistryError, match="already consumed"):
        service.register_profile(request)


def test_registry_consumes_challenge_on_failed_verification(
    tmp_path: Path,
) -> None:
    service, _admin_identity = make_service(tmp_path)
    identity = ClaimantIdentity.generate(service.registry_url)
    challenge = service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=0,
    )
    wrong_identity = ClaimantIdentity.generate(service.registry_url)
    bad_request = MutationRequest.create(
        wrong_identity,
        challenge,
        payload={"device_fingerprint": device_binding_token(wrong_identity)},
        proof_of_work_solution=solve_pow(challenge),
    )
    bad_request = MutationRequest(
        challenge_id=bad_request.challenge_id,
        claimant_public_jwk=bad_request.claimant_public_jwk,
        proof_of_work_solution=bad_request.proof_of_work_solution,
        payload=bad_request.payload,
        signature=(
            ("A" if bad_request.signature[0] != "A" else "B")
            + bad_request.signature[1:]
        ),
    )
    good_request = MutationRequest.create(
        identity,
        challenge,
        payload={"device_fingerprint": device_binding_token(identity)},
        proof_of_work_solution=solve_pow(challenge),
    )

    with pytest.raises(RegistryError):
        service.register_profile(bad_request)

    with pytest.raises(RegistryError, match="already consumed"):
        service.register_profile(good_request)


def test_registry_rejects_duplicate_device_fingerprint(tmp_path: Path) -> None:
    service, _admin_identity = make_service(tmp_path)
    first = ClaimantIdentity.generate(service.registry_url)
    second = ClaimantIdentity.generate(service.registry_url)
    fingerprint = device_binding_token(first)

    for identity in (first, second):
        challenge = service.issue_challenge(
            ChallengePurpose.PROFILE_REGISTRATION,
            difficulty=4,
        )
        request = MutationRequest.create(
            identity,
            challenge,
            payload={"device_fingerprint": fingerprint},
            proof_of_work_solution=solve_pow(challenge),
        )
        if identity is first:
            service.register_profile(request)
        else:
            with pytest.raises(RegistryError, match="already registered"):
                service.register_profile(request)


def test_registry_key_rotation_requires_old_and_new_signatures(
    tmp_path: Path,
) -> None:
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
        payload={
            "signed_manifest_json": signed_manifest.to_json().decode("utf-8")
        },
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
        payload={
            "claim_id": str(claim.claim_id),
            "reason": "possible conflict",
        },
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

    verification = service.verify_claim(claim.claim_id)
    assert verification.label is VerificationLabel.REVOKED
    assert verification.revoked is True


def test_registry_challenge_survives_service_restart_with_sqlite(
    tmp_path: Path,
) -> None:
    registry_url = "https://registry.example"
    database = tmp_path / "registry.sqlite"
    authority = RegistryCertificateAuthority.initialize(registry_url)
    identity = ClaimantIdentity.generate(registry_url)

    issuing_service = RegistryService(
        registry_url,
        store=SqliteRegistryStore(database),
        certificate_authority=authority,
    )

    challenge = issuing_service.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )

    consuming_service = RegistryService(
        registry_url,
        store=SqliteRegistryStore(database),
        certificate_authority=authority,
    )

    request = MutationRequest.create(
        identity,
        challenge,
        payload={"device_fingerprint": device_binding_token(identity)},
        proof_of_work_solution=solve_pow(challenge),
    )

    profile = consuming_service.register_profile(request)

    assert profile.key_id == identity.key_id

    with pytest.raises(RegistryError, match="already consumed"):
        consuming_service.register_profile(request)


def test_registry_snapshot_observes_external_sqlite_writes(
    tmp_path: Path,
) -> None:
    registry_url = "https://registry.example"
    database = tmp_path / "registry.sqlite"
    authority = RegistryCertificateAuthority.initialize(registry_url)

    service_a = RegistryService(
        registry_url,
        store=SqliteRegistryStore(database),
        certificate_authority=authority,
    )
    service_b = RegistryService(
        registry_url,
        store=SqliteRegistryStore(database),
        certificate_authority=authority,
    )

    first_identity = ClaimantIdentity.generate(registry_url)
    first_challenge = service_a.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    first_request = MutationRequest.create(
        first_identity,
        first_challenge,
        payload={"device_fingerprint": device_binding_token(first_identity)},
        proof_of_work_solution=solve_pow(first_challenge),
    )
    service_a.register_profile(first_request)

    # This warms service_b's snapshot.
    assert service_b.get_profile(first_identity.key_id).key_id == (
        first_identity.key_id
    )

    second_identity = ClaimantIdentity.generate(registry_url)
    second_challenge = service_a.issue_challenge(
        ChallengePurpose.PROFILE_REGISTRATION,
        difficulty=4,
    )
    second_request = MutationRequest.create(
        second_identity,
        second_challenge,
        payload={
            "device_fingerprint": device_binding_token(second_identity)
        },
        proof_of_work_solution=solve_pow(second_challenge),
    )

    # Write through service_a, read through service_b.
    service_a.register_profile(second_request)

    # This only passes if service_b notices latest_sequence changed
    # and rebuilds its snapshot.
    assert service_b.get_profile(second_identity.key_id).key_id == (
        second_identity.key_id
    )
