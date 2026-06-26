from uuid import UUID

import pytest

from pact import (
    CanonicalizationProfile,
    ClaimantIdentity,
    Manifest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    PrivacyAuditError,
    PrivacySeverity,
    audit_public_json_payload,
    audit_signed_manifest_publication,
    sign_manifest,
)


def make_signed_manifest():
    identity = ClaimantIdentity.generate("https://registry.example")
    content = b"private draft text"
    nonce = b"\x05" * 32
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint="A" * 43,
        content=content,
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
        claim_id=UUID("018f7f79-7b42-7c00-8000-000000000999"),
        nonce=nonce,
    )
    return sign_manifest(manifest, identity), content, nonce


def test_signed_manifest_privacy_audit_allows_salted_commitment() -> None:
    signed, content, nonce = make_signed_manifest()

    report = audit_signed_manifest_publication(
        signed,
        content=content,
        nonce=nonce,
    )

    assert report.passed is True
    assert {
        finding.code
        for finding in report.findings
        if finding.severity is PrivacySeverity.INFO
    } == {"registry_pseudonym_disclosed", "salted_commitment_disclosed"}


def test_public_payload_privacy_audit_rejects_private_material() -> None:
    report = audit_public_json_payload(
        {"nonce": "BQ" * 32, "note": "private draft text"},
        content=b"private draft text",
        nonce=b"\x05" * 32,
    )

    assert report.passed is False
    with pytest.raises(PrivacyAuditError, match="private local material"):
        report.require_passed()
