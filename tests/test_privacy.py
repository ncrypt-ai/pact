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
    audit_registry_claim_payload,
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
    } == {
        "registry_pseudonym_disclosed",
        "salted_commitment_disclosed",
        "public_content_nonce_disclosed",
    }


def test_private_nonce_privacy_audit_rejects_nonce_disclosure() -> None:
    signed, content, nonce = make_signed_manifest()

    report = audit_signed_manifest_publication(
        signed,
        content=content,
        nonce=nonce,
        allow_public_nonce=False,
    )

    assert report.passed is False
    assert any(
        finding.code == "nonce_disclosed" for finding in report.findings
    )


def test_public_payload_privacy_audit_rejects_private_material() -> None:
    report = audit_public_json_payload(
        {"nonce": "BQ" * 32, "note": "private draft text"},
        content=b"private draft text",
        nonce=b"\x05" * 32,
    )

    assert report.passed is False
    with pytest.raises(PrivacyAuditError, match="private local material"):
        report.require_passed()


def test_registry_claim_payload_rejects_plaintext_fields() -> None:
    signed, content, nonce = make_signed_manifest()

    report = audit_registry_claim_payload(
        {
            "signed_manifest_json": signed.to_json().decode("utf-8"),
            "plaintext": content.decode("utf-8"),
        },
        content=content,
        nonce=nonce,
    )

    assert report.passed is False
    assert any(
        finding.code == "unexpected_registry_claim_field"
        for finding in report.findings
    )
