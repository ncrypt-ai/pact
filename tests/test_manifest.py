import json
from collections.abc import Callable
from copy import deepcopy
from typing import Any, cast
from uuid import UUID

import pytest

from pact.canonical import CanonicalizationProfile
from pact.crypto import base64url_encode
from pact.identity import ClaimantIdentity
from pact.manifest import (
    ClaimMeaning,
    ContentBinding,
    Manifest,
    ManifestError,
    ManifestSignature,
    SignedManifest,
    sign_manifest,
    verify_manifest,
)
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry

CONTENT = "Cafe\u0301\r\n".encode()
ROOT_FINGERPRINT = base64url_encode(bytes(range(32)))
CLAIM_ID = UUID("018f7f79-7b42-7c00-8000-000000000001")
NONCE = bytes(reversed(range(32)))


def make_policy() -> Policy:
    return Policy(
        (
            PolicyEntry(
                Permission.GENERATIVE_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
        )
    )


def make_identity(
    registry: str = "https://registry.example",
) -> ClaimantIdentity:
    return ClaimantIdentity.generate(registry)


def make_manifest(identity: ClaimantIdentity | None = None) -> Manifest:
    identity = make_identity() if identity is None else identity
    return Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=CONTENT,
        mime_type="text/plain",
        canonicalization=CanonicalizationProfile.TEXT_V1,
        policy=make_policy(),
        carriers=("pact.visible.v1",),
        watermarks=("pact.invisible.v1",),
        source_url="https://creator.example/work",
        licensing_url="https://creator.example/license",
        claim_id=CLAIM_ID,
        nonce=NONCE,
    )


def test_content_binding_create_verify_and_round_trip() -> None:
    binding = ContentBinding.create(
        CONTENT,
        CanonicalizationProfile.TEXT_V1,
        NONCE,
    )

    assert binding.verify(
        "Caf\xe9\n".encode(), CanonicalizationProfile.TEXT_V1, NONCE
    )
    assert not binding.verify(
        b"changed", CanonicalizationProfile.TEXT_V1, NONCE
    )
    assert ContentBinding.from_dict(binding.to_dict()) == binding
    assert "nonce" not in binding.to_dict()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ContentBinding("bad"),
        lambda: ContentBinding(ROOT_FINGERPRINT, "unknown"),
        lambda: ContentBinding.from_dict({}),
    ],
)
def test_invalid_content_bindings_are_rejected(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ManifestError):
        factory()

    with pytest.raises(ManifestError, match="must be a string"):
        ContentBinding(cast(str, 1))


def test_manifest_create_and_round_trip() -> None:
    identity = make_identity()
    manifest = make_manifest(identity)
    parsed = Manifest.from_dict(manifest.to_dict())

    assert parsed == manifest
    assert manifest.claimant_key_id == identity.key_id
    assert manifest.to_dict()["policy"] == {
        "label": "cawg.training-mining",
        "entries": {"cawg.ai_generative_training": {"use": "notAllowed"}},
    }
    assert manifest.to_dict()["claim_meanings"] == [
        "signed_by",
        "training_restriction",
    ]
    assert manifest.canonical_bytes() == parsed.canonical_bytes()


def test_manifest_omits_absent_optional_urls() -> None:
    identity = make_identity()
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=b"content",
        mime_type="application/octet-stream",
        canonicalization=CanonicalizationProfile.BINARY_V1,
        policy=make_policy(),
        nonce=NONCE,
    )

    assert "source_url" not in manifest.to_dict()
    assert "licensing_url" not in manifest.to_dict()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"version": "2"}, "version"),
        ({"registry_root_fingerprint": "bad"}, "fingerprint"),
        ({"claimant_key_id": "bad"}, "key_id"),
        ({"mime_type": "invalid"}, "media type"),
        ({"carriers": ("",)}, "cannot be blank"),
        ({"carriers": ("same", "same")}, "must be unique"),
        ({"watermarks": ("same", "same")}, "must be unique"),
        ({"claim_meanings": ()}, "must not be empty"),
        (
            {
                "claim_meanings": (
                    ClaimMeaning.SIGNED_BY,
                    ClaimMeaning.SIGNED_BY,
                )
            },
            "must be unique",
        ),
        ({"source_url": "relative"}, "absolute HTTP"),
        (
            {"licensing_url": "https://user:pass@example.com"},
            "credentials",
        ),
    ],
)
def test_invalid_manifests_are_rejected(
    changes: dict[str, object],
    message: str,
) -> None:
    values: dict[str, Any] = {
        "claim_id": CLAIM_ID,
        "registry_url": "https://registry.example",
        "registry_root_fingerprint": ROOT_FINGERPRINT,
        "claimant_key_id": ROOT_FINGERPRINT,
        "mime_type": "text/plain",
        "canonicalization": CanonicalizationProfile.TEXT_V1,
        "content_binding": ContentBinding(ROOT_FINGERPRINT),
        "policy": make_policy(),
    }
    values.update(changes)

    with pytest.raises(ManifestError, match=message):
        Manifest(**values)


def test_manifest_parser_rejects_bad_policy_and_shape() -> None:
    value = make_manifest().to_dict()
    policy = cast(dict[str, object], value["policy"])
    policy["label"] = "unknown"

    with pytest.raises(ManifestError, match="policy label"):
        Manifest.from_dict(value)
    with pytest.raises(ManifestError, match="invalid manifest"):
        Manifest.from_dict({})


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("content_binding",), [], "must be objects"),
        (
            ("content_binding", "commitment"),
            1,
            "commitment must be a string",
        ),
        (("policy", "entries"), [], "entries must be an object"),
        (("carriers",), "carrier", "array of strings"),
        (("watermarks",), [1], "array of strings"),
        (("claim_meanings",), ["unknown"], "unsupported claim meaning"),
        (("source_url",), 1, "source_url must be a string"),
        (("licensing_url",), 1, "licensing_url must be a string"),
    ],
)
def test_manifest_parser_rejects_invalid_types(
    path: tuple[str, ...],
    replacement: object,
    message: str,
) -> None:
    value = make_manifest().to_dict()
    target = value
    for part in path[:-1]:
        target = cast(dict[str, object], target[part])
    target[path[-1]] = replacement

    with pytest.raises(ManifestError, match=message):
        Manifest.from_dict(value)


def test_manifest_parser_accepts_legacy_manifest_without_claim_meanings() -> (
    None
):
    value = make_manifest().to_dict()
    del value["claim_meanings"]

    parsed = Manifest.from_dict(value)

    assert parsed.claim_meanings == (ClaimMeaning.SIGNED_BY,)


@pytest.mark.parametrize(
    ("path", "message"),
    [
        (("unknown",), "manifest fields"),
        (("content_binding", "unknown"), "content binding fields"),
        (("policy", "unknown"), "policy fields"),
    ],
)
def test_manifest_parser_rejects_unknown_fields(
    path: tuple[str, ...],
    message: str,
) -> None:
    value = make_manifest().to_dict()
    target = value
    for part in path[:-1]:
        target = cast(dict[str, object], target[part])
    target[path[-1]] = True

    with pytest.raises(ManifestError, match=message):
        Manifest.from_dict(value)


def test_sign_parse_and_verify_manifest() -> None:
    identity = make_identity()
    signed = sign_manifest(make_manifest(identity), identity)
    parsed = SignedManifest.from_json(signed.to_json())
    report = verify_manifest(parsed, identity.public_jwk, CONTENT, NONCE)

    assert parsed == signed
    assert report.valid
    assert report.signature_valid
    assert report.key_id_valid
    assert report.content_binding_valid
    assert report.errors == ()

    without_content = verify_manifest(parsed, identity.public_jwk)
    assert without_content.valid
    assert without_content.content_binding_valid is None

    without_nonce = verify_manifest(parsed, identity.public_jwk, CONTENT)
    assert not without_nonce.valid
    assert without_nonce.errors == ("content binding nonce is required",)


def test_verification_reports_wrong_content_key_and_signature() -> None:
    identity = make_identity()
    signed = sign_manifest(make_manifest(identity), identity)

    wrong_content = verify_manifest(
        signed, identity.public_jwk, b"changed", NONCE
    )
    assert not wrong_content.valid
    assert wrong_content.errors == ("content binding does not match",)

    other = make_identity()
    wrong_key = verify_manifest(signed, other.public_jwk)
    assert not wrong_key.valid
    assert wrong_key.key_id_valid is False
    assert wrong_key.signature_valid is False
    assert wrong_key.errors == (
        "claimant key identifier does not match",
        "claimant signature is invalid",
    )

    tampered = deepcopy(signed.to_dict())
    manifest = cast(dict[str, object], tampered["manifest"])
    manifest["mime_type"] = "text/html"
    parsed_tampered = SignedManifest.from_json(json.dumps(tampered))
    bad_signature = verify_manifest(parsed_tampered, identity.public_jwk)
    assert not bad_signature.valid
    assert bad_signature.errors == ("claimant signature is invalid",)


def test_verification_reports_invalid_public_jwk() -> None:
    identity = make_identity()
    signed = sign_manifest(make_manifest(identity), identity)

    report = verify_manifest(signed, {"kty": "RSA"}, CONTENT, NONCE)

    assert not report.valid
    assert report.content_binding_valid is False
    assert report.errors == ("claimant public key is invalid",)


def test_signing_requires_matching_registry_and_key() -> None:
    identity = make_identity()
    manifest = make_manifest(identity)

    with pytest.raises(ManifestError, match="different registry"):
        sign_manifest(manifest, make_identity("https://other.example"))
    with pytest.raises(ManifestError, match="does not match"):
        sign_manifest(manifest, make_identity(identity.registry_url))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ManifestSignature(ROOT_FINGERPRINT, ROOT_FINGERPRINT, "RS256"),
        lambda: ManifestSignature(ROOT_FINGERPRINT, "bad"),
        lambda: ManifestSignature.from_dict({}),
    ],
)
def test_invalid_manifest_signatures_are_rejected(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ManifestError):
        factory()


def test_signed_manifest_requires_matching_signature_key() -> None:
    identity = make_identity()
    manifest = make_manifest(identity)
    signature = ManifestSignature(
        ROOT_FINGERPRINT,
        base64url_encode(bytes(64)),
    )

    with pytest.raises(ManifestError, match="does not match"):
        SignedManifest(manifest, signature)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("[]", "JSON object"),
        ('{"manifest":{},"manifest":{},"signature":{}}', "duplicate"),
        ('{"manifest":NaN,"signature":{}}', "constant"),
        ('{"manifest":[],"signature":{}}', "must be objects"),
        ('{"manifest":{},"signature":{},"unknown":true}', "manifest fields"),
        ('{"manifest":{},"signature":', "invalid signed"),
        ('{"manifest":{}}', "invalid signed"),
    ],
)
def test_signed_manifest_parser_rejects_invalid_json(
    value: str,
    message: str,
) -> None:
    with pytest.raises(ManifestError, match=message):
        SignedManifest.from_json(value)
