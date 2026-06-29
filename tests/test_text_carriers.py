from copy import deepcopy
from uuid import UUID

import pytest

from pact.canonical import CanonicalizationProfile
from pact.carriers import (
    CarrierError,
    CarrierMode,
    InvisibleLocator,
    embed_text_carrier,
    extract_text_carrier,
)
from pact.crypto import base64url_encode
from pact.identity import ClaimantIdentity
from pact.manifest import Manifest, SignedManifest, sign_manifest
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry

CONTENT = "Cafe\u0301\r\n".encode()
ROOT_FINGERPRINT = base64url_encode(bytes(range(32)))
CLAIM_ID = UUID("018f7f79-7b42-7c00-8000-000000000001")
NONCE = bytes(reversed(range(32)))
CANONICAL_CONTENT = "Caf\u00e9\n".encode("utf-8")


def make_policy() -> Policy:
    return Policy(
        (
            PolicyEntry(
                Permission.GENERATIVE_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
        )
    )


def make_signed_manifest() -> tuple[Manifest, SignedManifest]:
    identity = ClaimantIdentity.generate("https://registry.example")
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=CONTENT,
        mime_type="text/plain",
        canonicalization=CanonicalizationProfile.TEXT_V1,
        policy=make_policy(),
        claim_id=CLAIM_ID,
        nonce=NONCE,
    )
    return manifest, sign_manifest(manifest, identity)


def test_locator_round_trip_and_matching() -> None:
    manifest, _signed = make_signed_manifest()
    locator = InvisibleLocator.create(manifest, NONCE)

    assert locator.matches_manifest(manifest, NONCE)
    assert locator.public_nonce == NONCE
    assert locator.to_dict()["public_nonce"] == base64url_encode(NONCE)
    assert "nonce" not in locator.to_dict()
    assert InvisibleLocator.from_zero_width(locator.to_zero_width()) == locator


def test_locator_can_omit_public_nonce() -> None:
    manifest, _signed = make_signed_manifest()
    locator = InvisibleLocator.create(manifest, None)

    assert locator.public_nonce is None
    assert locator.nonce is None
    assert "public_nonce" not in locator.to_dict()
    assert locator.matches_manifest(manifest)


def test_locator_rejects_tampering() -> None:
    manifest, _signed = make_signed_manifest()
    locator = InvisibleLocator.create(manifest, NONCE)
    payload = deepcopy(locator.to_dict())
    payload["manifest_digest"] = ROOT_FINGERPRINT

    with pytest.raises(CarrierError, match="checksum"):
        InvisibleLocator.from_dict(payload)


def test_visible_text_carrier_round_trip() -> None:
    _manifest, signed = make_signed_manifest()

    embedded = embed_text_carrier(
        CONTENT,
        signed,
        nonce=NONCE,
        mode=CarrierMode.VISIBLE,
    )
    extraction = extract_text_carrier(embedded)

    assert b"PACT NOTICE:" in embedded
    assert extraction.mode is CarrierMode.VISIBLE
    assert extraction.content == CANONICAL_CONTENT
    assert extraction.signed_manifest == signed
    assert extraction.locator is None


def test_invisible_text_carrier_round_trip() -> None:
    manifest, signed = make_signed_manifest()

    embedded = embed_text_carrier(
        CONTENT,
        signed,
        nonce=NONCE,
        mode=CarrierMode.INVISIBLE,
    )
    extraction = extract_text_carrier(embedded)

    assert b"PACT NOTICE:" in embedded
    assert extraction.mode is CarrierMode.INVISIBLE
    assert extraction.content == CANONICAL_CONTENT
    assert extraction.signed_manifest is None
    assert extraction.locator is not None
    assert extraction.locator.matches_manifest(manifest, NONCE)


def test_both_text_carrier_round_trip() -> None:
    manifest, signed = make_signed_manifest()

    embedded = embed_text_carrier(CONTENT, signed, nonce=NONCE)
    extraction = extract_text_carrier(embedded)

    assert extraction.mode is CarrierMode.BOTH
    assert extraction.signed_manifest == signed
    assert extraction.locator is not None
    assert extraction.locator.matches_manifest(manifest, NONCE)


def test_text_carrier_experimental_mode_requires_secret_and_plugins() -> None:
    _manifest, signed = make_signed_manifest()

    with pytest.raises(CarrierError, match="require a secret"):
        embed_text_carrier(
            CONTENT,
            signed,
            nonce=NONCE,
            mode=CarrierMode.EXPERIMENTAL,
        )


def test_text_carrier_requires_text_manifest() -> None:
    identity = ClaimantIdentity.generate("https://registry.example")
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=b"\x00\x01",
        mime_type="application/octet-stream",
        canonicalization=CanonicalizationProfile.BINARY_V1,
        policy=make_policy(),
        nonce=NONCE,
    )
    signed = sign_manifest(manifest, identity)

    with pytest.raises(CarrierError, match="pact.text.v1"):
        embed_text_carrier("text", signed, nonce=NONCE)


def test_text_carrier_rejects_missing_or_duplicate_locator_frames() -> None:
    with pytest.raises(CarrierError, match="does not contain"):
        extract_text_carrier("plain text")

    manifest, _signed = make_signed_manifest()
    locator = InvisibleLocator.create(manifest, NONCE).to_zero_width()
    doubled = f"text{locator}{locator}"

    with pytest.raises(CarrierError, match="multiple locator"):
        extract_text_carrier(doubled)


def test_text_carrier_rejects_invalid_visible_block() -> None:
    with pytest.raises(CarrierError, match="malformed"):
        extract_text_carrier(b"-----BEGIN PACT MANIFEST-----\n{}\n")


def test_locator_parser_rejects_invalid_shapes() -> None:
    manifest, _signed = make_signed_manifest()
    locator = InvisibleLocator.create(manifest, NONCE)
    payload = deepcopy(locator.to_dict())
    payload["unknown"] = True

    with pytest.raises(CarrierError, match="locator fields"):
        InvisibleLocator.from_dict(payload)
    with pytest.raises(CarrierError, match="frame is malformed"):
        InvisibleLocator.from_zero_width("not-a-frame")
