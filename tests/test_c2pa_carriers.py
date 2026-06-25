import json
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest

from pact.canonical import CanonicalizationProfile
from pact.carriers.c2pa import (
    C2paAsset,
    C2paError,
    C2paReadResult,
    C2paSignerMaterial,
    build_c2pa_manifest_definition,
    c2pa_pdf_embedding_supported,
    c2pa_supported_builder_mime_types,
    c2pa_supported_embedded_image_mime_types,
    c2pa_supported_reader_mime_types,
    embed_c2pa_image,
    pdf_external_manifest_reference,
    read_c2pa_asset,
)
from pact.crypto import base64url_encode
from pact.identity import ClaimantIdentity
from pact.manifest import Manifest, SignedManifest, sign_manifest
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry

CONTENT = b"content"
ROOT_FINGERPRINT = base64url_encode(bytes(range(32)))
NONCE = bytes(reversed(range(32)))
CLAIM_ID = UUID("018f7f79-7b42-7c00-8000-000000000001")


def make_signed_manifest_png() -> SignedManifest:
    identity = ClaimantIdentity.generate("https://registry.example")
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=CONTENT,
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
        nonce=NONCE,
    )
    return sign_manifest(manifest, identity)


def test_supported_c2pa_type_lists_are_nonempty() -> None:
    assert c2pa_supported_reader_mime_types()
    assert c2pa_supported_builder_mime_types()
    assert "image/png" in c2pa_supported_embedded_image_mime_types()


def test_manifest_definition_includes_pact_metadata() -> None:
    signed = make_signed_manifest_png()

    result = build_c2pa_manifest_definition(
        signed,
        title="Asset",
        claim_generator="pact tests",
    )

    assert result["claim_generator"] == "pact tests"
    assert result["title"] == "Asset"
    metadata = cast(dict[str, str], result["metadata"])
    assert metadata["pact_claim_id"] == str(CLAIM_ID)


def test_pdf_external_manifest_reference_uses_jumbf_media_type() -> None:
    signed = make_signed_manifest_png()

    reference = pdf_external_manifest_reference(
        b"%PDF-1.4\n%%EOF\n",
        signed,
        manifest_uri="https://registry.example/manifests/claim.c2pa",
    )

    assert reference.asset_mime_type == "application/pdf"
    assert reference.media_type == "application/c2pa"
    assert reference.provenance_uri == reference.manifest_uri
    assert "Content Credentials" in reference.visible_notice


def test_read_c2pa_asset_requires_mime_for_bytes() -> None:
    with pytest.raises(C2paError, match="mime_type is required"):
        read_c2pa_asset(b"bytes")


def test_embed_c2pa_image_rejects_unsupported_types() -> None:
    signed = make_signed_manifest_png()
    signer = C2paSignerMaterial(b"certs", b"key")

    with pytest.raises(C2paError, match="supported image formats"):
        embed_c2pa_image(
            b"asset",
            "application/pdf",
            signed=signed,
            signer_material=signer,
            title="Asset",
        )


def test_embed_c2pa_image_uses_official_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    signed = make_signed_manifest_png()
    calls: dict[str, Any] = {}

    class FakeSigner:
        def __enter__(self) -> "FakeSigner":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class FakeBuilder:
        def __init__(self, manifest_json: Any) -> None:
            calls["manifest_json"] = manifest_json

        def __enter__(self) -> "FakeBuilder":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def set_intent(self, intent: Any, digital_source_type: Any) -> None:
            calls["intent"] = intent
            calls["digital_source_type"] = digital_source_type

        def sign(self, signer: Any, mime_type: str, source: Any, dest: Any) -> bytes:
            calls["mime_type"] = mime_type
            dest.write(b"signed-asset")
            return b"manifest-store"

    monkeypatch.setattr("pact.carriers.c2pa.Builder", FakeBuilder)
    monkeypatch.setattr(
        C2paSignerMaterial,
        "to_sdk_signer",
        lambda self: cast(Any, FakeSigner()),
    )

    result = embed_c2pa_image(
        b"asset",
        "image/png",
        signed=signed,
        signer_material=C2paSignerMaterial(b"certs", b"key"),
        title="Asset",
    )

    assert isinstance(result, C2paAsset)
    assert result.asset_bytes == b"signed-asset"
    assert result.manifest_store_bytes == b"manifest-store"
    assert calls["mime_type"] == "image/png"


def test_read_c2pa_asset_parses_reader_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    payload = {
        "manifests": {"active": {"title": "Asset"}},
        "active_manifest": "active",
    }

    class FakeReader:
        def __init__(self, *args: Any) -> None:
            self.args = args

        def __enter__(self) -> "FakeReader":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def json(self) -> str:
            return json.dumps(payload)

        def is_embedded(self) -> bool:
            return True

        def get_validation_state(self) -> str:
            return "valid"

        def get_active_manifest(self) -> dict[str, Any]:
            return {"title": "Asset"}

        def get_validation_results(self) -> dict[str, Any]:
            return {"status": "ok"}

    monkeypatch.setattr("pact.carriers.c2pa.Reader", FakeReader)
    asset_path = tmp_path / "asset.png"
    asset_path.write_bytes(b"png")

    result = read_c2pa_asset(asset_path)

    assert isinstance(result, C2paReadResult)
    assert result.embedded is True
    assert result.validation_state == "valid"
    assert result.active_manifest == {"title": "Asset"}
    assert result.validation_results == {"status": "ok"}
    assert result.manifest_store_json == payload


def test_pdf_embedding_support_reflects_builder_matrix() -> None:
    assert c2pa_pdf_embedding_supported() is False
