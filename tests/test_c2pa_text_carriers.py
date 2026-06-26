from uuid import UUID

import pytest
from c2pa_text import Method, Placement, embed_manifest, embed_structured

from pact.canonical import CanonicalizationProfile
from pact.carriers.c2pa import C2paReadResult, C2paSignerMaterial
from pact.carriers.c2pa_text import (
    C2paTextError,
    C2paTextValidationResult,
    c2pa_text_comment_syntax,
    c2pa_text_recommended_method,
    embed_c2pa_text_html,
    embed_c2pa_text_structured,
    embed_c2pa_text_unstructured,
    extract_c2pa_text_asset,
    extract_c2pa_text_html,
    extract_c2pa_text_structured,
    extract_c2pa_text_unstructured,
    read_c2pa_text_asset,
    sign_c2pa_text_asset,
    validate_c2pa_text_document,
)
from pact.crypto import base64url_encode
from pact.identity import ClaimantIdentity
from pact.manifest import Manifest, SignedManifest, sign_manifest
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry

CONTENT = b"plain text"
ROOT_FINGERPRINT = base64url_encode(bytes(range(32)))
NONCE = bytes(reversed(range(32)))
CLAIM_ID = UUID("018f7f79-7b42-7c00-8000-000000000001")


def make_signed_manifest_text() -> SignedManifest:
    identity = ClaimantIdentity.generate("https://registry.example")
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=CONTENT,
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
        claim_id=CLAIM_ID,
        nonce=NONCE,
    )
    return sign_manifest(manifest, identity)


def _valid_manifest_result(
    manifest_store_bytes: bytes = b"abc",
) -> C2paTextValidationResult:
    return C2paTextValidationResult(
        valid=True,
        issues=(),
        manifest_store_bytes=manifest_store_bytes,
    )


def test_c2pa_text_helpers_follow_reference_recommendations() -> None:
    assert c2pa_text_recommended_method("text/plain") is Method.UNSTRUCTURED
    assert c2pa_text_recommended_method("application/xml") is Method.STRUCTURED
    assert c2pa_text_recommended_method("text/html") is Method.HTML
    assert c2pa_text_comment_syntax("text/markdown") == ("<!--", "-->")


def test_unstructured_c2pa_text_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pact.carriers.c2pa_text.validate_c2pa_text_manifest_store",
        lambda manifest_store_bytes, strict=True: _valid_manifest_result(
            manifest_store_bytes
        ),
    )

    asset = embed_c2pa_text_unstructured("hello", b"abc")
    extracted = extract_c2pa_text_unstructured(asset.text)

    assert extracted is not None
    assert extracted.method is Method.UNSTRUCTURED
    assert extracted.clean_text == "hello"
    assert extracted.manifest_store_bytes == b"abc"


def test_structured_c2pa_text_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pact.carriers.c2pa_text.validate_c2pa_text_manifest_store",
        lambda manifest_store_bytes, strict=True: _valid_manifest_result(
            manifest_store_bytes
        ),
    )

    asset = embed_c2pa_text_structured(
        "hello", mime_type="text/markdown", manifest_store_bytes=b"abc"
    )
    extracted = extract_c2pa_text_structured(asset.text)

    assert extracted is not None
    assert extracted.method is Method.STRUCTURED
    assert extracted.reference is not None
    assert extracted.reference.startswith("data:application/c2pa;base64,")
    assert extracted.manifest_store_bytes == b"abc"


def test_html_c2pa_text_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pact.carriers.c2pa_text.validate_c2pa_text_manifest_store",
        lambda manifest_store_bytes, strict=True: _valid_manifest_result(
            manifest_store_bytes
        ),
    )

    asset = embed_c2pa_text_html(
        "<html><head></head><body>hello</body></html>",
        manifest_store_bytes=b"abc",
    )
    extracted = extract_c2pa_text_html(asset.text)

    assert extracted is not None
    assert extracted.method is Method.HTML
    assert extracted.manifest_store_bytes == b"abc"


def test_extract_c2pa_text_asset_rejects_ambiguous_documents() -> None:
    wrapped = embed_manifest("hello", b"abc")
    syntax = c2pa_text_comment_syntax("text/markdown")
    assert syntax is not None
    structured = embed_structured(
        wrapped,
        "https://registry.example/manifests/claim.c2pa",
        *syntax,
    )

    with pytest.raises(
        C2paTextError,
        match="multiple C2PA text association methods",
    ):
        extract_c2pa_text_asset(structured.text, mime_type="text/markdown")


def test_validate_c2pa_text_document_validates_html_references() -> None:
    html = (
        "<html><head>"
        '<link rel="c2pa-manifest" href="https://registry.example/claim.c2pa" '
        'type="application/c2pa">'
        "</head><body>hello</body></html>"
    )

    result = validate_c2pa_text_document(html, mime_type="text/html")

    assert result.valid
    assert not result.issues


def test_validate_c2pa_text_document_reports_invalid_inline_html() -> None:
    html = (
        "<html><head>"
        '<script type="application/c2pa">not-base64</script>'
        "</head><body>hello</body></html>"
    )

    result = validate_c2pa_text_document(html, mime_type="text/html")

    assert not result.valid
    assert result.issues[0]["code"] == "manifest.html.invalidManifest"


def test_read_c2pa_text_asset_parses_inline_manifest_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pact.carriers.c2pa_text.validate_c2pa_text_document",
        lambda text, mime_type=None: _valid_manifest_result(b"abc"),
    )
    monkeypatch.setattr(
        "pact.carriers.c2pa_text.read_c2pa_asset",
        lambda asset_bytes, mime_type: C2paReadResult(
            mime_type=mime_type,
            embedded=False,
            validation_state="valid",
            active_manifest={"title": "Asset"},
            validation_results={"state": "valid"},
            manifest_store_json={"manifests": []},
        ),
    )

    result = read_c2pa_text_asset(embed_manifest("hello", b"abc"))

    assert result is not None
    assert result.extraction.method is Method.UNSTRUCTURED
    assert result.manifest_read is not None
    assert result.manifest_read.mime_type == "application/c2pa"


def test_sign_c2pa_text_asset_supports_structured_external_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = make_signed_manifest_text()

    monkeypatch.setattr(
        "pact.carriers.c2pa_text.sign_c2pa_manifest_store",
        lambda *args, **kwargs: b"abc",
    )

    asset = sign_c2pa_text_asset(
        "title = 'hello'\n",
        mime_type="application/xml",
        signed=signed,
        signer_material=C2paSignerMaterial(b"certs", b"key"),
        title="Config",
        method=Method.STRUCTURED,
        external_manifest_url="https://registry.example/manifests/claim.c2pa",
        placement=Placement.END,
    )

    assert asset.method is Method.STRUCTURED
    assert asset.reference == "https://registry.example/manifests/claim.c2pa"
    assert asset.manifest_store_bytes is None


def test_sign_c2pa_text_asset_rejects_external_reference_for_unstructured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = make_signed_manifest_text()

    monkeypatch.setattr(
        "pact.carriers.c2pa_text.sign_c2pa_manifest_store",
        lambda *args, **kwargs: b"abc",
    )

    with pytest.raises(
        C2paTextError,
        match="cannot use external manifest references",
    ):
        sign_c2pa_text_asset(
            "hello",
            mime_type="text/plain",
            signed=signed,
            signer_material=C2paSignerMaterial(b"certs", b"key"),
            title="Notes",
            method=Method.UNSTRUCTURED,
            external_manifest_url="https://registry.example/manifests/claim.c2pa",
        )
