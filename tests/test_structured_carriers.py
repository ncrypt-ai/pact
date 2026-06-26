import pytest

from pact.canonical import CanonicalizationProfile
from pact.carriers import (
    CarrierError,
)
from pact.carriers.structured import (
    PACT_XML_NAMESPACE,
    embed_html_carrier,
    embed_xml_carrier,
    extract_html_carrier,
    extract_xml_carrier,
)
from pact.crypto import base64url_encode
from pact.identity import ClaimantIdentity
from pact.manifest import Manifest, SignedManifest, sign_manifest
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry

CONTENT = b"Hello <world>\r\n"
ROOT_FINGERPRINT = base64url_encode(bytes(range(32)))
NONCE = bytes(reversed(range(32)))
HTML = (
    b"<!doctype html>\r\n"
    b"<html>\r\n"
    b"<head><title>PACT</title></head>\r\n"
    b"<body><p>Hello</p></body>\r\n"
    b"</html>\r\n"
)
XML = b'<?xml version="1.0"?>\r\n<document><body>Hello</body></document>\r\n'


def make_policy() -> Policy:
    return Policy(
        (
            PolicyEntry(
                Permission.GENERATIVE_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
        )
    )


def make_signed_manifest() -> SignedManifest:
    identity = ClaimantIdentity.generate("https://registry.example")
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=CONTENT,
        mime_type="text/html",
        canonicalization=CanonicalizationProfile.TEXT_V1,
        policy=make_policy(),
        nonce=NONCE,
    )
    return sign_manifest(manifest, identity)


def test_html_carrier_round_trip_with_locator() -> None:
    signed = make_signed_manifest()

    embedded = embed_html_carrier(
        HTML,
        signed,
        nonce=NONCE,
        include_locator=True,
    )
    extraction = extract_html_carrier(embedded)

    assert extraction.content == HTML.replace(b"\r\n", b"\n")
    assert extraction.signed_manifest == signed
    assert extraction.locator is not None
    assert extraction.locator.matches_manifest(signed.manifest, NONCE)


def test_html_carrier_requires_head_and_rejects_duplicates() -> None:
    signed = make_signed_manifest()

    with pytest.raises(CarrierError, match="<head>"):
        embed_html_carrier("<html><body></body></html>", signed)

    embedded = embed_html_carrier(HTML, signed)
    with pytest.raises(CarrierError, match="already contains"):
        embed_html_carrier(embedded, signed)


def test_html_extraction_rejects_duplicates() -> None:
    signed = make_signed_manifest()
    embedded = embed_html_carrier(HTML, signed)
    duplicate = embedded + embedded

    with pytest.raises(CarrierError, match="multiple HTML manifest"):
        extract_html_carrier(duplicate)


def test_xml_carrier_round_trip_with_locator() -> None:
    signed = make_signed_manifest()

    embedded = embed_xml_carrier(
        XML,
        signed,
        nonce=NONCE,
        include_locator=True,
    )
    extraction = extract_xml_carrier(embedded)

    assert extraction.content == XML.replace(b"\r\n", b"\n")
    assert extraction.signed_manifest == signed
    assert extraction.locator is not None
    assert extraction.locator.matches_manifest(signed.manifest, NONCE)


def test_xml_carrier_uses_namespace_and_rejects_existing_pact_nodes() -> None:
    signed = make_signed_manifest()
    embedded = embed_xml_carrier(XML, signed)

    assert PACT_XML_NAMESPACE.encode() in embedded

    with pytest.raises(CarrierError, match="already contains"):
        embed_xml_carrier(embedded, signed)


def test_xml_carrier_rejects_external_entities() -> None:
    signed = make_signed_manifest()
    malicious = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE doc [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<doc>&xxe;</doc>"
    )

    with pytest.raises(CarrierError, match="external entities"):
        embed_xml_carrier(malicious, signed)


def test_structured_carriers_require_text_manifests() -> None:
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
        embed_html_carrier(HTML, signed)
    with pytest.raises(CarrierError, match="pact.text.v1"):
        embed_xml_carrier(XML, signed)
