"""HTML and XML carrier formats for signed PACT manifests."""

import re
from dataclasses import dataclass
from html import unescape
from xml.etree.ElementTree import ParseError
from xml.sax.saxutils import escape

from defusedxml import ElementTree as defused_etree
from defusedxml.common import DefusedXmlException

from pact.canonical import (
    CanonicalizationProfile,
    ContentCanonicalizationError,
    canonicalize_content,
)
from pact.carriers.text import CarrierError, InvisibleLocator
from pact.manifest import SignedManifest

PACT_XML_NAMESPACE = "urn:ncrypt-ai:pact:manifest:v1"

_HTML_HEAD_CLOSE = re.compile(r"</head\s*>", re.IGNORECASE)
_HTML_BODY_CLOSE = re.compile(r"</body\s*>", re.IGNORECASE)
_HTML_MANIFEST_BLOCK = re.compile(
    r"\n?<script type=\"application/pact\+json\" data-pact-role=\"manifest\">"
    r"\n(?P<manifest>.*?)\n</script>",
    re.DOTALL,
)
_HTML_LOCATOR_BLOCK = re.compile(
    r"\n?<span hidden data-pact-role=\"locator\">(?P<locator>.*?)</span>",
    re.DOTALL,
)

_XML_MANIFEST_BLOCK = re.compile(
    r"\n?<pact:manifest xmlns:pact=\""
    + re.escape(PACT_XML_NAMESPACE)
    + r"\">(?P<manifest>.*?)</pact:manifest>",
    re.DOTALL,
)
_XML_LOCATOR_BLOCK = re.compile(
    r"\n?<pact:locator xmlns:pact=\""
    + re.escape(PACT_XML_NAMESPACE)
    + r"\" encoding=\"zero-width\">(?P<locator>.*?)</pact:locator>",
    re.DOTALL,
)


def _canonical_text_bytes(value: bytes | str) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    try:
        return canonicalize_content(raw, CanonicalizationProfile.TEXT_V1)
    except ContentCanonicalizationError as error:
        raise CarrierError(str(error)) from error


def _require_text_manifest(signed: SignedManifest) -> None:
    if signed.manifest.canonicalization is not CanonicalizationProfile.TEXT_V1:
        raise CarrierError(
            "structured text carriers require pact.text.v1 manifests"
        )


def _remove_once(value: str, pattern: re.Pattern[str]) -> tuple[str, str]:
    matches = list(pattern.finditer(value))
    if not matches:
        raise CarrierError("structured carrier block is missing")
    if len(matches) != 1:
        raise CarrierError("multiple structured carrier blocks are not supported")
    match = matches[0]
    stripped = value[: match.start()] + value[match.end() :]
    return stripped, match.group(0)


@dataclass(frozen=True, slots=True)
class StructuredCarrierExtraction:
    """Recovered content and metadata from an HTML or XML carrier."""

    content: bytes
    signed_manifest: SignedManifest
    locator: InvisibleLocator | None = None


@dataclass(frozen=True, slots=True)
class _RootTag:
    name: str
    end_index: int
    self_closing: bool


def _scan_tag_end(text: str, start: int) -> int:
    quote: str | None = None
    for index in range(start, len(text)):
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == ">":
            return index
    raise CarrierError("XML start tag is not closed")


def _scan_declaration_end(text: str, start: int) -> int:
    quote: str | None = None
    bracket_depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        elif char == ">" and bracket_depth == 0:
            return index
    raise CarrierError("XML declaration is not closed")


def _find_root_tag(text: str) -> _RootTag:
    index = 0
    while index < len(text):
        marker = text.find("<", index)
        if marker == -1:
            break
        if text.startswith("<?", marker):
            end = text.find("?>", marker + 2)
            if end == -1:
                raise CarrierError("XML processing instruction is not closed")
            index = end + 2
            continue
        if text.startswith("<!--", marker):
            end = text.find("-->", marker + 4)
            if end == -1:
                raise CarrierError("XML comment is not closed")
            index = end + 3
            continue
        if text.startswith("<!", marker):
            index = _scan_declaration_end(text, marker + 2) + 1
            continue
        end = _scan_tag_end(text, marker + 1)
        tag = text[marker : end + 1]
        name_match = re.match(r"<\s*([^\s>/]+)", tag)
        if name_match is None:
            raise CarrierError("XML root tag is malformed")
        return _RootTag(
            name=name_match.group(1),
            end_index=end,
            self_closing=tag.rstrip().endswith("/>"),
        )
    raise CarrierError("XML document does not contain a root element")


def _parse_xml_safely(value: str) -> None:
    try:
        root = defused_etree.fromstring(value)
    except (DefusedXmlException, ParseError) as error:
        raise CarrierError(
            "XML must be well-formed and disallow external entities"
        ) from error
    manifest_nodes = root.findall(f".//{{{PACT_XML_NAMESPACE}}}manifest")
    locator_nodes = root.findall(f".//{{{PACT_XML_NAMESPACE}}}locator")
    if manifest_nodes:
        raise CarrierError("XML document already contains a PACT manifest")
    if locator_nodes:
        raise CarrierError("XML document already contains a PACT locator")


def embed_html_carrier(
    document: bytes | str,
    signed: SignedManifest,
    *,
    nonce: bytes | None = None,
    include_locator: bool = False,
) -> bytes:
    """Embed a signed manifest in the head of an HTML document."""

    _require_text_manifest(signed)
    text = _canonical_text_bytes(document).decode("utf-8")
    if _HTML_MANIFEST_BLOCK.search(text):
        raise CarrierError("HTML document already contains a PACT manifest")
    if _HTML_LOCATOR_BLOCK.search(text):
        raise CarrierError("HTML document already contains a PACT locator")
    head_close = _HTML_HEAD_CLOSE.search(text)
    if head_close is None:
        raise CarrierError("HTML document must contain a <head> element")

    manifest_json = signed.to_json().decode("utf-8").replace("<", "\\u003c")
    manifest_block = (
        "\n<script type=\"application/pact+json\" "
        "data-pact-role=\"manifest\">\n"
        f"{manifest_json}\n"
        "</script>"
    )
    result = (
        text[: head_close.start()] + manifest_block + text[head_close.start() :]
    )
    if include_locator:
        if nonce is None:
            raise CarrierError("a locator nonce is required")
        locator = InvisibleLocator.create(signed.manifest, nonce).to_zero_width()
        locator_block = (
            "\n<span hidden data-pact-role=\"locator\">"
            f"{locator}</span>"
        )
        body_close = _HTML_BODY_CLOSE.search(result)
        if body_close is None:
            result = result + locator_block
        else:
            result = (
                result[: body_close.start()]
                + locator_block
                + result[body_close.start() :]
            )
    return result.encode("utf-8")


def extract_html_carrier(value: bytes | str) -> StructuredCarrierExtraction:
    """Extract a signed manifest from an HTML document."""

    text = _canonical_text_bytes(value).decode("utf-8")
    manifest_matches = list(_HTML_MANIFEST_BLOCK.finditer(text))
    if not manifest_matches:
        raise CarrierError("HTML document does not contain a PACT manifest")
    if len(manifest_matches) != 1:
        raise CarrierError("multiple HTML manifest blocks are not supported")
    manifest_match = manifest_matches[0]
    signed = SignedManifest.from_json(manifest_match.group("manifest"))

    locator_matches = list(_HTML_LOCATOR_BLOCK.finditer(text))
    if len(locator_matches) > 1:
        raise CarrierError("multiple HTML locator blocks are not supported")
    locator = None
    cleaned = (
        text[: manifest_match.start()] + text[manifest_match.end() :]
    )
    if locator_matches:
        locator = InvisibleLocator.from_zero_width(locator_matches[0].group("locator"))
        cleaned, _removed = _remove_once(cleaned, _HTML_LOCATOR_BLOCK)

    return StructuredCarrierExtraction(
        content=cleaned.encode("utf-8"),
        signed_manifest=signed,
        locator=locator,
    )


def embed_xml_carrier(
    document: bytes | str,
    signed: SignedManifest,
    *,
    nonce: bytes | None = None,
    include_locator: bool = False,
) -> bytes:
    """Embed a signed manifest as a namespaced XML child element."""

    _require_text_manifest(signed)
    text = _canonical_text_bytes(document).decode("utf-8")
    _parse_xml_safely(text)
    root = _find_root_tag(text)

    manifest_json = escape(signed.to_json().decode("utf-8"))
    inserted = (
        "\n<pact:manifest xmlns:pact=\""
        + PACT_XML_NAMESPACE
        + "\">"
        + manifest_json
        + "</pact:manifest>"
    )
    if include_locator:
        if nonce is None:
            raise CarrierError("a locator nonce is required")
        locator = InvisibleLocator.create(signed.manifest, nonce).to_zero_width()
        inserted += (
            "\n<pact:locator xmlns:pact=\""
            + PACT_XML_NAMESPACE
            + "\" encoding=\"zero-width\">"
            + locator
            + "</pact:locator>"
        )

    if root.self_closing:
        opening = re.sub(r"/\s*>$", ">", text[: root.end_index + 1])
        closing = f"</{root.name}>"
        result = opening + inserted + closing + text[root.end_index + 1 :]
    else:
        result = (
            text[: root.end_index + 1]
            + inserted
            + text[root.end_index + 1 :]
        )
    return result.encode("utf-8")


def extract_xml_carrier(value: bytes | str) -> StructuredCarrierExtraction:
    """Extract a signed manifest from an XML document."""

    text = _canonical_text_bytes(value).decode("utf-8")
    try:
        defused_etree.fromstring(text)
    except (DefusedXmlException, ParseError) as error:
        raise CarrierError(
            "XML must be well-formed and disallow external entities"
        ) from error

    manifest_matches = list(_XML_MANIFEST_BLOCK.finditer(text))
    if not manifest_matches:
        raise CarrierError("XML document does not contain a PACT manifest")
    if len(manifest_matches) != 1:
        raise CarrierError("multiple XML manifest blocks are not supported")
    manifest_match = manifest_matches[0]
    signed = SignedManifest.from_json(unescape(manifest_match.group("manifest")))

    locator_matches = list(_XML_LOCATOR_BLOCK.finditer(text))
    if len(locator_matches) > 1:
        raise CarrierError("multiple XML locator blocks are not supported")
    locator = None
    cleaned = text[: manifest_match.start()] + text[manifest_match.end() :]
    if locator_matches:
        locator = InvisibleLocator.from_zero_width(locator_matches[0].group("locator"))
        cleaned, _removed = _remove_once(cleaned, _XML_LOCATOR_BLOCK)

    return StructuredCarrierExtraction(
        content=cleaned.encode("utf-8"),
        signed_manifest=signed,
        locator=locator,
    )
