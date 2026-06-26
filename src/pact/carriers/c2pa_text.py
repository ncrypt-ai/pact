"""C2PA-compliant text container helpers built on the reference implementation."""

from __future__ import annotations

from dataclasses import dataclass

from c2pa_text import (
    Method,
    Placement,
    ValidationIssue,
    ValidationResult,
    comment_syntax,
    embed_html_inline,
    embed_html_reference,
    embed_manifest,
    embed_structured,
    encode_data_uri,
    extract_html,
    extract_manifest,
    extract_structured,
    recommended_method,
    validate_manifest,
    validate_text,
)
from c2pa_text.html import HtmlError, HtmlExtraction
from c2pa_text.structured import (
    BEGIN_DELIMITER,
    DATA_URI_PREFIX,
    END_DELIMITER,
    StructuredError,
    StructuredExtraction,
)

from pact.carriers.c2pa import (
    C2paReadResult,
    C2paSignerMaterial,
    read_c2pa_asset,
    sign_c2pa_manifest_store,
)
from pact.carriers.text import CarrierError
from pact.manifest import SignedManifest


class C2paTextError(CarrierError):
    """Raised when C2PA text embedding or extraction fails."""


@dataclass(frozen=True, slots=True)
class C2paTextAsset:
    """A standards-compliant C2PA text container produced by this library."""

    method: Method
    text: str
    manifest_store_bytes: bytes | None
    reference: str | None = None
    exclusion_start: int | None = None
    exclusion_length: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible summary."""

        return {
            "method": self.method.value,
            "text_length": len(self.text),
            "manifest_size_bytes": (
                None
                if self.manifest_store_bytes is None
                else len(self.manifest_store_bytes)
            ),
            "reference": self.reference,
            "exclusion_start": self.exclusion_start,
            "exclusion_length": self.exclusion_length,
        }


@dataclass(frozen=True, slots=True)
class C2paTextExtractionResult:
    """Manifest extraction result for one C2PA text container."""

    method: Method
    clean_text: str
    manifest_store_bytes: bytes | None
    reference: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible summary."""

        return {
            "method": self.method.value,
            "clean_text": self.clean_text,
            "manifest_size_bytes": (
                None
                if self.manifest_store_bytes is None
                else len(self.manifest_store_bytes)
            ),
            "reference": self.reference,
        }


@dataclass(frozen=True, slots=True)
class C2paTextValidationResult:
    """Normalized validation result for a C2PA text document or manifest store."""

    valid: bool
    issues: tuple[dict[str, object], ...]
    manifest_store_bytes: bytes | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible summary."""

        return {
            "valid": self.valid,
            "issues": list(self.issues),
            "manifest_size_bytes": (
                None
                if self.manifest_store_bytes is None
                else len(self.manifest_store_bytes)
            ),
        }


@dataclass(frozen=True, slots=True)
class C2paTextReadResult:
    """Combined extraction, structural validation, and C2PA manifest readout."""

    extraction: C2paTextExtractionResult
    validation: C2paTextValidationResult
    manifest_read: C2paReadResult | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible summary."""

        return {
            "extraction": self.extraction.to_dict(),
            "validation": self.validation.to_dict(),
            "manifest_read": (
                None
                if self.manifest_read is None
                else {
                    "mime_type": self.manifest_read.mime_type,
                    "embedded": self.manifest_read.embedded,
                    "validation_state": self.manifest_read.validation_state,
                    "active_manifest": self.manifest_read.active_manifest,
                    "validation_results": self.manifest_read.validation_results,
                    "manifest_store_json": self.manifest_read.manifest_store_json,
                }
            ),
        }


def _normalize_validation_issue(issue: ValidationIssue) -> dict[str, object]:
    return {
        "code": issue.code.value,
        "message": issue.message,
        "offset": issue.offset,
        "context": issue.context,
    }


def _make_issue(
    code: str,
    message: str,
    *,
    offset: int | None = None,
    context: str | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "offset": offset,
        "context": context,
    }


def _normalize_validation_result(
    result: ValidationResult,
) -> C2paTextValidationResult:
    manifest_store_bytes = result.manifest_bytes or result.jumbf_bytes
    return C2paTextValidationResult(
        valid=result.valid,
        issues=tuple(
            _normalize_validation_issue(issue) for issue in result.issues
        ),
        manifest_store_bytes=manifest_store_bytes,
    )


def _validation_result_from_issues(
    issues: list[dict[str, object]],
    *,
    manifest_store_bytes: bytes | None = None,
) -> C2paTextValidationResult:
    return C2paTextValidationResult(
        valid=not issues,
        issues=tuple(issues),
        manifest_store_bytes=manifest_store_bytes,
    )


def _validate_structured_document(text: str) -> C2paTextValidationResult:
    begin_count = text.count(BEGIN_DELIMITER)
    end_count = text.count(END_DELIMITER)
    if begin_count == 0 and end_count == 0:
        return _validation_result_from_issues([])
    if begin_count > 1 or end_count > 1:
        return _validation_result_from_issues(
            [
                _make_issue(
                    "manifest.structuredText.multipleReferences",
                    "Multiple C2PA structured-text manifest blocks found",
                )
            ]
        )
    if begin_count != 1 or end_count != 1:
        return _validation_result_from_issues(
            [
                _make_issue(
                    "manifest.structuredText.noManifest",
                    "Structured-text manifest block delimiters are incomplete",
                )
            ]
        )
    try:
        extraction: StructuredExtraction = extract_structured(text)
    except StructuredError as error:
        return _validation_result_from_issues(
            [_make_issue(error.code, str(error))]
        )
    if extraction.manifest is not None:
        return validate_c2pa_text_manifest_store(extraction.manifest)
    if extraction.reference.startswith(DATA_URI_PREFIX):
        return _validation_result_from_issues(
            [
                _make_issue(
                    "manifest.structuredText.invalidDataUri",
                    "Structured-text manifest block contains an invalid data URI",
                )
            ]
        )
    return _validation_result_from_issues([])


def _validate_html_document(text: str) -> C2paTextValidationResult:
    try:
        extraction: HtmlExtraction | None = extract_html(text)
    except HtmlError as error:
        return _validation_result_from_issues(
            [_make_issue(error.code, str(error))]
        )
    if extraction is None:
        return _validation_result_from_issues([])
    if extraction.method == "inline":
        if extraction.manifest is None:
            return _validation_result_from_issues(
                [
                    _make_issue(
                        "manifest.html.invalidManifest",
                        "HTML inline manifest is not valid Base64 C2PA data",
                    )
                ]
            )
        return validate_c2pa_text_manifest_store(extraction.manifest)
    if extraction.reference is None or not extraction.reference.strip():
        return _validation_result_from_issues(
            [
                _make_issue(
                    "manifest.html.emptyReference",
                    "HTML manifest reference is empty",
                )
            ]
        )
    return _validation_result_from_issues([])


def c2pa_text_recommended_method(mime_type: str) -> Method | None:
    """Return the reference implementation's advisory method choice."""

    return recommended_method(mime_type)


def c2pa_text_comment_syntax(mime_type: str) -> tuple[str, str] | None:
    """Return the structured-text host comment delimiters for one MIME type."""

    return comment_syntax(mime_type)


def validate_c2pa_text_manifest_store(
    manifest_store_bytes: bytes,
    *,
    strict: bool = True,
) -> C2paTextValidationResult:
    """Validate a detached C2PA text manifest store before embedding."""

    return _normalize_validation_result(
        validate_manifest(
            manifest_store_bytes,
            validate_jumbf=True,
            strict=strict,
        )
    )


def validate_c2pa_text_document(
    text: str,
    *,
    mime_type: str | None = None,
) -> C2paTextValidationResult:
    """Validate one text asset across the supported C2PA text methods."""

    issues: list[dict[str, object]] = []
    matches: list[Method] = []
    manifest_store_bytes: bytes | None = None

    html_validation = _validate_html_document(text)
    if html_validation.manifest_store_bytes is not None:
        matches.append(Method.HTML)
        manifest_store_bytes = html_validation.manifest_store_bytes
    elif extract_c2pa_text_html(text) is not None:
        matches.append(Method.HTML)
    issues.extend(html_validation.issues)

    structured_validation = _validate_structured_document(text)
    if structured_validation.manifest_store_bytes is not None:
        matches.append(Method.STRUCTURED)
        if manifest_store_bytes is None:
            manifest_store_bytes = structured_validation.manifest_store_bytes
    elif extract_c2pa_text_structured(text) is not None:
        matches.append(Method.STRUCTURED)
    issues.extend(structured_validation.issues)

    unstructured_validation = _normalize_validation_result(validate_text(text))
    unstructured_extraction = extract_c2pa_text_unstructured(text)
    if unstructured_extraction is not None:
        matches.append(Method.UNSTRUCTURED)
        if manifest_store_bytes is None:
            manifest_store_bytes = unstructured_extraction.manifest_store_bytes
    issues.extend(unstructured_validation.issues)

    unique_matches: tuple[Method, ...]
    if mime_type is None:
        unique_matches = tuple(dict.fromkeys(matches))
    else:
        preferred = c2pa_text_recommended_method(mime_type)
        ordered = []
        if preferred is not None:
            ordered.append(preferred)
        ordered.extend(match for match in matches if match not in ordered)
        unique_matches = tuple(dict.fromkeys(ordered))
    if len(unique_matches) > 1:
        issues.append(
            _make_issue(
                "pact.c2paText.multipleAssociations",
                "Document contains more than one C2PA text association method",
                context=", ".join(method.value for method in unique_matches),
            )
        )
    return _validation_result_from_issues(
        issues,
        manifest_store_bytes=manifest_store_bytes,
    )


def embed_c2pa_text_unstructured(
    text: str,
    manifest_store_bytes: bytes,
    *,
    strict: bool = True,
) -> C2paTextAsset:
    """Embed a manifest store using the Appendix A.8 unstructured wrapper."""

    validation = validate_c2pa_text_manifest_store(
        manifest_store_bytes,
        strict=strict,
    )
    if not validation.valid:
        raise C2paTextError("manifest store failed C2PA text validation")
    return C2paTextAsset(
        method=Method.UNSTRUCTURED,
        text=embed_manifest(text, manifest_store_bytes),
        manifest_store_bytes=manifest_store_bytes,
    )


def extract_c2pa_text_unstructured(
    text: str,
) -> C2paTextExtractionResult | None:
    """Extract the Appendix A.8 unstructured wrapper, if present."""

    manifest_store_bytes, clean_text = extract_manifest(text)
    if manifest_store_bytes is None:
        return None
    return C2paTextExtractionResult(
        method=Method.UNSTRUCTURED,
        clean_text=clean_text,
        manifest_store_bytes=manifest_store_bytes,
    )


def embed_c2pa_text_structured(
    text: str,
    *,
    mime_type: str,
    manifest_store_bytes: bytes | None = None,
    reference: str | None = None,
    placement: Placement = Placement.START,
    newline: str = "\n",
    strict: bool = True,
) -> C2paTextAsset:
    """Embed a structured-text C2PA block using Appendix A.9."""

    syntax = c2pa_text_comment_syntax(mime_type)
    if syntax is None:
        raise C2paTextError(
            "no structured-text comment syntax is defined for this MIME type"
        )
    if (manifest_store_bytes is None) == (reference is None):
        raise C2paTextError(
            "provide exactly one of manifest_store_bytes or reference"
        )
    if manifest_store_bytes is not None:
        validation = validate_c2pa_text_manifest_store(
            manifest_store_bytes,
            strict=strict,
        )
        if not validation.valid:
            raise C2paTextError("manifest store failed C2PA text validation")
        resolved_reference = encode_data_uri(manifest_store_bytes)
    else:
        resolved_reference = reference
    if resolved_reference is None:
        raise C2paTextError("reference is required")
    prefix, suffix = syntax
    embedded = embed_structured(
        text,
        resolved_reference,
        prefix,
        suffix,
        placement=placement,
        newline=newline,
    )
    return C2paTextAsset(
        method=Method.STRUCTURED,
        text=embedded.text,
        manifest_store_bytes=manifest_store_bytes,
        reference=reference,
        exclusion_start=embedded.exclusion_start,
        exclusion_length=embedded.exclusion_length,
    )


def extract_c2pa_text_structured(text: str) -> C2paTextExtractionResult | None:
    """Extract a structured-text C2PA block, if present."""

    try:
        extraction: StructuredExtraction = extract_structured(text)
    except StructuredError as error:
        if error.code == "manifest.structuredText.noManifest":
            return None
        raise C2paTextError(str(error)) from error
    return C2paTextExtractionResult(
        method=Method.STRUCTURED,
        clean_text=text,
        manifest_store_bytes=extraction.manifest,
        reference=extraction.reference,
    )


def embed_c2pa_text_html(
    html: str,
    *,
    manifest_store_bytes: bytes | None = None,
    reference: str | None = None,
    newline: str = "\n",
    strict: bool = True,
) -> C2paTextAsset:
    """Embed a C2PA manifest association into HTML using Appendix A.7."""

    if (manifest_store_bytes is None) == (reference is None):
        raise C2paTextError(
            "provide exactly one of manifest_store_bytes or reference"
        )
    if manifest_store_bytes is not None:
        validation = validate_c2pa_text_manifest_store(
            manifest_store_bytes,
            strict=strict,
        )
        if not validation.valid:
            raise C2paTextError("manifest store failed C2PA text validation")
        embedded = embed_html_inline(
            html, manifest_store_bytes, newline=newline
        )
        return C2paTextAsset(
            method=Method.HTML,
            text=embedded.html,
            manifest_store_bytes=manifest_store_bytes,
            exclusion_start=embedded.exclusion_start,
            exclusion_length=embedded.exclusion_length,
        )
    if reference is None:
        raise C2paTextError("reference is required")
    return C2paTextAsset(
        method=Method.HTML,
        text=embed_html_reference(html, reference, newline=newline),
        manifest_store_bytes=None,
        reference=reference,
    )


def extract_c2pa_text_html(html: str) -> C2paTextExtractionResult | None:
    """Extract a C2PA HTML association, if present."""

    try:
        extraction: HtmlExtraction | None = extract_html(html)
    except HtmlError as error:
        raise C2paTextError(str(error)) from error
    if extraction is None:
        return None
    return C2paTextExtractionResult(
        method=Method.HTML,
        clean_text=html,
        manifest_store_bytes=extraction.manifest,
        reference=extraction.reference,
    )


def extract_c2pa_text_asset(
    text: str,
    *,
    mime_type: str | None = None,
) -> C2paTextExtractionResult | None:
    """Extract any supported C2PA text container from one document."""

    ordered_methods: list[Method] = []
    recommended = (
        c2pa_text_recommended_method(mime_type)
        if mime_type is not None
        else None
    )
    if recommended is not None:
        ordered_methods.append(recommended)
    for method in (Method.HTML, Method.STRUCTURED, Method.UNSTRUCTURED):
        if method not in ordered_methods:
            ordered_methods.append(method)
    matches: list[C2paTextExtractionResult] = []
    for method in ordered_methods:
        if method is Method.HTML:
            extracted = extract_c2pa_text_html(text)
        elif method is Method.STRUCTURED:
            extracted = extract_c2pa_text_structured(text)
        else:
            extracted = extract_c2pa_text_unstructured(text)
        if extracted is not None:
            matches.append(extracted)
    unique_matches = tuple(
        dict.fromkeys(
            (match.method, match.reference, match.manifest_store_bytes)
            for match in matches
        )
    )
    if len(unique_matches) > 1:
        raise C2paTextError(
            "document contains multiple C2PA text association methods"
        )
    if matches:
        return matches[0]
    return None


def read_c2pa_text_asset(
    text: str,
    *,
    mime_type: str | None = None,
) -> C2paTextReadResult | None:
    """Extract, validate, and parse one C2PA text container."""

    extraction = extract_c2pa_text_asset(text, mime_type=mime_type)
    if extraction is None:
        return None
    validation = validate_c2pa_text_document(text, mime_type=mime_type)
    manifest_read = None
    if extraction.manifest_store_bytes is not None:
        manifest_read = read_c2pa_asset(
            extraction.manifest_store_bytes,
            mime_type="application/c2pa",
        )
    return C2paTextReadResult(
        extraction=extraction,
        validation=validation,
        manifest_read=manifest_read,
    )


def sign_c2pa_text_asset(
    text: str,
    *,
    mime_type: str,
    signed: SignedManifest,
    signer_material: C2paSignerMaterial,
    title: str,
    method: Method | None = None,
    external_manifest_url: str | None = None,
    placement: Placement = Placement.START,
    newline: str = "\n",
    claim_generator: str = "pact",
) -> C2paTextAsset:
    """Create a detached C2PA manifest store and wrap it in a text container."""

    resolved_method = method or c2pa_text_recommended_method(mime_type)
    if resolved_method is None:
        resolved_method = Method.UNSTRUCTURED
    manifest_store_bytes = sign_c2pa_manifest_store(
        text.encode("utf-8"),
        mime_type,
        signed=signed,
        signer_material=signer_material,
        title=title,
        claim_generator=claim_generator,
    )
    if resolved_method is Method.UNSTRUCTURED:
        if external_manifest_url is not None:
            raise C2paTextError(
                "unstructured text containers cannot use external manifest references"
            )
        return embed_c2pa_text_unstructured(text, manifest_store_bytes)
    if resolved_method is Method.STRUCTURED:
        return embed_c2pa_text_structured(
            text,
            mime_type=mime_type,
            manifest_store_bytes=(
                None
                if external_manifest_url is not None
                else manifest_store_bytes
            ),
            reference=external_manifest_url,
            placement=placement,
            newline=newline,
        )
    if resolved_method is Method.HTML:
        return embed_c2pa_text_html(
            text,
            manifest_store_bytes=(
                None
                if external_manifest_url is not None
                else manifest_store_bytes
            ),
            reference=external_manifest_url,
            newline=newline,
        )
    raise C2paTextError(
        f"unsupported C2PA text method: {resolved_method.value}"
    )
