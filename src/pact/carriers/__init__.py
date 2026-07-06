"""Public carrier exports for text, structured, and C2PA assets."""

from importlib import import_module

_TEXT_EXPORTS = {
    "CarrierError",
    "CarrierMode",
    "InvisibleLocator",
    "TextCarrierExtraction",
    "embed_text_carrier",
    "extract_text_carrier",
}

_STRUCTURED_EXPORTS = {
    "PACT_XML_NAMESPACE",
    "StructuredCarrierExtraction",
    "embed_html_carrier",
    "embed_xml_carrier",
    "extract_html_carrier",
    "extract_xml_carrier",
}

_C2PA_EXPORTS = {
    "C2paAsset",
    "C2paError",
    "C2paReadResult",
    "C2paSignerMaterial",
    "ExternalManifestReference",
    "build_c2pa_manifest_definition",
    "build_external_manifest_reference",
    "c2pa_pdf_embedding_supported",
    "c2pa_supported_builder_mime_types",
    "c2pa_supported_embedded_document_mime_types",
    "c2pa_supported_embedded_image_mime_types",
    "c2pa_supported_reader_mime_types",
    "embed_c2pa_image",
    "embed_c2pa_manifest_in_pdf",
    "embed_c2pa_manifest_in_zip_document",
    "extract_c2pa_manifest_from_pdf",
    "extract_c2pa_manifest_from_zip_document",
    "pdf_external_manifest_reference",
    "read_c2pa_asset",
    "sign_c2pa_document",
    "sign_c2pa_manifest_store",
}

_C2PA_TEXT_EXPORTS = {
    "C2paTextAsset",
    "C2paTextError",
    "C2paTextExtractionResult",
    "C2paTextReadResult",
    "C2paTextValidationResult",
    "c2pa_text_comment_syntax",
    "c2pa_text_recommended_method",
    "embed_c2pa_text_html",
    "embed_c2pa_text_structured",
    "embed_c2pa_text_unstructured",
    "extract_c2pa_text_asset",
    "extract_c2pa_text_html",
    "extract_c2pa_text_structured",
    "extract_c2pa_text_unstructured",
    "read_c2pa_text_asset",
    "sign_c2pa_text_asset",
    "validate_c2pa_text_document",
    "validate_c2pa_text_manifest_store",
}

_EXPORT_MODULES = {
    **dict.fromkeys(_TEXT_EXPORTS, "pact.carriers.text"),
    **dict.fromkeys(_STRUCTURED_EXPORTS, "pact.carriers.structured"),
    **dict.fromkeys(_C2PA_EXPORTS, "pact.carriers.c2pa"),
    **dict.fromkeys(_C2PA_TEXT_EXPORTS, "pact.carriers.c2pa_text"),
}

__all__ = sorted(_EXPORT_MODULES)


def __getattr__(name: str) -> object:
    """Load carrier exports only when the caller requests them."""

    module_name = _EXPORT_MODULES.get(name)
    if module_name is not None:
        value = getattr(import_module(module_name), name)
        globals()[name] = value
        return value
    raise AttributeError(name)
