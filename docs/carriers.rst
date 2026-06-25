Carriers
========

PACT now provides text, HTML, and XML carrier helpers for ``pact.text.v1``
manifests.

Plain text
----------

Text carriers support three implemented modes:

- ``visible`` adds a parseable manifest block at the top of the document.
- ``invisible`` appends a framed zero-width locator.
- ``both`` combines the visible block and invisible redundancy.

The zero-width locator contains:

- locator version;
- claim UUID;
- registry-root fingerprint;
- private 32-byte nonce;
- SHA-256 digest of the canonical manifest payload;
- checksum.

It is a redundancy carrier, not a signature. The signed manifest remains the
authoritative proof object.

.. code-block:: python

   import secrets

   from pact import CarrierMode, embed_text_carrier, extract_text_carrier

   nonce = secrets.token_bytes(32)
   protected = embed_text_carrier(content, signed, nonce=nonce, mode=CarrierMode.BOTH)
   extracted = extract_text_carrier(protected)
   assert extracted.signed_manifest == signed
   assert extracted.locator is not None

HTML
----

HTML carriers insert the signed manifest into ``<head>`` using a non-executing
``application/pact+json`` block. When requested, they also append the
zero-width locator inside a hidden element near ``</body>``.

.. code-block:: python

   from pact import embed_html_carrier, extract_html_carrier

   protected = embed_html_carrier(html_document, signed, nonce=nonce, include_locator=True)
   extracted = extract_html_carrier(protected)
   assert extracted.signed_manifest == signed

XML
---

XML carriers insert namespaced ``pact:manifest`` and optional
``pact:locator`` child elements using the namespace
``urn:ncrypt-ai:pact:manifest:v1``. Parsing uses a hardened XML parser that
rejects external entities and other unsafe constructs before carrier handling.

.. code-block:: python

   from pact import embed_xml_carrier, extract_xml_carrier

   protected = embed_xml_carrier(xml_document, signed, nonce=nonce, include_locator=True)
   extracted = extract_xml_carrier(protected)
   assert extracted.signed_manifest == signed

C2PA
----

PACT step 3 adds a dedicated C2PA integration layer.

Supported image formats
~~~~~~~~~~~~~~~~~~~~~~~

For image formats that the installed official SDK can embed, PACT can create
an actual C2PA Manifest Store inside the asset and read it back later.

.. code-block:: python

   from pact import (
       C2paSignerMaterial,
       embed_c2pa_image,
       read_c2pa_asset,
   )

   signer = C2paSignerMaterial(certificate_chain_pem, private_key_pem)
   embedded = embed_c2pa_image(
       image_bytes,
       "image/png",
       signed=signed,
       signer_material=signer,
       title="Protected image",
   )
   inspected = read_c2pa_asset(embedded.asset_bytes, mime_type="image/png")
   assert inspected.active_manifest is not None

The signer material must already satisfy the certificate requirements enforced
by the official C2PA SDK.

PDF, DOCX, and external manifests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PACT now has real container writers for formats where the official Python SDK
can read credentials but cannot author them directly:

- PDF uses an embedded file stream with ``/AFRelationship /C2PA_Manifest`` and
  a catalog ``/AF`` entry.
- ZIP-based document formats such as DOCX use
  ``META-INF/content_credential.c2pa`` stored without compression.

Those helpers embed a manifest store that has already been signed elsewhere.
They do not generate a new compliant C2PA manifest store for PDF or OOXML on
their own, because the installed official Python builder still does not sign
those source formats.

.. code-block:: python

   from pact import (
       embed_c2pa_manifest_in_pdf,
       embed_c2pa_manifest_in_zip_document,
       pdf_external_manifest_reference,
   )

   protected_pdf = embed_c2pa_manifest_in_pdf(pdf_bytes, manifest_store_bytes)
   protected_docx = embed_c2pa_manifest_in_zip_document(
       docx_bytes,
       "docx",
       manifest_store_bytes,
   )

   reference = pdf_external_manifest_reference(
       pdf_bytes,
       signed,
       manifest_uri="https://registry.example/manifests/claim.c2pa",
   )
   assert reference.media_type == "application/c2pa"

For plain text, legacy ``.doc``, and other formats without a supported
embedded-carrier path, use the external-manifest bootstrap.
