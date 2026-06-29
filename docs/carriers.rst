Carriers
========

PACT provides text, HTML, and XML carrier helpers for ``pact.text.v1``
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

Visible plain-text proof blocks include a short PACT notice explaining that the
embedded proof is provenance and usage-rights metadata, not legal advice or a
rights transfer. Extraction strips that notice before returning the content body
so content verification remains stable.

.. code-block:: python

   import secrets

   from pact import CarrierMode, embed_text_carrier, extract_text_carrier

   nonce = secrets.token_bytes(32)
   protected = embed_text_carrier(content, signed, nonce=nonce, mode=CarrierMode.BOTH)
   extracted = extract_text_carrier(protected)
   assert extracted.signed_manifest == signed
   assert extracted.locator is not None

Experimental text watermark plugins
-----------------------------------

PACT provides an experimental plugin layer for prose-only text watermarking.

Implemented plugins:

- invisible framing;
- context-limited lexical substitution;
- keyed syntactic variation;
- local semantic paraphrasing;
- user-approved canary phrases;
- statistical sentence-selection markers.

All text watermark transforms require explicit confirmation. Semantic methods
are disabled by default. The safety gate rejects content that looks like code,
configuration, structured records, legal text, or medical/safety text.

.. code-block:: python

   from pact import (
       LexicalSubstitutionPlugin,
       TextWatermarkParameters,
       apply_text_watermark_plugins,
   )

   result = apply_text_watermark_plugins(
       "We help new users start quickly because clear setup guidance matters.",
       "secret",
       (LexicalSubstitutionPlugin(),),
       TextWatermarkParameters(user_confirmation=True),
   )
   assert result.embeddings

The ``experimental`` text carrier mode composes the normal text carrier
with one or more selected plugins:

.. code-block:: python

   protected = embed_text_carrier(
       content,
       signed,
       nonce=nonce,
       mode=CarrierMode.EXPERIMENTAL,
       secret="secret",
       plugins=(LexicalSubstitutionPlugin(),),
       plugin_parameters=TextWatermarkParameters(user_confirmation=True),
   )

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

PACT provides a dedicated C2PA integration layer.

Recommended background:

- official C2PA project: https://c2pa.org/
- C2PA overview and critique: https://lowentropy.net/posts/c2pa/
- Hacker Factor VIDA discussion: https://www.hackerfactor.com/blog/index.php?/archives/1028-VIDA-The-Simple-Life.html

PACT uses C2PA as a practical carrier for content credentials. It does not
treat C2PA validation as proof of authorship, ownership, or legal permission.
PACT verification keeps container credentials, registry state, content binding,
revocation, disputes, and trust labels separate.

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

PACT includes container writers for formats where the official Python SDK can
read credentials but cannot author them directly:

- PDF uses an embedded file stream with ``/AFRelationship /C2PA_Manifest`` and
  a catalog ``/AF`` entry.
- ZIP-based document formats such as DOCX use
  ``META-INF/content_credential.c2pa`` stored without compression.

Those helpers embed a manifest store that has already been signed elsewhere.
PACT also exposes a hybrid signer path for unsupported document formats:

- for ZIP-based formats such as DOCX, it uses the official builder in
  ``no_embed`` mode and bypasses only the Python wrapper's format allow-list;
- for PDF, it uses the official builder to sign a detached manifest over the
  asset bytes, then uses the official ``format_embeddable()`` helper to
  produce PDF-ready manifest bytes before inserting them into the PDF.

The custom code in PACT is limited to container insertion and extraction.
Manifest construction, signing, and PDF embeddable-manifest formatting still
come from the official CAI SDK.

.. code-block:: python

   from pact import (
       C2paSignerMaterial,
       embed_c2pa_manifest_in_pdf,
       embed_c2pa_manifest_in_zip_document,
       pdf_external_manifest_reference,
       sign_c2pa_document,
   )

   protected_pdf = embed_c2pa_manifest_in_pdf(pdf_bytes, manifest_store_bytes)
   protected_docx = embed_c2pa_manifest_in_zip_document(
       docx_bytes,
       "docx",
       manifest_store_bytes,
   )
   signed_pdf = sign_c2pa_document(
       pdf_bytes,
       "application/pdf",
       signed=signed,
       signer_material=C2paSignerMaterial(certificate_chain_pem, private_key_pem),
       title="Protected PDF",
   )

   reference = pdf_external_manifest_reference(
       pdf_bytes,
       signed,
       manifest_uri="https://registry.example/manifests/claim.c2pa",
   )
   assert reference.media_type == "application/c2pa"

For legacy ``.doc`` and other formats without an embedded-carrier path, PACT
can still produce a detached manifest store, but the external-manifest
bootstrap remains the portable delivery option.

C2PA text containers
~~~~~~~~~~~~~~~~~~~~

PACT provides a text-container layer that stays aligned with the
``c2pa-text`` reference implementation instead of defining a new wire format.

Supported methods:

- unstructured Unicode variation-selector wrappers for plain text;
- structured manifest blocks for comment-friendly text formats;
- HTML ``<script type="application/c2pa">`` and
  ``<link rel="c2pa-manifest">`` associations.

PACT uses the reference package to encode and parse those containers, then
reuses PACT's detached-manifest signer to produce the Manifest Store bytes that
go inside them. Verification can inspect the text container itself and, when
the container carries an inline Manifest Store, parse that store through the
official C2PA SDK.

.. code-block:: python

   from pact import (
       C2paSignerMaterial,
       read_c2pa_text_asset,
       sign_c2pa_text_asset,
   )

   protected = sign_c2pa_text_asset(
       "# Notes\n",
       mime_type="text/markdown",
       signed=signed,
       signer_material=C2paSignerMaterial(certificate_chain_pem, private_key_pem),
       title="Protected notes",
   )
   inspected = read_c2pa_text_asset(protected.text, mime_type="text/markdown")
   assert inspected is not None
   assert inspected.validation.valid

TrustMark soft bindings
-----------------------

PACT provides an optional image watermark layer for JPEG, PNG, TIFF, and WebP
using TrustMark.

The payload is intentionally small. It carries a 96-bit compact claim locator,
not the manifest signature itself. The locator is enough to resolve one claim
on the configured registry and then verify the registry record, claimant
signature, and any C2PA binding separately.

PACT uses a raw binary TrustMark payload here because the ECC mode leaves too
little usable capacity for a practical claim locator.

PACT stores perceptual image fingerprints beside the TrustMark locator. The
fingerprint is not a secret and is not an authentication proof. It is a matching
aid made from multiple 64-bit perceptual hashes across deterministic views of
the image: original pixels, resize, center crops, recompression, and a small
photo-style resampling pass. This lets verification compare a transformed image
against a registered claim even when the embedded TrustMark signal is lost or
copied.

.. code-block:: python

   from pact import (
       compare_image_perceptual_fingerprints,
       create_image_perceptual_fingerprint,
       decode_image_soft_binding,
       embed_image_soft_binding,
   )

   watermarked = embed_image_soft_binding(
       image_bytes,
       "image/png",
       claim_id=claim.claim_id,
       registry_root_fingerprint=claim.signed_manifest.manifest.registry_root_fingerprint,
   )
   decoded = decode_image_soft_binding(watermarked.image_bytes, "image/png")
   assert decoded.locator is not None

   expected = create_image_perceptual_fingerprint(image_bytes, "image/png")
   observed = create_image_perceptual_fingerprint(transformed_bytes, "image/png")
   match = compare_image_perceptual_fingerprints(expected, observed)
   assert match.matched
