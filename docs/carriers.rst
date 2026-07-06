Carriers
========

A carrier attaches a signed PACT manifest to a file so the claim travels
with the content. Carriers do not replace the manifest signature — the signed
manifest JSON is always the authoritative proof object. A carrier is a recovery
and distribution aid: it lets inspection tools find the claim without a
separate sidecar file, and lets verifiers confirm the file has not been
separated from its claim.

PACT provides carriers for plain text, HTML, XML, C2PA image/PDF/DOCX, C2PA
text containers, and image soft bindings.

Plain text
----------

Three modes are supported:

``visible``
  Adds a parseable manifest block at the top of the document, including a
  plain-language PACT notice. The notice is stripped before content
  verification so the signed hash still matches the user's original content.

``invisible``
  Appends a framed zero-width locator using Unicode zero-width characters.
  Invisible to readers; recoverable by tools that know the framing format.

``both``
  Combines the visible block and invisible locator for maximum redundancy.

The zero-width locator carries the claim UUID, registry-root fingerprint,
private 32-byte nonce, SHA-256 digest of the canonical manifest payload, and
a checksum. It is a cross-check and recovery signal, not a second signature.

.. code-block:: python

   import secrets
   from pact import CarrierMode, embed_text_carrier, extract_text_carrier

   nonce = secrets.token_bytes(32)
   protected = embed_text_carrier(content, signed, nonce=nonce, mode=CarrierMode.BOTH)
   extracted = extract_text_carrier(protected)
   assert extracted.signed_manifest == signed
   assert extracted.locator is not None

Experimental text watermarks
-----------------------------

An additional ``experimental`` carrier mode composes the standard text carrier
with one or more watermark plugins that rewrite the prose to embed a recoverable
signal. This layer is conservative by design: all methods require explicit
user confirmation, the safety gate rejects content that looks like code,
configuration, structured records, legal text, or medical text, and semantic
methods are disabled by default.

Available plugins:

- Invisible framing (zero-width characters only)
- Context-limited lexical substitution
- Keyed syntactic variation
- Local semantic paraphrasing (disabled by default)
- User-approved canary phrases
- Statistical sentence-selection markers

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

Using a plugin through the carrier API:

.. code-block:: python

   protected = embed_text_carrier(
       content, signed,
       nonce=nonce,
       mode=CarrierMode.EXPERIMENTAL,
       secret="secret",
       plugins=(LexicalSubstitutionPlugin(),),
       plugin_parameters=TextWatermarkParameters(user_confirmation=True),
   )

HTML
----

The HTML carrier inserts the signed manifest into ``<head>`` as a
non-executing ``<script type="application/pact+json">`` block. The content
visible to readers is not modified. An optional zero-width locator can be
appended in a hidden element near ``</body>``.

.. code-block:: python

   from pact import embed_html_carrier, extract_html_carrier

   protected = embed_html_carrier(html_document, signed, nonce=nonce, include_locator=True)
   extracted = extract_html_carrier(protected)
   assert extracted.signed_manifest == signed

XML
---

The XML carrier inserts a namespaced ``<pact:manifest>`` element and optional
``<pact:locator>`` using the namespace ``urn:ncrypt-ai:pact:manifest:v1``.
Parsing uses a hardened XML parser that rejects external entities and other
unsafe constructs before carrier handling begins.

.. code-block:: python

   from pact import embed_xml_carrier, extract_xml_carrier

   protected = embed_xml_carrier(xml_document, signed, nonce=nonce, include_locator=True)
   extracted = extract_xml_carrier(protected)
   assert extracted.signed_manifest == signed

C2PA
----

C2PA is an industry standard for content credentials embedded directly in media
files. PACT uses it as a practical carrier — it helps metadata travel through
real image, PDF, and DOCX files in an interoperable way. PACT does not treat
C2PA validation as a trust decision by itself.

For useful background on C2PA's guarantees and limits, see:

- Official project: https://c2pa.org/
- Threat-model critique: https://lowentropy.net/posts/c2pa/
- Hacker Factor critique: https://www.hackerfactor.com/blog/index.php?/archives/1010-C2PAs-Butterfly-Effect.html

Supported image formats
~~~~~~~~~~~~~~~~~~~~~~~

For image formats supported by the official C2PA Python SDK, PACT creates a
full C2PA Manifest Store inside the asset:

.. code-block:: python

   from pact import C2paSignerMaterial, embed_c2pa_image, read_c2pa_asset

   signer = C2paSignerMaterial(certificate_chain_pem, private_key_pem)
   embedded = embed_c2pa_image(
       image_bytes, "image/png",
       signed=signed,
       signer_material=signer,
       title="Protected image",
   )
   inspected = read_c2pa_asset(embedded.asset_bytes, mime_type="image/png")
   assert inspected.active_manifest is not None

The signer material must satisfy the certificate requirements enforced by the
official C2PA SDK. PACT does not relax those requirements.

PDF and DOCX — prebuilt manifests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For PDF and ZIP-based document formats, PACT provides container writers that
place an already-signed manifest store into the spec-defined location:

- PDF uses an embedded file stream with ``/AFRelationship /C2PA_Manifest`` and
  a ``/AF`` entry in the catalog.
- ZIP-based formats (DOCX, etc.) use
  ``META-INF/content_credential.c2pa`` stored without compression.

.. code-block:: python

   from pact import embed_c2pa_manifest_in_pdf, embed_c2pa_manifest_in_zip_document

   protected_pdf  = embed_c2pa_manifest_in_pdf(pdf_bytes, manifest_store_bytes)
   protected_docx = embed_c2pa_manifest_in_zip_document(docx_bytes, "docx", manifest_store_bytes)

PDF and DOCX — hybrid signer path
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PACT also drives the official CAI signer path for document formats where the
Python wrapper does not expose signing directly. For DOCX it uses the builder
in ``no_embed`` mode and inserts the result via the container writer above. For
PDF it drives the builder to produce detached manifest bytes through the
official ``format_embeddable()`` helper, then inserts them:

.. code-block:: python

   from pact import C2paSignerMaterial, sign_c2pa_document

   signer = C2paSignerMaterial(certificate_chain_pem, private_key_pem)
   signed_pdf  = sign_c2pa_document(pdf_bytes,  "application/pdf", signed=signed, signer_material=signer, title="Protected PDF")
   signed_docx = sign_c2pa_document(docx_bytes, "docx",            signed=signed, signer_material=signer, title="Protected document")

Custom code in PACT is limited to container insertion. Manifest construction,
signing, and embeddable-manifest formatting come from the official SDK.

For legacy formats without an embedded-carrier path, PACT returns a detached
manifest store and leaves the original bytes unchanged.

C2PA text containers
~~~~~~~~~~~~~~~~~~~~

PACT provides a text-container layer aligned with the ``c2pa-text`` reference
implementation rather than defining its own wire format. Supported methods:

- Unicode variation-selector wrappers for unstructured plain text
- Structured manifest blocks for comment-friendly formats
- HTML ``<script type="application/c2pa">`` and ``<link rel="c2pa-manifest">``
  associations

PACT uses the reference package for encoding and parsing, then supplies the
Manifest Store bytes from its own detached-manifest signer.

.. code-block:: python

   from pact import C2paSignerMaterial, read_c2pa_text_asset, sign_c2pa_text_asset

   protected = sign_c2pa_text_asset(
       "# Notes\n", mime_type="text/markdown",
       signed=signed,
       signer_material=C2paSignerMaterial(certificate_chain_pem, private_key_pem),
       title="Protected notes",
   )
   inspected = read_c2pa_text_asset(protected.text, mime_type="text/markdown")
   assert inspected is not None
   assert inspected.validation.valid

TrustMark soft bindings
-----------------------

For JPEG, PNG, TIFF, and WebP, PACT can embed a 96-bit compact claim locator as
a TrustMark soft binding. The payload carries only a locator — not the manifest
signature — so recovering a locator from a transformed image gives a starting
point to look up the registry claim and then verify the signature, registry
record, and content binding separately. PACT uses a raw binary TrustMark payload
because the ECC mode provides insufficient capacity for a practical locator.

Alongside the TrustMark locator, PACT stores a perceptual fingerprint built from
multiple 64-bit perceptual hashes across deterministic views of the image:
original pixels, resize, center crops, recompression, and photo-style
resampling. This fingerprint is not a secret and is not a signature. It lets
a verifier match a transformed image against a registered claim even when the
embedded TrustMark has been removed or replaced.

.. code-block:: python

   from pact import (
       compare_image_perceptual_fingerprints,
       create_image_perceptual_fingerprint,
       decode_image_soft_binding,
       embed_image_soft_binding,
   )

   watermarked = embed_image_soft_binding(
       image_bytes, "image/png",
       claim_id=claim.claim_id,
       registry_root_fingerprint=claim.signed_manifest.manifest.registry_root_fingerprint,
   )
   decoded = decode_image_soft_binding(watermarked.image_bytes, "image/png")
   assert decoded.locator is not None

   original    = create_image_perceptual_fingerprint(image_bytes, "image/png")
   transformed = create_image_perceptual_fingerprint(transformed_bytes, "image/png")
   match = compare_image_perceptual_fingerprints(original, transformed)
   assert match.matched
