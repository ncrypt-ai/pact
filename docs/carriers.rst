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

PDF and external manifests
~~~~~~~~~~~~~~~~~~~~~~~~~~

The C2PA specification defines PDF embedding via embedded file streams, but
the installed official Python builder does not currently write PDFs. PACT
therefore exposes two practical pieces today:

- reading existing C2PA credentials from PDFs via the official reader;
- creating an external-manifest reference bootstrap using the JUMBF media type
  ``application/c2pa`` and a provenance URI suitable for a repository-backed
  manifest workflow.

.. code-block:: python

   from pact import pdf_external_manifest_reference

   reference = pdf_external_manifest_reference(
       pdf_bytes,
       signed,
       manifest_uri="https://registry.example/manifests/claim.c2pa",
   )
   assert reference.media_type == "application/c2pa"
