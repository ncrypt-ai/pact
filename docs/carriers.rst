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
