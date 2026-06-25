PACT Manifest v1
================

Signed envelope
---------------

A serialized signed manifest is RFC 8785 canonical JSON with two top-level
members:

.. code-block:: json

   {
     "manifest": {
       "version": "1",
       "claim_id": "018f7f79-7b42-7c00-8000-000000000001",
       "registry_url": "https://registry.example",
       "registry_root_fingerprint": "base64url-sha256",
       "claimant_key_id": "rfc7638-base64url-sha256",
       "mime_type": "text/plain",
       "canonicalization": "pact.text.v1",
       "content_binding": {
         "algorithm": "sha256-nonce-sha256",
         "commitment": "base64url-sha256"
       },
       "policy": {
         "label": "cawg.training-mining",
         "entries": {
           "cawg.ai_generative_training": {"use": "notAllowed"}
         }
       },
       "carriers": [],
       "watermarks": []
     },
     "signature": {
       "algorithm": "ES256",
       "key_id": "rfc7638-base64url-sha256",
       "value": "base64url-raw-r-and-s"
     }
   }

The signature covers only the canonical bytes of the ``manifest`` member.
The ES256 value is the fixed-width 64-byte ``R || S`` representation used by
JWS, not an ASN.1 DER signature.

Content binding
---------------

PACT v1 computes the commitment as::

   SHA-256(nonce || SHA-256(canonical_content))

The nonce is exactly 32 random bytes. It is intentionally absent from the
manifest so a registry can store the signed commitment without receiving the
nonce or an unsalted content hash. A carrier or private evidence package must
provide the nonce when a verifier is expected to validate content.

The ``pact.text.v1`` profile requires UTF-8 without a BOM, converts CRLF and
CR endings to LF, and normalizes text to Unicode NFC. The
``pact.binary.v1`` profile preserves bytes exactly.

Policy values
-------------

The four CAWG keys use their standard names. PACT extensions use the
``pact.`` prefix. Python uses ``not_allowed`` while the serialized CAWG value
is ``notAllowed``. A constrained entry requires explanatory text and can
include an absolute HTTP(S) licensing URL.

Parsing
-------

``SignedManifest.from_json`` rejects duplicate object keys, non-standard JSON
constants, unsupported versions or algorithms, malformed identifiers, and
invalid policy data before verification.

Carrier formats
---------------

Step 2 adds carrier helpers for ``pact.text.v1`` manifests:

- plain text can embed a visible manifest block, an invisible zero-width
  locator, or both;
- HTML inserts an escaped ``application/pact+json`` block in ``<head>`` and
  can optionally carry the zero-width locator in a hidden element;
- XML inserts namespaced ``pact:manifest`` and optional ``pact:locator``
  elements using ``urn:ncrypt-ai:pact:manifest:v1``.

The locator contains the claim UUID, registry-root fingerprint, nonce,
manifest digest, and checksum. It helps recover or cross-check a claim, but it
does not replace manifest verification.
