PACT Manifest v1
================

A PACT manifest is a signed JSON object that binds a claimant identity, a
content commitment, and a policy declaration into a single portable artifact.
This document describes the format precisely enough to implement a compatible
reader or writer.

Signed envelope
---------------

A serialized signed manifest is RFC 8785 canonical JSON with exactly two
top-level members: ``manifest`` and ``signature``.

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
           "cawg.ai_generative_training": {"use": "notAllowed"},
           "pact.no_commercial_training": {"use": "notAllowed"}
         }
       },
       "claim_meanings": ["signed_by", "training_restriction"],
       "carriers": [],
       "watermarks": []
     },
     "signature": {
       "algorithm": "ES256",
       "key_id": "rfc7638-base64url-sha256",
       "value": "base64url-raw-r-and-s"
     }
   }

The signature covers only the canonical bytes of the ``manifest`` member. The
ES256 value is the fixed-width 64-byte ``R ‖ S`` representation used by JWS,
not an ASN.1 DER signature. Using RFC 8785 canonical JSON ensures the exact
byte sequence that was signed is deterministic regardless of how the JSON was
generated, which closes a class of attacks that exploit serialization ambiguity.

The ``claimant_key_id`` is an RFC 7638 JWK thumbprint: base64url-encoded
SHA-256 over the canonical JWK. This ties the identifier to the key material
itself rather than to a separately issued name, so a key cannot be relabeled
without invalidating existing references.

Content binding
---------------

The ``content_binding.commitment`` is computed as::

   SHA-256(nonce ‖ SHA-256(canonical_content))

The nonce is exactly 32 random bytes. It is intentionally absent from the
manifest so a registry can store the signed commitment without receiving the
content or an unsalted hash. This preserves privacy for private claims: an
observer with access to the registry cannot brute-force candidate content,
because the nonce salt is unknown to them.

When a claimant wants to allow public content verification, they include a
``content_nonce`` field in the manifest with the base64url-encoded nonce — any
party with the original content can then verify the commitment independently.
When they omit it, exact content verification requires the claimant to share
the nonce separately.

Canonicalization profiles
~~~~~~~~~~~~~~~~~~~~~~~~~

``pact.text.v1``
  Requires UTF-8 without a BOM, converts CRLF and CR line endings to LF, and
  normalizes text to Unicode NFC form. This ensures that identical prose
  produces the same hash regardless of platform line endings or composition
  form.

``pact.binary.v1``
  Preserves bytes exactly. No normalization is applied.

Claim meanings
--------------

``claim_meanings`` states what the claimant is asserting. PACT keeps these
values separate because a signature over a manifest does not automatically imply
authorship, ownership, licensing, or training-use evidence — making those
assertions explicit prevents a signed claim from being misread as broader proof
than the claimant intended.

Supported values:

``signed_by``
  The claimant key signed this manifest. This is the minimal implied claim.
  Manifests without a ``claim_meanings`` field parse as ``signed_by`` only.

``created_by``
  The claimant asserts they created the content.

``owned_by``
  The claimant asserts they own rights to the content.

``licensed_by``
  The claimant asserts they are a licensed user of the content.

``training_restriction``
  The manifest policy entries are intended training-use restrictions.

``suspected_training_use``
  The claimant is reporting suspected unauthorized training use of the content.

Policy
------

The ``policy`` block uses a ``cawg.training-mining`` label. The four CAWG keys
use their standard names. PACT extension keys use the ``pact.`` prefix.

Python uses ``not_allowed`` as the enum value while the serialized CAWG JSON
value is ``notAllowed``. A ``constrained`` entry requires explanatory text and
may include an absolute HTTP(S) licensing URL.

``pact.no_commercial_training`` is a separate, explicit machine-readable
marker for commercial training restrictions — distinct from the broader
``cawg.ai_generative_training`` key. This lets registries, crawlers, and
pipeline operators detect the restricted scope precisely without inferring it
from prose.

Parsing
-------

``SignedManifest.from_json`` rejects duplicate object keys, non-standard JSON
constants, unsupported versions or algorithms, malformed identifiers, and
invalid policy data before signature verification. These checks prevent a class
of confusion attacks where the same bytes parse differently in different
implementations.

Carrier and watermark fields
----------------------------

The ``carriers`` array records where the manifest is embedded in the associated
file. The ``watermarks`` array records which soft-binding or statistical
watermark methods were applied and the associated locator or detection
parameters.

These fields are informational. The signed manifest remains the authoritative
proof object. A carrier or watermark that points to the manifest is a recovery
aid; its absence does not invalidate the signature.

See :doc:`carriers <carriers>` for details on each carrier format.
