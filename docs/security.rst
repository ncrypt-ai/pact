Security Model
==============

What verification establishes
-----------------------------

``verify_manifest`` reports these checks independently:

- whether the supplied public JWK has the manifest's RFC 7638 key identifier;
- whether that key validates the ES256 signature;
- when content and its nonce are supplied, whether the content commitment
  matches.

A valid report establishes that the holder of a registry-scoped claimant key
signed a commitment to particular canonical content. It does not establish a
unique human identity, copyright ownership, legal permission, registry trust,
or an independently witnessed registration time.

Key storage
-----------

Claimant keys use P-256 and are generated separately for each registry. The
preferred local store is the operating-system credential store. The explicit
fallback writes password-encrypted PKCS#8 PEM atomically with mode ``0600``.
PACT does not silently fall back from an unavailable OS credential store to
an unencrypted file.

Exported identities must be protected with a high-entropy password and moved
over a trusted channel. ``ClaimantIdentity.rotate`` creates a new key for the
same registry; co-signed registry rotation records belong to the registry
implementation step and are not yet available.

Registry privacy boundary
-------------------------

The signed manifest contains a salted commitment but not the nonce, original
content, unsalted content hash, or private key. The future registry must not
request or persist those values. Content carriers and evidence packages will
define how an authorized verifier obtains a nonce.

Current scope
-------------

This implementation does not yet provide a registry, certificate authority,
PDF/image carriers, C2PA integration, CLI, or web UI. Public-key trust and
registry-root trust remain caller decisions. The format and carrier schemes
must receive an independent cryptographic review before being declared stable.
