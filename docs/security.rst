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

The registry-level ``verify_claim`` path is the trust-clearinghouse view. It
combines manifest verification with registry inclusion, claimant trust tier,
revocation state, dispute state, claim meanings, and public evidence labels.
C2PA signatures, recovered watermarks, and perceptual hash matches are
reported as evidence signals; they do not authenticate ownership by
themselves.

Trust tiers currently distinguish unauthenticated device continuity, hosted
account status, domain verification, platform attestation, and third-party
attestation. Verification labels are evidence-based: ``verified_claim``,
``partial_match``, ``untrusted_claim``, ``disputed``, ``revoked``, or
``inconclusive``.

Key storage
-----------

Claimant keys use P-256 and are generated separately for each registry. The
preferred local store is the operating-system credential store. The explicit
fallback writes password-encrypted PKCS#8 PEM atomically with mode ``0600``.
PACT does not silently fall back from an unavailable OS credential store to
an unencrypted file.

Exported identities must be protected with a high-entropy password and moved
over a trusted channel. ``ClaimantIdentity.rotate`` creates a new key for the
same registry, and the registry core now supports old/new co-signed rotation
requests so a rotation can be published as an append-only registry event.

Registry privacy boundary
-------------------------

The signed manifest contains a salted commitment but not the nonce, original
content, unsalted content hash, or private key. The registry core persists
public events, claimant keys, signed manifest envelopes, revocations,
certificates, and dispute records, but it does not need private nonces or
private keys. Content carriers and evidence packages define how an authorized
verifier obtains a nonce.

``audit_signed_manifest_publication`` checks a signed manifest against local
content, nonce, and other private values before publication. It treats the
registry-scoped claimant key identifier and salted content commitment as public
disclosures, and reports private material such as nonces, raw content,
unsalted content hashes, private keys, probe contents, prompts, and provider
responses as errors. ``pact privacy audit`` exposes the same check from the
CLI.

Claim registration accepts only a signed manifest envelope. Extra fields such
as raw content, nonces, probe material, or responses are rejected before the
registry appends an event.

Registry challenge boundary
---------------------------

State-changing registry operations require:

- a server-issued replay challenge;
- a proof-of-work solution;
- a claimant signature over the exact challenge and mutation payload;
- for key rotation, signatures from both the current and replacement keys.

The in-process registry library enforces those rules before appending an
event. The future HTTP/API layer must preserve the same exact verification
boundary.

C2PA trust boundary
-------------------

The C2PA layer adds a second signature system with its own certificate-chain
requirements. A valid PACT manifest does not make a C2PA certificate trusted,
and a readable C2PA manifest store does not replace PACT content binding or
registry trust decisions.

Current scope
-------------

This implementation now provides a registry-core library layer, certificate
authority material generation, a FastAPI HTTP/API surface, HTML proof pages,
and a CLI entrypoint. It can also embed an already-built C2PA manifest store
into PDF and ZIP-based document containers, but it still does not generate
new spec-compliant C2PA manifest stores for PDF or OOXML through a first-class
official writer API. Instead, it uses the official CAI signer path in detached
mode and then applies official embeddable-manifest formatting plus local
container patching. Public-key trust and registry-root trust remain caller
decisions. The format and carrier schemes must receive an independent
cryptographic review before being declared stable.

CA handling
-----------

``pact registry init`` writes an encrypted offline root private key and the
online intermediate material required by the serving process. ``pact registry
serve`` loads only the public root certificate plus the intermediate key and
certificate; it does not require the offline root private key at runtime.

Current transport limitations
-----------------------------

The HTTP and HTML layer is present, but several production-hardening items
from the plan remain future work:

- strict CSRF and cookie-based browser auth flows;
- hardened CORS and Host/Origin policy;
- SSRF-safe live domain-verification fetches;
- resource-isolated worker processes for untrusted file handling;
- public batch-root timestamp publication;
- full hosted-browser consent and recovery UX.

The current transport layer should be treated as a functional foundation, not
as a finished internet-exposed service profile.
