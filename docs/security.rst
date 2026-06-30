Security Model
==============

What verification establishes
-----------------------------

``verify_manifest`` reports these checks independently:

- whether the supplied public JWK has the manifest's RFC 7638 key identifier;
- whether that key validates the ES256 signature;
- when content and either a public proof nonce or separately supplied private
  nonce are available, whether the content commitment matches.

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

``create_training_use_risk_report`` combines local probe analysis, text
watermark or canary detections, image watermark recovery, perceptual image
matches, and registry verification into one evidence report. The score is an
explanation aid, not a legal or technical assertion that a provider trained on
specific material.

Trust tiers distinguish unauthenticated device continuity, hosted
account status, domain verification, and third-party attestation. Claimant
certificates are registry-issued key material and do not raise trust tier.
Verification labels are evidence-based. ``content_claim_verified`` means the
registry claim is current, the claimant signature is valid, and supplied
content matches the signed commitment. ``claim_verified_content_unchecked``
means the registry claim and signature were checked, but no content was
checked. ``claim_verified_content_private`` means the claim is valid but the
content check needs a private nonce. ``content_mismatch``,
``invalid_claim_signature``, ``disputed``, ``revoked``, and
``inconclusive`` report the corresponding weaker or negative outcomes.

Identity and device continuity
------------------------------

Claimant keys use P-256 and are generated separately for each registry. The
preferred local store is the operating-system credential store. The explicit
fallback writes password-encrypted PKCS#8 PEM atomically with mode ``0600``.
PACT does not silently fall back from an unavailable OS credential store to
an unencrypted file.

Every registered claimant profile must include a signed
``pact-device-binding-v2`` token. This is the proof required for the baseline
``unauthenticated_device`` tier. The token does not grant elevated privileges,
but the registry will not accept a profile without it.

The CLI keeps local continuity state so one local device is normally bound to
one claimant identity per registry. It derives local fingerprint material from
harder-to-change local signals, but raw hardware and host values are not sent to
the registry.

The browser keeps the same privacy boundary. It uses WebAuthn PRF output as the
preferred local secret when the browser and authenticator support it. Otherwise
it falls back to the profile passcode and, only when no passcode is available,
a local random secret. It combines that local secret with local browser
fingerprint material and the registry-root fingerprint, then derives the final
token through the same blinded Ristretto OPRF flow used by the CLI.

The OPRF implementation uses the pure-Python ``oblivious`` package. The
registry receives a blinded Ristretto255 element and returns an evaluated
element; final token derivation happens locally. Raw browser traits, raw device
traits, passcodes, WebAuthn PRF output, and local HMAC input are not sent to the
registry.

This is spam resistance and device continuity, not proof of a unique person. A
determined user with administrator access can still change hardware identifiers,
run virtual machines, reinstall the OS, use another browser profile, or delete
local state. The goal is to make casual duplicate identity creation on the same
device difficult while avoiding a reusable cross-registry tracking identifier.

Exported identities must be protected with a high-entropy password and moved
over a trusted channel. ``ClaimantIdentity.rotate`` creates a new key for the
same registry, and the registry core supports old/new co-signed rotation
requests so a rotation can be published as an append-only registry event.

Registry privacy boundary
-------------------------

The signed manifest contains a nonce-bound commitment and may include a public
content-verification nonce. A public nonce lets anyone with candidate content
test whether it matches the signed commitment. Private nonce mode omits that
value, so the registry can verify the claim while exact content verification
requires the claimant to share the nonce separately. The signed manifest must
not contain original content, unsalted content hashes, private keys, or private
nonce values.

``audit_signed_manifest_publication`` checks a signed manifest against local
content, nonce, and other private values before publication. It treats the
registry-scoped claimant key identifier and salted content commitment as public
disclosures, treats intentional public content nonces as an info disclosure,
and reports private material such as private nonces, raw content, unsalted
content hashes, private keys, probe contents, prompts, and provider responses
as errors. ``pact privacy audit`` exposes the same check from the CLI.

Claim registration accepts only a signed manifest envelope. Extra fields such
as raw content, private nonces, probe material, or responses are rejected
before the registry appends an event.

Profile registration accepts a signed mutation that includes the private
device-binding token. The claimant signature prevents network tampering with
that token. The registry also rejects missing tokens and legacy arbitrary
fingerprint strings, so an unauthenticated profile still carries a minimum
device-continuity signal. The token is not presented as proof that a physical
device completed the OPRF endpoint; it is a privacy-preserving continuity
mechanism for honest clients.

Registry challenge boundary
---------------------------

State-changing registry operations require:

- a server-issued replay challenge;
- a proof-of-work solution;
- a claimant signature over the exact challenge and mutation payload;
- for key rotation, signatures from both the current and replacement keys.

The registry library and HTTP/API layer both enforce those rules before
appending an event.

C2PA trust boundary
-------------------

The C2PA layer adds a second signature system with its own certificate-chain
requirements. A valid PACT manifest does not make a C2PA certificate trusted,
and a readable C2PA manifest store does not replace PACT content binding or
registry trust decisions.

Useful references:

- official C2PA project: https://c2pa.org/
- C2PA threat-model critique: https://lowentropy.net/posts/c2pa/
- Hacker Factor VIDA discussion: https://www.hackerfactor.com/blog/index.php?/archives/1028-VIDA-The-Simple-Life.html

PACT treats those concerns as product requirements: verification reports should
say what was checked, avoid implying authorship or ownership from a container
credential alone, and preserve separate signals for registry state, content
binding, disputes, revocation, and C2PA validation.

Current scope
-------------

PACT provides a registry-core library layer, certificate authority material
generation, a FastAPI HTTP/API surface, HTML proof pages, and a CLI entrypoint.
It can also embed an already-built C2PA manifest store
into PDF and ZIP-based document containers, but it still does not generate
new spec-compliant C2PA manifest stores for PDF or OOXML through a first-class
official writer API. Instead, it uses the official CAI signer path in detached
mode and then applies official embeddable-manifest formatting plus local
container patching. Public-key trust and registry-root trust remain caller
decisions. The format and carrier schemes should receive independent
cryptographic review before they are treated as stable.

CA handling
-----------

``pact registry init`` writes an encrypted offline root private key and the
online intermediate material required by the serving process. ``pact registry
serve`` loads only the public root certificate plus the intermediate key and
certificate; it does not require the offline root private key at runtime.

Current transport limits
------------------------

The HTTP layer rejects oversized request bodies before parsing, reads uploads
with an application-level byte limit, applies ZIP metadata checks before
parsing ZIP-like carriers, and runs inspection parsing with a timeout. Public
``inspect`` and ``recover`` remain available because they are proof and review
workflows, but they use stricter anonymous request limits than normal metadata
reads.

Forwarded client IP headers are ignored unless the immediate peer is explicitly
configured as a trusted proxy. If the app is reachable directly, clients cannot
move rate-limit buckets by sending ``X-Forwarded-For`` themselves.

These controls are still not a replacement for production operator controls:

- gateway or load-balancer rate limits, especially for mutation routes;
- strict CORS and Host/Origin configuration for the actual deployment;
- careful logging policy for inspection uploads;
- separate worker/process isolation for untrusted file handling at larger scale;
- backup and rotation procedures for registry CA material, databases, and the
  dedicated OPRF server secret;
- public communication about disputes, takedowns, and retention.

The AWS templates include WAF rate-limit scaffolding, but operators still need
to connect it to their existing API Gateway or ALB and confirm the resulting
behavior in their account.
