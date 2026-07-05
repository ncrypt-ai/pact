Security Model
==============

This document describes what PACT's cryptographic guarantees are, where the
privacy boundaries are, and what the trust model expects from each party.
For reporting vulnerabilities, see ``SECURITY.md``.

What verification establishes
-----------------------------

``verify_manifest`` checks three things independently:

1. Whether the supplied public JWK has the manifest's RFC 7638 key identifier.
2. Whether that key validates the ES256 signature over the RFC 8785 canonical
   manifest bytes.
3. When content and a nonce are available, whether
   ``SHA-256(nonce ‖ SHA-256(canonical_content))`` matches the signed
   commitment.

A valid report from ``verify_manifest`` establishes that the holder of a
specific registry-scoped key signed a specific content commitment. It does not
establish a unique human identity, copyright ownership, legal permission, or an
independently witnessed registration time.

``verify_claim`` adds registry-level evidence: inclusion in the registry log,
claimant trust tier, revocation state, dispute history, and C2PA validation.
These are combined into a ``VerificationLabel`` that says precisely what was
checked:

``content_claim_verified``
  Registry record is current, claimant signature is valid, supplied content
  matches the signed commitment.

``claim_verified_content_unchecked``
  Registry record and signature checked; no content was supplied for
  verification.

``claim_verified_content_private``
  Registry record and signature checked; content verification requires a nonce
  that was not supplied.

``content_mismatch``
  Registry record and signature are valid, but supplied content does not match
  the commitment.

``invalid_claim_signature``
  The signature does not validate against the declared key.

``disputed``
  The claim is subject to a current active dispute.

``revoked``
  The claimant has revoked the claim.

``inconclusive``
  Insufficient evidence to reach any of the above.

These labels are intentionally not collapsed. Applications should surface them
separately rather than reducing them to a single verified/not-verified result.

C2PA signatures, recovered watermarks, and perceptual hash matches are reported
as additional evidence signals alongside the registry labels. They inform a
human reviewer but do not by themselves authenticate ownership.

Training-use risk reports
-------------------------

``create_training_use_risk_report`` combines local probe analysis, text
watermark and canary detections, image watermark recovery, perceptual image
fingerprint matching, and registry verification into a single evidence package.
The score is an explanation aid. It is not a legal or technical assertion that a
provider trained on specific material.

Identity and key management
---------------------------

Claimant keys use P-256 and are generated separately per registry. The key
identifier is an RFC 7638 JWK thumbprint — deterministically derived from the
key material itself — so the same key always has the same identifier, and the
identifier cannot be transferred to a different key.

The preferred local store is the operating-system credential store. The
explicit fallback is a password-encrypted PKCS#8 PEM file written atomically
with mode ``0600``. PACT does not silently fall back from an unavailable OS
credential store to an unencrypted file. The password is never stored by PACT.

Identity exports use ``BestAvailableEncryption`` from the ``cryptography``
library, which applies PBKDF2-HMAC-SHA512 key derivation. Exported files should
be treated with the same care as private key material.

``ClaimantIdentity.rotate`` creates a new key for the same registry. Key
rotation requests require co-signatures from both the current and replacement
key, and are recorded as append-only events so the rotation history is
permanently auditable.

Device binding and spam resistance
------------------------------------

Every registered profile must include a ``pact-device-binding-v2`` token. This
is the minimum requirement for the ``unauthenticated_device`` trust tier. It
is not a high-trust signal, but the registry will not accept a profile without
it.

The token is derived through a blinded Ristretto255 OPRF, implemented by the
``oblivious`` library:

1. The CLI or browser workspace prepares local device material — hardware
   identifiers for the CLI, a combination of WebAuthn PRF output, profile
   passcode, and browser fingerprint values for the browser workspace.
2. That material is blinded with a local random scalar before leaving the
   device.
3. The blinded element is sent to ``/pact/api/v1/device-bindings/oprf``.
4. The registry evaluates the blinded element using its OPRF server secret and
   returns the evaluated point.
5. The final token is derived locally. The registry never sees the raw input,
   the local secret, or the derived token.

This makes casual duplicate-account creation on the same device difficult
without creating a persistent cross-registry tracking identifier. It is not
proof of a unique person. A determined actor with administrator access can
reset device identifiers, use a virtual machine, or reinstall the OS.

The trust tier model
---------------------

PACT defines four claimant trust tiers. Each tier requires specific registry
evidence and cannot be self-asserted by the claimant.

``unauthenticated_device``
  Minimum baseline. Requires a valid ``pact-device-binding-v2`` token in the
  signed profile registration mutation.

``hosted_account``
  Requires a registry admin to explicitly authorize the account. Intended for
  registries that gate higher trust behind identity verification or review.

``domain_verified``
  Requires a DNS TXT record proving control of a domain name, checked by the
  registry using its own DNS resolver. The registry records the verification
  event.

``third_party_attested``
  Requires a signed attestation from a third party whose key the registry
  trusts. The attestation is a registry event, not a free-text field.

Claimant certificates are registry-issued key material. Receiving a certificate
does not raise a claimant's trust tier; tiers are raised only by the specific
registry evidence described above.

Registry event log and challenge design
-----------------------------------------

Registry state is an append-only log of signed events. There is no in-place
update. Every mutation — profile registration, claim registration, revocation,
dispute, key rotation, domain verification — is a log entry.

State-changing operations require:

- A server-issued replay challenge with a short TTL.
- A proof-of-work solution meeting the challenge difficulty.
- A claimant ES256 signature over the exact challenge and mutation payload.

The challenge is consumed atomically by a ``DELETE ... RETURNING`` statement,
so a challenge cannot be used more than once even under concurrent requests.

Key rotation additionally requires co-signatures from both the current and
replacement key.

These requirements are enforced by both the registry library and the HTTP layer
before any event is appended.

Registry privacy boundary
--------------------------

The registry is designed to hold signed claims and public evidence, not private
content.

Before a manifest is published, ``audit_signed_manifest_publication`` checks
the manifest for:

- Raw content (always an error)
- Unsalted content hashes (always an error)
- Private nonce values (always an error)
- Private keys (always an error)
- Probe text, prompts, or provider responses (always an error)
- Public content nonces (reported as an intentional disclosure, not an error)

The HTTP claim-registration endpoint enforces the same checks server-side before
appending any event.

Profile registration accepts a signed mutation that includes the device-binding
token. The registry stores the token but never returns it in public profile
responses or proof pages.

Certificate authority setup
-----------------------------

``pact registry init`` generates two keys: an offline root key and an online
intermediate key. The offline root key signs the intermediate certificate at
initialization and is not required at runtime. ``pact registry serve`` loads only
the intermediate private key and the public root certificate.

The intermediate key signs claimant certificates. The root key is required only
to rotate the intermediate. Keep the root key encrypted and store it separately
from the intermediate key and the serving environment.

For AWS deployments, set ``PACT_OPRF_SERVER_SECRET`` to a high-entropy secret
independent of the CA material. If this variable is unset, the server derives a
fallback OPRF scalar from the intermediate CA key — which ties OPRF security to
CA key secrecy rather than to a separate secret.

Transport controls
------------------

The HTTP layer enforces:

- ``Host`` and ``Origin`` header validation against configured allowed values
- Per-IP and per-identity sliding-window rate limits
- Request body size limits enforced before parsing
- Content inspection with an application-level timeout
- Trusted-proxy CIDR validation before trusting forwarded IP headers

**Multi-instance note:** the in-process rate limiter does not coordinate across
multiple processes or Lambda execution environments. AWS deployments must attach
WAF rate limiting via ``deploy/aws/gateway-rate-limit.yaml``. See
:doc:`server <server>` for the full deployment checklist.

C2PA trust boundary
--------------------

C2PA is used as a carrier. A valid C2PA manifest inside a file does not make a
PACT claim trusted, and a readable C2PA manifest store does not replace PACT
content binding or registry trust decisions. The two systems are complementary,
not equivalent.

C2PA validation results are reported alongside registry labels, not instead of
them. The verification output keeps container credentials, registry state,
content binding, disputes, revocation, and C2PA validation as separate fields.

Useful references:

- Official C2PA project: https://c2pa.org/
- C2PA threat-model critique: https://lowentropy.net/posts/c2pa/
- Hacker Factor VIDA discussion: https://www.hackerfactor.com/blog/index.php?/archives/1028-VIDA-The-Simple-Life.html

Format stability
----------------

The PACT Manifest v1 format and carrier schemes are reviewable drafts. They
should receive independent cryptographic review before being treated as stable.
Do not rely on the current format for anything consequential until that review
is complete and stability is declared.
