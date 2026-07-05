# Security Policy

## Supported versions

Security fixes are applied to the latest released version. PACT is pre-alpha;
public APIs, deployment templates, and carrier formats may change when a
security issue requires it.

## Reporting a vulnerability

Do not report vulnerabilities in a public issue. Use GitHub's private
security-advisory feature for this repository.

Include in your report:

- Affected version or commit
- Affected component (CLI, registry API, browser workspace, carrier format, or
  deployment template)
- Reproduction steps
- Expected and observed behavior
- Whether private content, keys, nonces, device material, or registry secrets
  can be exposed
- Suggested mitigation, if you have one

You should receive acknowledgement within seven days. Disclosure timing will be
coordinated after the issue is assessed and a fix is available.

---

## Security model

### What PACT verifies, and what it does not

A valid PACT claim establishes that a specific registry-scoped ES256 key signed
a specific content commitment, and that a specific registry recorded that event.
Nothing more.

A valid claim does **not** establish that:

- the claimant is who they claim to be, or a unique person
- the claimant authored or owns the content
- a C2PA container credential in the same file is trustworthy

Verification labels say exactly what was checked. `content_claim_verified` means
the registry record is current, the signature is valid, and the supplied content
matches the signed commitment. `claim_verified_content_unchecked` means the
registry and signature were checked, but no content was verified.
`claim_verified_content_private` means the claim is valid but the content check
requires a nonce that was not supplied. `disputed`, `revoked`, `content_mismatch`,
and `invalid_claim_signature` report the corresponding negative outcomes.
Applications should surface these labels rather than collapsing them.

### Cryptographic design

PACT manifests use ES256 (P-256 / SHA-256 ECDSA) with a fixed-width 64-byte
`R ‖ S` signature value. Before signing, the `manifest` object is serialized
to RFC 8785 canonical JSON so the exact byte sequence signed is deterministic
regardless of how the JSON was generated or formatted. This closes a class of
attacks that exploit ambiguity in non-canonical serialization.

Claimant key identifiers use RFC 7638 JWK thumbprints (base64url-encoded
SHA-256 over the canonical JWK). This ties the identifier to the key material
itself rather than to a separately issued name, so a key cannot be relabeled
without invalidating existing references.

Content commitments use a salted double-hash:

```
commitment = SHA-256(nonce ‖ SHA-256(canonical_content))
```

The 32-byte nonce is generated locally and never sent to the registry without the
users explicit choice to opt into publicly verifiable content commitments. This
serves two purposes. First, the registry holds evidence of what was signed
without receiving the content, preserving privacy for private claims. Second, an
adversary with access to the registry's stored commitments cannot brute-force
private candidate content, because the nonce salt is unknown to them.

State-changing operations require a server-issued replay challenge, a
proof-of-work solution, and a claimant ES256 signature over the exact challenge
and mutation payload. Key rotation requires co-signatures from both the current
and replacement keys, and the registry records the rotation as an append-only
event rather than overwriting the original profile. The library and HTTP layers
both enforce these rules before appending any event.

### Privacy boundary

The registry is designed to hold signed claims and public evidence, not private
content. Before any manifest is published, `audit_signed_manifest_publication`
checks that the manifest does not contain raw content, unsalted content hashes,
private nonce values, private keys, probe text, prompts, or provider responses.
The HTTP API enforces the same checks server-side on claim registration.

When a claimant wants to allow public content verification, they include a
public nonce in the manifest — anyone with the content can then verify the
commitment. When they do not include a public nonce, exact content verification
requires the claimant to share the nonce separately. The registry cannot
distinguish between the two except by the presence or absence of the public
nonce field.

Public profile responses and proof pages never expose stored device-binding
tokens, private nonces, or internal registry state beyond what is explicitly
documented as public.

### Identity storage

PACT generates a separate P-256 key for each registry. The key identifier is
an RFC 7638 JWK thumbprint that is specific to one registry and cannot be used
to correlate activity across registries.

The preferred local store is the operating-system credential store. The explicit
fallback is a password-encrypted PKCS#8 PEM file written atomically with mode
`0600`. PACT does not silently fall back from an unavailable OS credential store
to an unencrypted file. The password is never stored by PACT.

Identity exports use `BestAvailableEncryption` from the `cryptography` library,
which currently maps to AES-256-CBC with PBKDF2-HMAC-SHA512. Exported identity
files should be treated as sensitive material and protected accordingly.

### Device binding

Every registered claimant profile must include a `pact-device-binding-v2` token
as a baseline device-continuity signal. This token qualifies the profile for the
`unauthenticated_device` trust tier. It does not grant elevated privileges, but
the registry rejects profiles without it.

The token is derived through a blinded Ristretto255 OPRF flow backed by the
`oblivious` library. The CLI and browser workspace derive local device material
(hardware identifiers for the CLI, a combination of WebAuthn PRF output, profile
passcode, and browser fingerprint values for the browser workspace), blind it
before it leaves the device, send the blinded element to the OPRF endpoint,
receive an evaluated element, and derive the final token locally. The registry
evaluates the blinded element without seeing the raw input, the derived token,
or the local secret used to blind it.

This is spam resistance and continuity, not proof of a unique person. A
determined actor with administrator access can still reset hardware identifiers,
use a virtual machine, or create a new browser profile. The mechanism raises the
practical cost of casual duplicate-account creation on the same device while
avoiding a persistent cross-registry tracking identifier.

### Certificate authority

`pact registry init` generates an offline root key and an online intermediate
key. The offline root key encrypts the intermediate certificate at initialization
time and is not needed at runtime. `pact registry serve` loads only the
intermediate private key and the public root certificate. The intermediate key
signs claimant certificates; the root key is required only to rotate the
intermediate.

The intermediate private key is the most sensitive secret in a self-hosted
registry deployment. It should be stored in a secret manager, rotated on a
documented schedule, and never committed to source control or baked into a
container image.

For AWS deployments, set `PACT_OPRF_SERVER_SECRET` to a dedicated high-entropy
secret separate from the registry CA material. If this variable is unset, the
server derives a fallback from the intermediate CA key meaning the OPRF
security is then tied to CA key secrecy rather than to an independent secret.

### Transport and rate limiting

The HTTP layer validates `Host` and `Origin` headers against configured allowed
values, enforces per-IP and per-identity sliding-window rate limits, rejects
oversized request bodies before parsing, and runs content inspection with an
application-level timeout. The `X-Forwarded-For` header is ignored unless the
immediate peer is explicitly configured as a trusted proxy CIDR, so clients
cannot shift their rate-limit bucket by spoofing forwarding headers.

**Important for multi-instance deployments:** the in-process rate limiter does
not coordinate across multiple processes or Lambda execution environments. AWS
deployments must attach WAF rate limiting via `deploy/aws/gateway-rate-limit.yaml`.
The in-process limiter is defense-in-depth only in those configurations.

---

## What to report

Please report any path that exposes or allows the following:

- Plaintext content for a private claim
- Private nonces, private keys, or decrypted identity material
- Raw browser or hardware fingerprint source material sent to the registry
- Prompts, probe text, provider responses, or private evidence packages
- Registry CA private keys or deployment secrets (`PACT_OPRF_SERVER_SECRET`,
  intermediate private key material)
- Proof-of-work bypass or challenge replay
- Privilege escalation from `unauthenticated_device` to a higher trust tier
  without the corresponding registry evidence
- Signature verification bypass in `verify_manifest` or `verify_claim`
- Any path where a registry stores content it should not

Also report cases where the product misrepresents what was verified — for
example, showing `content_claim_verified` without actually confirming the
content hash, or presenting a C2PA credential as proof of authorship.

## Out of scope

PACT does not determine whether content is real, AI-generated, legally owned,
or legally licensed. Reports about those limitations are useful only when the
product actively misrepresents them.

Watermark robustness, statistical probe sensitivity, and training-detection
accuracy are research questions with inherent uncertainty. Reports framing these
as security vulnerabilities will be treated as feedback rather than
vulnerabilities unless a specific bypass allows a claimant to falsely register a
detection or hide a clear positive.
