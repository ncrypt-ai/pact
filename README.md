# PACT

[![Version](https://img.shields.io/badge/version-0.0.2-blue)](pyproject.toml)
[![Stage](https://img.shields.io/badge/stage-pre--alpha-orange)](README.md#status-and-license)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Production site:** [https://ncryptai.com/pact](https://ncryptai.com/pact)

**Policy Authenticated Content Token** — a toolkit for signing content claims,
attaching them to files, and verifying them against a trust registry.

Most content provenance tools collapse a complicated question into a single
indicator: signed, or not signed. That design fails the moment you ask what the
signature actually proves. For example, a C2PA manifest tells you that a key signed some
content. It says nothing about whether the signer registered the claim, whether
it has been disputed or revoked, whether the credential in the file matches the
one the signer published, or whether the signature implies ownership or
authorship. While there have been many critiques of C2PA and its pitfalls, two I found
particularly interesting/accessible are
[Low Entropy's C2PA threat-model critique](https://lowentropy.net/posts/c2pa/) and
[Hacker Factor's C2PA Butterfly Effect](https://www.hackerfactor.com/blog/index.php?/archives/1010-C2PAs-Butterfly-Effect.html).

PACT is built around a different model. Rather than one badge, it gives
verifiers a set of independent signals: the claimant signature, the registry
record, the content binding, the revocation state, the dispute history, and the
trust tier. Each is reported separately. Applications decide which signals matter
for their context.

---

## What a claim establishes

A valid PACT claim means a specific registry-scoped key signed a specific
content commitment, and a specific registry recorded that event. The content
commitment is computed as:

```
commitment = SHA-256(nonce ‖ SHA-256(canonical_content))
```

When a verifier has both the content and the nonce (a random value intended to be
used only once in a given cryptographic context), they can confirm the content
matches what was signed. That is the full extent of what the cryptography proves.
A claim does **not** establish that the claimant created or owns the content, that
the claimant is a unique person, or that a C2PA container credential is trustworthy
by itself.

PACT keeps these questions separate. Verification labels say exactly what was
checked (`content_claim_verified`, `claim_verified_content_unchecked`,
`claim_verified_content_private`, `disputed`, `revoked`, `content_mismatch`)
so downstream systems can reason about each without collapsing them into a single
result.

---

## Training policy, not AI detection

PACT is not trying to prove that a file was or was not made by AI. The project
is aimed at a narrower problem: helping legitimate content owners and claimants
attach a signed, machine-readable policy to their work, publish a registry
record for that policy, and later show whether the policy, claim, or carrier was
removed, disputed, copied, or ignored.

Training policy entries such as `pact.no_commercial_training` and
`training_restriction` express what the claimant is allowing or refusing. They
do not prove copyright ownership by themselves, and they do not automatically
make a legal conclusion. They create a durable technical record: who signed the
policy, what content commitment it was bound to, which registry recorded it, and
whether later verification still supports that record. It is intended to help
content owners and authorized claimants communicate machine-readable restrictions,
and bypassing, removing, suppressing, falsifying, or stripping PACT manifests,
watermarks, locators, registry proofs, or policy metadata may be a legally
significant act in addition to a technical act.

---

## Trust tiers

PACT separates the claim from the claimant's level of supporting evidence. A
new profile starts at the `unauthenticated_device` tier, which means it has a
valid device-binding token but has not proven much else to the registry owner. A
registry can raise a profile to `hosted_account`, `domain_verified`, or
`third_party_attested` only after recording the required evidence, such as admin
review, DNS control, or a trusted third-party attestation respectively.

Trust tiers are context, not a truth label. A higher tier can make a claimant
more credible, but it still does not prove authorship, ownership, or that a file
is genuine. Verification reports keep the tier visible alongside the signature,
content binding, revocation state, and dispute history. See `docs/security.rst`
for the full trust-tier model.

---

## Key design decisions

**Registry-scoped identities.** Each claimant key is generated separately per
registry. The key identifier (an RFC 7638 JWK thumbprint) is specific to one
registry and cannot link activity across registries. This prevents cross-registry
user tracking at the cost of requiring a separate identity per registry.

**Salted content commitments, not content hashes.** The registry stores
`SHA-256(nonce ‖ SHA-256(content))`, not a raw content hash. The 32-byte nonce
stays with the claimant, not in the registry. This means the registry can hold
a signed claim without receiving the work, and an observer cannot reverse-lookup
content from the published commitment. A claimant who wants to allow public
content verification (allowing others to verify not just that the manifest is valid
but that it is tied to a specific piece of content) can publish the nonce explicitly;
otherwise they share it privately with specific verifiers.

**Blinded OPRF for device binding.** Profile registration requires a
`pact-device-binding-v2` token, which is effectively a device/browser fingerprint.
Rather than sending raw device or browser fingerprints to the registry, the CLI and
browser workspace use a blinded Ristretto255 OPRF: local material is blinded before it
leaves the device, the registry evaluates the blinded point, and the final token is
derived entirely locally. The registry evaluates without seeing the input or the derived
token. This is an attempt to introduce some measure of spam resistance and profile
continuity (thought it is not proof of a unique person), while keeping sensitive user
information private.

**Explicit claim meanings.** An ES256 signature proves a key signed a manifest,
nothing more. PACT requires explicit `claim_meanings` fields
(`signed_by`, `created_by`, `owned_by`, `licensed_by`, `training_restriction`,
`suspected_training_use`) so verification never implies authorship or ownership
from a signature alone.

**C2PA as a carrier, not a trust anchor.** PACT uses C2PA where it helps move
metadata through real files such as images, PDFs, DOCX. It does not treat a valid C2PA
manifest as sufficient for a trust decision. The PACT registry record, claimant
identity evidence, revocation state, and dispute history are the trust signals.
C2PA validation is one more signal alongside them.

**Append-only event log.** Registry state is a log of signed events with Merkle
batch disclosure. There is no in-place update, and revocations, disputes, key
rotations, and domain verifications are events layered on the original claim
record. The registries full history is publicly verifiable.

---

## What is included

- Registry-scoped P-256 identities with OS keyring or password-encrypted PKCS#8
  fallback
- Signed PACT Manifest v1 JSON using RFC 8785 canonical JSON and ES256
- Machine-readable training policies such as `pact.no_commercial_training`
- Plain text, HTML, XML, C2PA image, PDF, DOCX, and image carrier helpers
- Privacy audit that rejects raw content, private nonces, probe text, and
  provider responses before registry publication
- FastAPI registry with profiles, claims, revocation, disputes, key rotation,
  public proof pages, and a browser workspace
- `pact` CLI for identity, signing, verification, inspection, privacy audits,
  watermarking, probes, and local registry operation
- Templates for deploying the registry to AWS behind an existing API Gateway, load
  balancer, and Cognito authorizer

---

## Install

```bash
uv sync --locked
```

Optional dependency groups:

```bash
uv sync --locked --extra server          # FastAPI registry and proof pages
uv sync --locked --extra web             # browser workspace
uv sync --locked --extra c2pa            # C2PA image, PDF, and document carriers
uv sync --locked --extra image-watermark # TrustMark soft binding
uv sync --locked --extra aws             # Lambda/Postgres support
```

---

## Quick CLI flow

**Create an identity.** Keys are registry-scoped (one per registry).

```bash
pact identity init \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'your-password'
```

**Register the profile:**

```bash
pact registry register-profile \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'your-password'
```

**Sign a file.** Produces `<filename>.manifest.json` and `<filename>.nonce`. Keep
the nonce as it is required for private content verification and must not go to
the registry.

```bash
pact sign ./work.txt \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'your-password'
```

**Publish the signed manifest:**

```bash
pact registry register-claim ./work.txt.manifest.json \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'your-password'
```

**Verify later:**

```bash
pact verify ./work.txt.manifest.json --content ./work.txt
```

Pass `--private-nonce ./work.txt.nonce` to also confirm the content binding.
Without the nonce, verification confirms the registry record and claimant
signature but reports the content check as `claim_verified_content_private`.

---

## Operations reference

**Sign** creates a local signed manifest for a file. It does not publish
anything. The signer keeps the original file, the manifest, and any private
nonce needed for later content verification. Users can optionally choose to
include both visible and invisible carriers/watermarks in the original file.

**Register** publishes a signed registry event. `pact registry register-profile`
publishes the claimant's public profile so the registry knows that key.
`pact registry register-claim` publishes a signed manifest under that profile.
Registration does not upload the original file.

**Verify** checks a manifest and reports each signal separately: signature,
content binding, registry claim status, revocation, disputes, and policy. With
content and the required nonce, verification can confirm the file matches the
signed commitment. Without them, it can still report signature and registry
status without claiming the content was checked.

**Recover** starts from a carrier or file and tries to find PACT metadata or a
registry reference inside it. Recovery is discovery. It can point you to a claim
or proof page, but the result still needs verification before it should be
treated as proven.

---

## Local registry and browser workspace

```bash
pact registry init \
  --registry http://127.0.0.1:8000 \
  --data-dir ./.pact-dev \
  --root-key-password 'store-this-offline'

pact registry serve \
  --registry http://127.0.0.1:8000 \
  --data-dir ./.pact-dev \
  --public-base-url http://127.0.0.1:8000 \
  --database ./.pact-dev/registry.sqlite3 \
  --enable-workspace
```

Open `http://127.0.0.1:8000/pact` for the landing page, or
`http://127.0.0.1:8000/pact/web` for the browser workspace.

The browser workspace runs PACT's Python logic in Pyodide inside a Web Worker.
Signing is entirely local; only the signed manifest JSON is sent to the registry.
Raw file content never leaves the browser.

Registry administrators are PACT identities whose public JWK is loaded at
startup. Create an admin identity, export its public key, and pass it to serve:

```bash
pact identity init \
  --registry http://127.0.0.1:8000 \
  --identity-file ./.pact-dev/admin.pem \
  --identity-password 'change-this'

pact identity public-jwk \
  --registry http://127.0.0.1:8000 \
  --identity-file ./.pact-dev/admin.pem \
  --identity-password 'change-this' \
  --out ./.pact-dev/admin.public.jwk.json

pact registry serve ... \
  --admin-jwk-file ./.pact-dev/admin.public.jwk.json
```

---

## Documentation

| Document | Contents |
|---|---|
| `docs/quickstart.rst` | End-to-end setup and first claim, Python API examples |
| `docs/manifest.rst` | Signed envelope format, content binding, policy schema |
| `docs/carriers.rst` | Text, HTML, XML, C2PA, image carrier details |
| `docs/security.rst` | Verification model, privacy boundaries, CA handling |
| `docs/server.rst` | Monolith and AWS deployment, admin setup, WAF config |
| `docs/tpm.rst` | Technological protection measure specification |
| `docs/legal.rst` | What policy entries mean and what they don't |
| `docs/api.rst` | Full Python API reference |

```bash
uv run sphinx-build -W -b html docs docs/_build/html
```

---

## Development

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run python -m pytest tests -q
uv run sphinx-build -W -b html docs docs/_build/html
uv build
```

LLM assistance is permitted for contributions, but every submitted change must
have human review, testing, and a named owner. See `CONTRIBUTING.md`.

---

## Status and license

PACT is **pre-alpha**. The manifest format and carrier schemes are reviewable
drafts, not stable standards. While I made a best-effort to rely only on reputable
and open source cryptography libraries, this package has not yet had an independent
cryptographic review. Relying on the current format for anything consequential is at
the users own risk.

Apache-2.0. See `LICENSE` and `NOTICE`.
