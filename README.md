# PACT

PACT stands for Policy Authenticated Content Token.

PACT is a Python toolkit for policy-bound content claims and machine-readable
rights enforcement.

The package version in this repo is `0.0.1`. It is currently pre-alpha.
User-visible changes are tracked in `CHANGELOG.md`. Tagged releases should map
to the package version in `pyproject.toml`.

It covers four parts of the problem:

- registry-scoped claimant identities
- signed manifests over canonicalized content
- carrier formats for attaching those manifests to files
- registry and verification surfaces for publishing and checking claims

In practice, PACT is trying to give developers a way to say:

- this key signed this claim
- this claim is bound to this exact content commitment
- this work carries these policy assertions
- this registry has or has not seen, revoked, disputed, or attested to that claim

Current surface area:

- P-256 claimant identities with OS keyring or encrypted-file storage
- RFC 8785 canonical JSON manifests with ES256 signatures
- text, HTML, and XML carriers
- C2PA helpers for supported image, PDF, DOCX, and text workflows
- append-only registry services with challenges, proof-of-work, certificate issuance, key rotation, revocation, disputes, and verification labels
- FastAPI registry app and `pact` CLI
- optional image watermark, text watermark, privacy-audit, and training-use probe tooling

PACT treats C2PA as an interoperability layer and evidence carrier, not as the trust model.

The design is intentionally conservative about what it claims to prove. A lot
of provenance systems fail by collapsing different questions into one result:
who signed something, who created it, who owns it, whether it was edited,
whether a container still has a readable credential, and whether any of that
should be trusted. PACT keeps those separate.

It is also trying to avoid a few predictable failure modes:

- treating a valid signature as proof of authorship or ownership
- treating a readable C2PA asset as proof of trust
- treating content provenance as a detector for whether something is "real" or "AI"
- binding trust to opaque central services instead of explicit registry state and evidence
- leaking raw content, nonces, prompts, or other private material into public registry records
- silently weakening key storage or verification boundaries for convenience

What a valid manifest proves:

- a registry-scoped claimant key signed the manifest
- if you supply the original content and nonce, the content commitment matches

What it does not prove:

- that content is "real"
- that a claimant is a unique human
- authorship, ownership, or licensing by signature alone
- trust in a C2PA asset by itself

## Install

```bash
uv sync --locked
```

Optional features:

```bash
uv sync --locked --extra c2pa
uv sync --locked --extra image-watermark
uv sync --locked --extra aws
```

Requires Python `>=3.11`.

## Quick start

Create an identity:

```bash
pact identity init \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Show the public JWK for that identity:

```bash
pact identity show \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Sign a file:

```bash
pact sign ./work.txt \
  --registry https://registry.example \
  --registry-root-fingerprint AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
  --output ./work.manifest.json \
  --nonce-out ./work.nonce \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Verify a manifest:

```bash
pact verify ./work.manifest.json \
  --public-jwk ./public_jwk.json \
  --content ./work.txt \
  --nonce ./work.nonce
```

Run the local registry/web app:

```bash
pact web --data-dir ./.pact-dev --port 8000
```

## Library example

```python
import secrets

from pact import (
    CanonicalizationProfile,
    ClaimantIdentity,
    Manifest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    base64url_encode,
    sign_manifest,
    verify_manifest,
)

content = b"An original work.\n"
nonce = secrets.token_bytes(32)
identity = ClaimantIdentity.generate("https://registry.example")
policy = Policy(
    (
        PolicyEntry(
            Permission.GENERATIVE_TRAINING,
            PermissionValue.NOT_ALLOWED,
        ),
    )
)

manifest = Manifest.create(
    identity=identity,
    registry_root_fingerprint=base64url_encode(bytes(32)),
    content=content,
    mime_type="text/plain",
    canonicalization=CanonicalizationProfile.TEXT_V1,
    policy=policy,
    nonce=nonce,
)
signed = sign_manifest(manifest, identity)
report = verify_manifest(signed, identity.public_jwk, content, nonce)
assert report.valid
```

## Development

Run the checks used by this repo:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run coverage run -m pytest
uv run coverage report
uv run sphinx-build -W -b html docs docs/_build/html
uv build
```

Docs live in `docs/`. The local API and proof-page app is in `src/pact/web/`.

## Releases

- Package name: `pact`
- Current version in this repo: `0.0.1`
- Status: pre-alpha
- Release notes: `CHANGELOG.md`

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
