# PACT

Policy Authenticated Content Token.

PACT is policy-bound content for machine-readable rights enforcement. It is a
Python toolkit for signing content claims, attaching those claims to files, and
checking them against registry evidence.

PACT is not a detector for whether content is real, fake, edited, or AI
generated. It is a way to make specific claims about content explicit,
portable, and verifiable.

## What it does

PACT gives developers primitives for answering narrower questions:

- which registry-scoped key signed this claim
- which content commitment the claim is bound to
- which policy assertions the claimant attached to the work
- whether a registry has seen, revoked, disputed, or attested to the claim

The current implementation includes:

- P-256 claimant identities with OS keyring or encrypted-file storage
- RFC 8785 canonical JSON manifests with ES256 signatures
- text, HTML, and XML carriers
- C2PA helpers for supported image, PDF, DOCX, and text workflows
- append-only registry services with replay challenges, proof-of-work,
  certificate issuance, key rotation, revocation, disputes, and verification
  labels
- a FastAPI registry app and `pact` CLI
- optional image watermark, text watermark, privacy-audit, and training-use
  probe tooling

## Trust model

PACT treats C2PA as an interoperability layer and evidence carrier, not as the
source of trust.

A valid PACT manifest proves:

- a registry-scoped claimant key signed the manifest
- when content and nonce are supplied, the content commitment matches

It does not prove:

- that the content is real
- that the claimant is a unique human
- that the claimant authored or owns the content
- that the attached policy is legally enforceable
- that a readable C2PA asset is trustworthy by itself

The point is to avoid collapsing different questions into one result. Signing,
authorship, ownership, policy intent, registry state, revocation, disputes, and
container-level credentials are separate signals.

PACT is designed to avoid these failure modes:

- treating a valid signature as proof of authorship or ownership
- treating a readable C2PA asset as proof of trust
- presenting provenance as an AI-content detector
- relying on opaque central services instead of explicit registry state
- publishing raw content, nonces, prompts, or private evidence to the registry
- silently weakening key storage or verification for convenience

## Version and releases

- Package: `pact`
- Current version: `0.0.1`
- Status: pre-alpha
- Python: `>=3.11`
- Release notes: `CHANGELOG.md`

Tagged releases should match the package version in `pyproject.toml`.

## Install

```bash
uv sync --locked
```

Optional extras:

```bash
uv sync --locked --extra c2pa
uv sync --locked --extra server
uv sync --locked --extra web
uv sync --locked --extra image-watermark
uv sync --locked --extra aws
```

## Quick start

Create an identity:

```bash
pact identity init \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Show the public JWK:

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
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Register the identity and claim:

```bash
pact registry register-profile \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'

pact registry register-claim ./work.manifest.json \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Verify the manifest:

```bash
pact verify ./work.manifest.json \
  --content ./work.txt \
  --nonce ./work.nonce
```

Run the local registry/web app:

```bash
pact web --data-dir ./.pact-dev --port 8000 --database ./.pact-dev/registry.sqlite3
```

Run only the browser workspace against a remote registry:

```bash
pact web --remote-registry https://registry.example --port 8000
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

Run the repo checks:

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

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
