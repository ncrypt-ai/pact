# PACT

Policy Authenticated Content Token.

PACT is a toolkit for signing content claims, attaching those claims to files,
and checking them against registry evidence. It is built for workflows where a
person or organization wants to say:

- this key signed this claim
- this claim is bound to this exact content, when the verifier has the content
- this policy says how the claimant wants the work handled
- this registry has or has not seen, revoked, disputed, or attested to the claim

PACT is not an AI detector, copyright decision engine, or proof that something is true.
It keeps those questions separate so applications can show users exactly what
was verified and what was not.

## What is included

- Registry-scoped P-256 identities with OS keyring or encrypted-file storage.
- Signed PACT Manifest v1 JSON using RFC 8785 canonicalization and ES256.
- Machine-readable training policy entries, including
  `pact.no_commercial_training`.
- Text, HTML, XML, C2PA, document, and image soft-binding carrier helpers.
- Privacy checks that reject raw content, private nonces, prompts, probe text,
  and provider responses before registry publication.
- A FastAPI registry with profiles, claims, revocation, disputes, key rotation,
  public proof pages, and a browser workspace.
- A `pact` CLI for identity, signing, verification, inspection, privacy audits,
  watermarking, probes, and local registry operation.
- AWS Lambda/SAM templates for deploying the same monolith behind an existing
  API Gateway, load balancer, and Cognito authorizer.

## How to think about trust

A valid PACT claim means a registry-scoped key signed a manifest. If the verifier
has the content and nonce, PACT can also check that the content matches the
signed commitment.

It does not prove:

- the content is real, unedited, or AI-generated
- the claimant is a unique person
- the claimant authored or owns the content
- the policy is legally enforceable
- a readable C2PA asset is trustworthy by itself

PACT uses C2PA as an interoperability layer and evidence carrier. For C2PA
background, start with the official project at <https://c2pa.org/>. For useful
skeptical context, see <https://lowentropy.net/posts/c2pa/> and Hacker Factor's
VIDA discussion at
<https://www.hackerfactor.com/blog/index.php?/archives/1028-VIDA-The-Simple-Life.html>.
PACT's stance is practical: use C2PA where it helps move metadata through real
files, but do not treat a container credential as the whole trust decision.

## Install

```bash
uv sync --locked
```

Useful extras:

```bash
uv sync --locked --extra server
uv sync --locked --extra web
uv sync --locked --extra c2pa
uv sync --locked --extra image-watermark
uv sync --locked --extra aws
```

## Quick CLI flow

Create an identity:

```bash
pact identity init \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Register the profile with the registry:

```bash
pact registry register-profile \
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

Publish the signed manifest:

```bash
pact registry register-claim ./work.manifest.json \
  --registry https://registry.example \
  --identity-file ./.pact/identity.pem \
  --identity-password 'change-this'
```

Verify it later:

```bash
pact verify ./work.manifest.json --content ./work.txt
```

Use `pact sign --private-nonce` when the claim should be public but exact
content verification should require a separately shared nonce file.

## Local registry and web workspace

Start a local registry and browser workspace:

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

Open `http://127.0.0.1:8000/pact`.

To reset that local registry and remove this machine's registry-scoped device
binding, run:

```bash
pact registry teardown \
  --registry http://127.0.0.1:8000 \
  --data-dir ./.pact-dev \
  --database ./.pact-dev/registry.sqlite3
```

The command prints the files it will delete and requires two confirmations.

Registry admins are normal PACT identities whose public JWK is loaded at server
startup. Create an admin identity, export its public JWK, and pass it when
serving:

```bash
pact identity init \
  --registry http://127.0.0.1:8000 \
  --identity-file ./.pact-dev/admin.identity.pem \
  --identity-password 'change-this'

pact identity public-jwk \
  --registry http://127.0.0.1:8000 \
  --identity-file ./.pact-dev/admin.identity.pem \
  --identity-password 'change-this' \
  --out ./.pact-dev/admin.public.jwk.json

pact registry serve ... \
  --admin-jwk-file ./.pact-dev/admin.public.jwk.json
```

The browser workspace keeps signing local. Publishing sends signed manifest JSON
to the registry, not the raw file. Browser/device fingerprinting is used for
baseline device continuity, but the registry receives only a private,
registry-scoped device-binding token. The CLI and browser workspace use a
blinded Ristretto OPRF flow backed by the pure-Python `oblivious` package, so
raw device or browser traits are not sent to the registry. The token is a
privacy-preserving continuity signal from honest clients, not proof that a
particular physical device used the official endpoint.

## AWS deployment shape

The AWS templates intentionally do not create your API Gateway, Cognito
authorizer, DNS, certificates, or load balancer. They create the Lambda compute
piece and optional invoke permissions so an existing gateway or load balancer
can call the same FastAPI app used by the monolith.

```bash
uv run cfn-lint deploy/aws/registry-compute.sam.yaml deploy/aws/gateway-rate-limit.yaml
sam build --template-file deploy/aws/registry-compute.sam.yaml
sam deploy --guided --template-file .aws-sam/build/template.yaml
```

Use `deploy/aws/gateway-rate-limit.yaml` to attach AWS WAF rate limits to your
existing API Gateway stage ARN, ALB ARN, or both. See `docs/server.rst` for the
parameter list and deployment checklist.

## HTTP examples

Fetch registry metadata:

```bash
curl https://registry.example/api/v1/registry
```

Inspect a proof or carrier:

```bash
curl -F file=@work.txt -F mime_type=text/plain \
  https://registry.example/api/v1/inspect
```

Report submissions require a registered profile signature. Submitted reports
are claimant/moderator visible by default and become public only after a
review/public-listing step. Public claim, profile, dispute, inspect, and recover
reads remain available so a reviewer can inspect proof material without
creating an account.

Fetch a public claim:

```bash
curl https://registry.example/api/v1/claims/018f7f79-7b42-7c00-8000-000000000001
```

State-changing operations use signed mutation requests. Prefer the CLI or
browser workspace unless you are integrating directly with the API.

## Documentation

- Quickstart: `docs/quickstart.rst`
- CLI commands: `docs/cli.rst`
- Identity commands: `docs/identity.rst`
- Carrier formats and C2PA notes: `docs/carriers.rst`
- Manifest format: `docs/manifest.rst`
- Security model: `docs/security.rst`
- Technological protection measure specification: `docs/tpm.rst`
- Server and AWS deployment: `docs/server.rst`
- Legal and policy notes: `docs/legal.rst`
- Terms notice template: `TERMS.md`
- API reference: `docs/api.rst`

Build docs locally:

```bash
uv run sphinx-build -W -b html docs docs/_build/html
```

## Development

Run the repo checks:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run python -m pytest tests -q
uv run cfn-lint deploy/aws/registry-compute.sam.yaml deploy/aws/gateway-rate-limit.yaml
uv run sphinx-build -W -b html docs docs/_build/html
uv build
```

Contributors may use LLM assistance, but every submitted change needs human
review, testing, and ownership by the contributor. See `CONTRIBUTING.md`.

## Status and license

PACT is pre-alpha. Treat the format and carrier schemes as reviewable drafts,
not stable standards. Apache-2.0. See `LICENSE` and `NOTICE`.
