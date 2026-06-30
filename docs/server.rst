Server deployments
==================

PACT exposes the same registry API and proof pages in two deployment shapes:

- a monolith FastAPI app for local or small self-hosted registries;
- an AWS Lambda/API Gateway layout for serverless deployments.

Monolith runtime
----------------

The monolith uses SQLite. The database can be ``:memory`` for ephemeral testing
or a file path for a lightweight persistent registry.

For local setup, ``pact registry init`` reads ``PACT_DATA_DIR``,
``PACT_REGISTRY_URL``, and ``PACT_ROOT_KEY_PASSWORD`` when they are set. If
the data directory, registry URL, or root key password is still missing, the CLI
prompts for it. File-backed identity commands also read
``PACT_IDENTITY_PASSWORD`` before prompting.

.. code-block:: bash

   pact registry init \
     --registry http://127.0.0.1:8000 \
     --data-dir .pact-registry

   pact registry serve \
     --registry http://127.0.0.1:8000 \
     --data-dir .pact-registry \
     --public-base-url http://127.0.0.1:8000 \
     --host 127.0.0.1 \
     --port 8000 \
     --database :memory

Use ``--database .pact-registry/registry.sqlite3`` for a local persistent
SQLite database. ``:memory`` is only for development and tests; a restart loses
all claims, profiles, challenges, reports, and disputes.

Browser workspace
-----------------

The interactive browser workspace is optional. A registry can serve only the
JSON API and proof pages, or it can also expose ``/pact``:

.. code-block:: bash

   pact registry serve \
     --registry http://127.0.0.1:8000 \
     --data-dir .pact-registry \
     --public-base-url http://127.0.0.1:8000 \
     --host 127.0.0.1 \
     --port 8000 \
     --database :memory \
     --enable-workspace

The workspace runs PACT's Python logic in Pyodide inside a Web Worker. The
JavaScript layer is limited to browser plumbing: file input/output, registry
requests, local browser storage, and page updates. Feature packs are loaded on
demand so identity, manifest, watermark, probe, C2PA carrier, PDF, and document
workflows can stay aligned with the CLI without loading every dependency at
startup.

The workspace can also be hosted without a local registry service:

.. code-block:: bash

   pact web \
     --remote-registry https://registry.example \
     --port 8000

In this mode the browser sends signed requests directly to the remote registry.
The remote registry must allow the workspace origin:

.. code-block:: bash

   pact registry serve \
     --registry https://registry.example \
     --data-dir .pact-registry \
     --public-base-url https://registry.example \
     --cors-allowed-origin http://127.0.0.1:8000

``pact[server]`` installs the registry API/proof-page dependencies.
``pact[web]`` installs the same server dependencies needed to host the
interactive workspace. C2PA and PDF/document carrier functionality remain in
``pact[c2pa]`` and are loaded by the browser workspace as feature packs where
the runtime supports them.

Self-hosted documentation
-------------------------

The web app can also serve prebuilt Sphinx documentation at ``/docs/`` when
``docs/_build/html/index.html`` is present in the checkout:

.. code-block:: bash

   uv run sphinx-build -b html docs docs/_build/html

The registry homepage links to the documentation only when the built HTML is
available. ``/api/v1/server/info`` also reports ``documentation_url`` for
deployments that mount the docs.

AWS serverless runtime
----------------------

The AWS deployment model uses:

- one Lambda container running the same FastAPI app as the monolith;
- externally managed API Gateway, Cognito, and load balancer resources;
- externally managed gateway/load-balancer rate limiting through AWS WAF;
- Postgres for registry events and batches;
- a dedicated high-entropy OPRF server secret, managed separately from the
  registry CA keys;
- environment-driven runtime configuration.

``default_routes`` is the open-source route and permission map. It marks
public routes, claimant-signed mutation routes, and admin routes. Existing API
Gateway deployments should route ``ANY /`` and ``ANY /{proxy+}`` to the Lambda
integration so FastAPI remains the source of truth for the monolith and AWS
surfaces.

The running web app exposes the same route map at
``/api/v1/server/routes`` so operators and clients can discover the public
URLs and mutation permissions supported by a deployment.

Use ``deploy/aws/registry-compute.sam.yaml`` for current AWS deployments. The
older ``deploy/aws/registry.sam.yaml`` file is a legacy partial full-stack
example and does not expose the complete current API surface.
``/api/v1/server/info`` reports the package version and deployed commit hash.
Set ``PACT_COMMIT_SHA`` during deployment so serverless or container builds do
not depend on a local ``.git`` directory.
``/api/v1/inspect`` is public and accepts multipart uploads for signed
manifest JSON or raw carrier media. It reports embedded references and, when
the referenced claim exists in the registry, registry verification evidence.
``/api/v1/recover`` is also public for source-candidate review. Both endpoints
enforce application upload limits and parsing timeouts; deployments should
still enforce lower gateway/proxy limits that match their expected workload.

Avoidance report submission is not anonymous. A caller must have a registered
profile and sign an ``account_authorization`` request proof. Dispute and report
reads are public so reviewers can see the issue, total dispute count, and
reporter credibility context.

The Lambda entrypoint is ``pact.server.lambda_app.lambda_handler``. It expects
the ``pact[aws]`` optional dependencies and these environment variables:

.. code-block:: bash

   PACT_DEPLOYMENT_MODE=aws_lambda
   PACT_STORE_BACKEND=postgres
   PACT_POSTGRES_DSN=postgresql://...
   PACT_REGISTRY_URL=https://registry.example
   PACT_PUBLIC_BASE_URL=https://registry.example
   PACT_AUTH_PROVIDER=cognito
   PACT_AWS_REGION=us-east-1
   PACT_COGNITO_USER_POOL_ID=...
   PACT_COGNITO_APP_CLIENT_ID=...
   PACT_ROOT_CERTIFICATE_PEM=...
   PACT_INTERMEDIATE_CERTIFICATE_PEM=...
   PACT_INTERMEDIATE_PRIVATE_KEY_PEM=...
   PACT_ALLOWED_HOSTS=registry.example
   PACT_CORS_ORIGINS=https://workspace.example
   PACT_COMMIT_SHA=...

The repository includes a Lambda container package at
``services/lambdas/registry/Dockerfile`` and a compute-only SAM template at
``deploy/aws/registry-compute.sam.yaml``. That template creates the Lambda
runtime and optional invoke permissions for an existing API Gateway or ALB. It
does not create API Gateway, Cognito, DNS, certificates, or the load balancer.

Use ``deploy/aws/gateway-rate-limit.yaml`` to attach a regional WAF WebACL to
an existing API Gateway stage ARN, an existing ALB ARN, or both. It includes a
global IP rate limit, a lower mutation-route IP rate limit, and AWS managed
common and known-bad-input rule groups. This is required for AWS Lambda
deployments because the in-process limiter is only a defense-in-depth fallback
and does not coordinate across concurrent Lambda execution environments.

Build and deploy from the repository root:

.. code-block:: bash

   sam build --template-file deploy/aws/registry-compute.sam.yaml
   sam deploy --guided --template-file .aws-sam/build/template.yaml

Then configure the existing gateway/load balancer to invoke the
``RegistryFunctionArn`` output. For API Gateway, grant the template an
``ApiGatewaySourceArn`` such as ``arn:aws:execute-api:REGION:ACCOUNT:API/*/*/*``
or add equivalent invoke permission yourself. For ALB Lambda targets, pass the
target group ARN as ``LoadBalancerTargetGroupArn`` or add equivalent invoke
permission yourself.

The SAM deployment expects an existing Postgres DSN and existing certificate
material. The template keeps those values as parameters so operators can wire
in RDS, Aurora Serverless, or another managed Postgres endpoint without
changing application code.

Deployment checklist
~~~~~~~~~~~~~~~~~~~~

Before treating a registry as public, confirm:

- the API Gateway or ALB forwards ``ANY /`` and ``ANY /{proxy+}`` to the Lambda;
- the Cognito authorizer, if used, matches the route scopes from
  ``/api/v1/server/routes``;
- public routes are intentionally public, including registry metadata,
  inspection/recovery, challenges, proof pages, public dispute/report reads,
  and the device-binding OPRF endpoint;
- mutation routes require signed mutation requests and, where applicable,
  gateway authorization;
- report submissions require a signed registered-profile proof;
- AWS WAF rate limiting is attached to the API Gateway stage ARN, ALB ARN, or
  both;
- CORS origins and allowed hosts are exact deployment values, not wildcards;
- forwarding headers are stripped and rewritten by the gateway/load balancer,
  and the app trusts them only from configured proxy peers;
- upload and request logs do not retain private claim content unnecessarily;
- registry CA material comes from your secret manager and is not baked into an
  image or template;
- database backups, retention, and dispute handling are documented for users.

Validation commands:

.. code-block:: bash

   uv run cfn-lint deploy/aws/registry-compute.sam.yaml deploy/aws/gateway-rate-limit.yaml
   uv run python -m pytest tests -q
   uv run sphinx-build -W -b html docs docs/_build/html

Privacy and publication boundary
--------------------------------

The browser workspace signs content locally and sends only signed manifest
JSON to the registry. It does not upload raw plaintext or binary file content
when publishing a claim. Browser/device fingerprinting is used only as a local
device-continuity signal. Before registration, the browser derives
``HMAC(local_secret, registry_root_fingerprint || browser_fingerprint)`` and
uses a blinded OPRF request to obtain a private, registry-scoped
``pact-device-binding-v2`` token. WebAuthn PRF is the preferred browser local
secret source when available; the profile passcode is the normal fallback. The
CLI uses the same token format while keeping raw hardware-derived material
local.

Every claimant profile must include this token to qualify for the baseline
``unauthenticated_device`` tier. It is not an elevated trust label and it is not
proof of a unique person. It is the minimum device-continuity proof the registry
accepts for a profile.

Public profile responses and proof pages omit the stored token.

Plain-text carrier embeddings include a PACT legal notice in the visible proof
block. Carrier extraction strips that notice before returning the signed
content body, so verification continues to cover the user-selected content.
