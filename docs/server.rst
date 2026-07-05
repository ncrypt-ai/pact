Server Deployments
==================

PACT's registry, API, and proof pages run as the same FastAPI application in
two deployment shapes: a SQLite-backed monolith for local and small self-hosted
registries, and a Lambda/Postgres layout for serverless AWS deployments. This
document covers both.

Monolith
--------

The monolith runs via ``pact registry serve`` and uses SQLite for storage.

**Initialize the registry CA** (run once):

.. code-block:: bash

   pact registry init \
     --registry https://registry.example \
     --data-dir ./registry-data

This generates an offline root key and an online intermediate key. The root key
is not needed at runtime — keep it encrypted and store it separately. The
``--data-dir`` flag reads ``PACT_DATA_DIR`` from the environment when omitted,
and the CLI prompts for anything still missing.

**Serve the registry:**

.. code-block:: bash

   pact registry serve \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --public-base-url https://registry.example \
     --database ./registry-data/registry.sqlite3

Use ``--database :memory`` for development and tests only — a restart loses all
data. The registry landing page is served at ``/pact``. Pass
``--enable-workspace`` to also serve the browser workspace at ``/pact/web``.

Registry administrators
-----------------------

A registry administrator is a PACT identity whose public JWK is loaded at
startup. Admins are not created by ``pact registry init``; they are separate
identities that authorize elevated operations such as approving hosted-account
trust tiers and resolving disputes.

**Create an admin identity and export its public key:**

.. code-block:: bash

   pact identity init \
     --registry https://registry.example \
     --identity-file ./secrets/admin.pem \
     --identity-password 'store-this-in-your-password-manager'

   pact identity public-jwk \
     --registry https://registry.example \
     --identity-file ./secrets/admin.pem \
     --identity-password 'store-this-in-your-password-manager' \
     --out ./secrets/admin.public.jwk.json

**Start the server with the admin key:**

.. code-block:: bash

   pact registry serve \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --public-base-url https://registry.example \
     --database ./registry-data/registry.sqlite3 \
     --admin-jwk-file ./secrets/admin.public.jwk.json

Repeat ``--admin-jwk-file`` for each administrator. The server stores only the
public JWK; the private identity stays with the operator.

Admin actions use the CLI and the private identity:

.. code-block:: bash

   pact registry authorize-hosted-account CLAIMANT_KEY_ID \
     --registry https://registry.example \
     --identity-file ./secrets/admin.pem \
     --identity-password 'store-this-in-your-password-manager'

Browser workspace
-----------------

The browser workspace is optional. It runs PACT's Python signing logic in
Pyodide inside a Web Worker. Signing is local; only signed manifest JSON is
sent to the registry, not raw file content. Enable it with
``--enable-workspace`` and open ``/pact/web``.

You can also host the workspace separately from the registry and point it at a
remote registry. In this mode, the local process serves only the static
workspace assets:

.. code-block:: bash

   pact web \
     --remote-registry https://registry.example \
     --port 8000

The remote registry must allow the workspace origin:

.. code-block:: bash

   pact registry serve \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --public-base-url https://registry.example \
     --database ./registry-data/registry.sqlite3 \
     --cors-allowed-origin http://127.0.0.1:8000

The ``pact[server]`` extra installs registry and proof-page dependencies.
``pact[web]`` adds the assets needed to host the interactive workspace.
C2PA and image-watermark functionality loads as on-demand feature packs.

Self-hosted documentation
~~~~~~~~~~~~~~~~~~~~~~~~~

The web app serves prebuilt Sphinx docs at ``/pact/docs/`` when
``docs/_build/html/index.html`` is present. Build them locally:

.. code-block:: bash

   uv run sphinx-build -b html docs docs/_build/html

AWS serverless
--------------

The AWS deployment runs the same FastAPI application as the monolith in a
Lambda container with Postgres for storage. Your existing API Gateway, Cognito
authorizer, DNS, certificates, and load balancer stay in place.

Architecture:

- Lambda container running the PACT FastAPI app
- Externally managed API Gateway or ALB (not created by the template)
- Postgres for registry events (RDS, Aurora Serverless, or compatible)
- AWS WAF for primary rate limiting (see below)
- Dedicated OPRF server secret, separate from the registry CA keys

**Build and deploy:**

.. code-block:: bash

   sam build --template-file deploy/aws/registry-compute.sam.yaml
   sam deploy --guided --template-file .aws-sam/build/template.yaml

Connect the existing gateway or load balancer to the ``RegistryFunctionArn``
output. For API Gateway, pass your stage ARN as ``ApiGatewaySourceArn``. For
ALB Lambda targets, pass the target group ARN as ``LoadBalancerTargetGroupArn``.

**Pass admin keys at deploy time:**

.. code-block:: bash

   ADMIN_PUBLIC_JWKS="$(python -c 'import json,sys; print(json.dumps([json.load(open(p)) for p in sys.argv[1:]]))' ./secrets/admin.public.jwk.json)"

   sam deploy \
     --template-file .aws-sam/build/template.yaml \
     --parameter-overrides AdminPublicJwks="$ADMIN_PUBLIC_JWKS"

**Attach WAF rate limits** to your existing API Gateway stage or ALB:

.. code-block:: bash

   aws cloudformation deploy \
     --template-file deploy/aws/gateway-rate-limit.yaml \
     --stack-name pact-rate-limits \
     --parameter-overrides ApiGatewayStageArn=arn:aws:execute-api:...

The WAF template is the **primary rate-limiting control** for Lambda
deployments. The in-process rate limiter does not coordinate across concurrent
Lambda execution environments; it is defense-in-depth only.

Note: ``deploy/aws/registry.sam.yaml`` is a legacy partial example. Use
``registry-compute.sam.yaml`` for all new deployments.

Environment variables
~~~~~~~~~~~~~~~~~~~~~

The Lambda entrypoint (``pact.server.lambda_app.lambda_handler``) is configured
entirely via environment variables:

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
   PACT_OPRF_SERVER_SECRET=...          # high-entropy, separate from CA keys
   PACT_ADMIN_PUBLIC_JWKS='[{"kty":"EC","crv":"P-256","x":"...","y":"..."}]'
   PACT_ALLOWED_HOSTS=registry.example
   PACT_CORS_ORIGINS=https://workspace.example
   PACT_COMMIT_SHA=...                  # set during build; avoids needing .git at runtime

``PACT_COMMIT_SHA`` is reported at ``/pact/api/v1/server/info`` and is useful for
confirming which build is running without SSH access.

Route map
~~~~~~~~~

The route and permission map is self-documenting at runtime:

.. code-block:: bash

   curl https://registry.example/pact/api/v1/server/routes

Public routes (no authentication required): registry metadata, server info,
inspection/recovery, challenges, the OPRF endpoint, the ``/pact`` landing page,
public proof pages under ``/pact``, profile evidence, claim data, public
disputes and reports.

Mutation routes require a signed mutation request. Admin routes additionally
require the admin identity signature.

Deployment checklist
--------------------

Before treating a registry as public, verify:

- API Gateway or ALB routes ``ANY /`` and ``ANY /{proxy+}`` to the Lambda
- Cognito authorizer scopes (if used) match the route map at
  ``/pact/api/v1/server/routes``
- Public routes are intentionally accessible, including the OPRF endpoint,
  inspection, and public proof pages
- AWS WAF rate limiting is attached to the API Gateway stage ARN or ALB ARN
- ``PACT_CORS_ORIGINS`` and ``PACT_ALLOWED_HOSTS`` are exact deployment values,
  not wildcards
- Forwarding headers are stripped and rewritten by the gateway; the app trusts
  them only from configured proxy peers
- Upload and inspection logs do not retain private claim content
- Registry CA material comes from a secret manager and is not baked into an
  image or template
- ``PACT_OPRF_SERVER_SECRET`` is set to a dedicated secret separate from CA keys
- Database backups, retention, and CA key rotation procedures are documented

Validate templates and tests:

.. code-block:: bash

   uv run cfn-lint deploy/aws/registry-compute.sam.yaml deploy/aws/gateway-rate-limit.yaml
   uv run python -m pytest tests -q
   uv run sphinx-build -W -b html docs docs/_build/html
