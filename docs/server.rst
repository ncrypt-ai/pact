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
SQLite database.

Browser workspace
-----------------

The interactive browser workspace is optional. A registry can serve only the
JSON API and proof pages, or it can also expose ``/app``:

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

AWS serverless runtime
----------------------

The AWS deployment model uses:

- API Gateway routes backed by Lambda functions;
- Cognito authorization for non-public routes;
- Postgres for registry events and batches;
- environment-driven runtime configuration.

``default_routes`` is the open-source route and permission map. It marks
public routes, claimant-signed mutation routes, and admin routes. The
``aws_lambda_routes`` helper converts that map into Lambda names and Cognito
scopes such as ``pact/claims:write`` and ``pact/disputes:resolve``.

The running web app exposes the same route map at
``/api/v1/server/routes`` so operators and clients can discover the public
URLs and mutation permissions supported by a deployment.
``/api/v1/inspect`` is public and accepts multipart uploads for signed
manifest JSON or raw carrier media. It reports embedded references and, when
the referenced claim exists in the registry, registry verification evidence.

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

The repository includes a Lambda container package at
``services/lambdas/registry/Dockerfile`` and a SAM template at
``deploy/aws/registry.sam.yaml``. The template maps every public URL to the
registry Lambda, keeps read-only proof pages public, and applies Cognito scopes
to mutation routes.

Build and deploy from the repository root:

.. code-block:: bash

   sam build --template-file deploy/aws/registry.sam.yaml
   sam deploy --guided

The SAM deployment expects an existing Postgres DSN and Cognito user pool. The
template keeps those values as parameters so operators can wire in RDS, Aurora
Serverless, or another managed Postgres endpoint without changing application
code.
