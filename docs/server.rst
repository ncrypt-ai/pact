Server deployments
==================

PACT exposes the same registry API and proof pages in two deployment shapes:

- a monolith FastAPI app for local or small self-hosted registries;
- an AWS Lambda/API Gateway layout for serverless deployments.

Monolith runtime
----------------

The monolith can use the file-backed event log or SQLite. SQLite may be
in-memory for ephemeral testing or a file path for a lightweight persistent
registry.

.. code-block:: bash

   pact registry init \
     --registry http://127.0.0.1:8000 \
     --data-dir .pact-registry \
     --root-key-password change-me

   pact registry serve \
     --registry http://127.0.0.1:8000 \
     --data-dir .pact-registry \
     --public-base-url http://127.0.0.1:8000 \
     --host 127.0.0.1 \
     --port 8000 \
     --store-backend sqlite \
     --sqlite-database :memory:

Use ``--sqlite-database .pact-registry/registry.sqlite3`` for a local
persistent SQLite database.

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
