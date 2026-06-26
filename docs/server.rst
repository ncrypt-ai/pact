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

The current AWS package surface provides the Lambda entrypoint, route metadata,
Cognito scope metadata, and Postgres-backed registry store. Infrastructure
templates can consume those open route definitions rather than duplicating
route names and permissions by hand.
