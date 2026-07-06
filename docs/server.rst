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

Deploying to AWS Lambda + RDS
-----------------------------

The AWS deployment runs the same FastAPI application in a Lambda container and
uses Postgres for durable registry state. The repository no longer ships
CloudFormation or SAM templates; provision the AWS resources directly, then
build and push the container image from this repo.

This guide covers:

- generating registry CA keys
- building the Lambda container image from ``deploy/lambdas/Dockerfile``
- creating an ECR repository and pushing the image
- wiring Lambda to RDS or Aurora Postgres through a VPC
- setting the required environment variables safely
- exposing the app through a Lambda Function URL or API Gateway
- testing the deployed registry

Prerequisites
~~~~~~~~~~~~~

Install Docker and AWS CLI v2, configure an AWS profile with IAM, Lambda, ECR,
EC2/VPC, RDS, and Secrets Manager permissions, and create or choose a Postgres
database. Aurora Serverless v2 is a reasonable middle ground for low-traffic
production: it can scale down farther than provisioned RDS, but still behaves
like Postgres from the app's point of view.

Set the shell variables used below:

.. code-block:: bash

   export AWS_PROFILE=default
   export AWS_REGION=us-east-1
   export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
   export PACT_IMAGE_NAME=pact-registry
   export PACT_FUNCTION_NAME=pact-registry

Generate registry CA material
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run this once, on a trusted local machine:

.. code-block:: bash

   pact registry init \
     --registry https://your-domain.example.com \
     --data-dir ./pact-ca

This writes:

.. code-block:: text

   pact-ca/
     root_certificate.pem
     intermediate_certificate.pem
     intermediate_private_key.pem
     root_private_key.pem

Move ``root_private_key.pem`` to offline storage immediately. It is not needed
by Lambda. The intermediate private key is needed at runtime and must be treated
as a secret.

Create an OPRF server secret:

.. code-block:: bash

   export PACT_OPRF_SECRET=$(python3 -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")

Create an admin identity and export its public JWK:

.. code-block:: bash

   pact identity init \
     --registry https://your-domain.example.com \
     --identity-file ./pact-admin.pem \
     --identity-password 'use-a-strong-password'

   pact identity public-jwk \
     --registry https://your-domain.example.com \
     --identity-file ./pact-admin.pem \
     --identity-password 'use-a-strong-password' \
     --out ./admin.public.jwk.json

   export ADMIN_JWKS="[$(cat admin.public.jwk.json)]"

Store secrets
~~~~~~~~~~~~~

Use Secrets Manager for values that should not live in shell history or source
control. The simplest deployment still places resolved values into Lambda
environment variables, so restrict IAM access to the function configuration.

Postgres DSNs are URLs. If your password contains characters such as ``@``,
``:``, ``/``, ``?``, ``#``, ``{``, ``}``, ``^``, or backticks, URL-encode the
password before putting it in the DSN. Prefer a dedicated app user over the
``postgres`` admin user.

.. code-block:: bash

   aws secretsmanager create-secret \
     --name pact/intermediate-private-key \
     --secret-string "$(cat pact-ca/intermediate_private_key.pem)" \
     --region $AWS_REGION

   aws secretsmanager create-secret \
     --name pact/postgres-dsn \
     --secret-string "postgresql://pact_registry_app:CHANGE_ME@your-rds-writer-endpoint.rds.amazonaws.com:5432/pact?sslmode=require" \
     --region $AWS_REGION

   aws secretsmanager create-secret \
     --name pact/oprf-secret \
     --secret-string "$PACT_OPRF_SECRET" \
     --region $AWS_REGION

Create the Postgres database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run this once as your RDS admin user. The PACT app creates its own tables on the
first successful connection, but the database and app role must already exist.

.. code-block:: sql

   CREATE DATABASE pact;
   CREATE USER pact_registry_app WITH PASSWORD 'use-a-strong-password';
   GRANT ALL PRIVILEGES ON DATABASE pact TO pact_registry_app;

Connect to the ``pact`` database and grant schema creation:

.. code-block:: sql

   GRANT USAGE, CREATE ON SCHEMA public TO pact_registry_app;

The runtime creates ``registry_events``, ``registry_batches``, and
``registry_challenges`` automatically. No manual table migration is required for
a new deployment.

Build and push the image
~~~~~~~~~~~~~~~~~~~~~~~~

Build from the repository root and point Docker at the Lambda Dockerfile. The
``--provenance=false`` and ``--sbom=false`` flags avoid OCI manifest formats
that Lambda rejects for container images.

.. code-block:: bash

   uv run sphinx-build -b html docs docs/_build/html

   aws ecr create-repository \
     --repository-name $PACT_IMAGE_NAME \
     --region $AWS_REGION \
     --image-scanning-configuration scanOnPush=true

   aws ecr get-login-password --region $AWS_REGION \
     | docker login \
       --username AWS \
       --password-stdin \
       "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

   docker buildx build \
     --platform linux/amd64 \
     --provenance=false \
     --sbom=false \
     -f deploy/lambdas/Dockerfile \
     -t "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PACT_IMAGE_NAME}:latest" \
     --push \
     .

   export PACT_IMAGE_DIGEST=$(aws ecr describe-images \
     --repository-name $PACT_IMAGE_NAME \
     --region $AWS_REGION \
     --query 'sort_by(imageDetails, &imagePushedAt)[-1].imageDigest' \
     --output text)

   export PACT_FULL_IMAGE="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PACT_IMAGE_NAME}@${PACT_IMAGE_DIGEST}"

The image installs the CPU-only PyTorch wheels through the PyTorch CPU index.
Do not use CUDA wheels in Lambda; the runtime has no CUDA drivers and the image
becomes unnecessarily large.

VPC and security groups
~~~~~~~~~~~~~~~~~~~~~~~

Lambda and RDS must be reachable inside the same VPC. Use private subnets for
the Lambda. If the function needs outbound internet access from private subnets,
add a NAT gateway or the relevant VPC endpoints.

.. code-block:: bash

   export VPC_ID=vpc-xxxxxxxx
   export SUBNET_IDS=subnet-aaa,subnet-bbb
   export RDS_SG_ID=sg-rdsxxxxxxxx

   export LAMBDA_SG_ID=$(aws ec2 create-security-group \
     --group-name pact-registry-lambda \
     --description "PACT registry Lambda to RDS" \
     --vpc-id $VPC_ID \
     --query 'GroupId' \
     --output text)

   aws ec2 authorize-security-group-egress \
     --group-id $LAMBDA_SG_ID \
     --protocol tcp \
     --port 5432 \
     --cidr 0.0.0.0/0

   aws ec2 authorize-security-group-ingress \
     --group-id $RDS_SG_ID \
     --protocol tcp \
     --port 5432 \
     --source-group $LAMBDA_SG_ID

Use the RDS writer endpoint and port ``5432`` unless you explicitly configured
a different database port.

IAM execution role
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   cat > /tmp/pact-lambda-trust.json <<'EOF'
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"Service": "lambda.amazonaws.com"},
       "Action": "sts:AssumeRole"
     }]
   }
   EOF

   export LAMBDA_ROLE_ARN=$(aws iam create-role \
     --role-name pact-registry-lambda \
     --assume-role-policy-document file:///tmp/pact-lambda-trust.json \
     --query 'Role.Arn' \
     --output text)

   aws iam attach-role-policy \
     --role-name pact-registry-lambda \
     --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole

   cat > /tmp/pact-secrets-policy.json <<EOF
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["secretsmanager:GetSecretValue"],
       "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:pact/*"
     }]
   }
   EOF

   aws iam put-role-policy \
     --role-name pact-registry-lambda \
     --policy-name pact-secrets-read \
     --policy-document file:///tmp/pact-secrets-policy.json

   sleep 10

Create the Lambda environment file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Do not pass PEMs, JSON Web Keys, or DSNs through the AWS CLI shorthand syntax.
Newlines, quotes, commas, and special password characters are easy to corrupt.
Write a JSON environment file and pass it with ``file://``.

The app accepts PEM values either with real newlines or with literal ``\n``
sequences. This helper writes literal ``\n`` sequences:

.. code-block:: bash

   pem_to_env() { awk '{printf "%s\\n", $0}' "$1"; }

   export ROOT_CERT=$(pem_to_env pact-ca/root_certificate.pem)
   export INTERMEDIATE_CERT=$(pem_to_env pact-ca/intermediate_certificate.pem)
   export INTERMEDIATE_KEY=$(aws secretsmanager get-secret-value \
     --secret-id pact/intermediate-private-key \
     --query SecretString \
     --output text | awk '{printf "%s\\n", $0}')
   export POSTGRES_DSN=$(aws secretsmanager get-secret-value \
     --secret-id pact/postgres-dsn \
     --query SecretString \
     --output text)
   export OPRF_SECRET=$(aws secretsmanager get-secret-value \
     --secret-id pact/oprf-secret \
     --query SecretString \
     --output text)

Use Python only to JSON-escape the values:

.. code-block:: bash

   python3 - <<'PY' > /tmp/pact-lambda-env.json
   import json
   import os

   env = {
       "PACT_DEPLOYMENT_MODE": "aws_lambda",
       "PACT_STORE_BACKEND": "postgres",
       "PACT_REGISTRY_URL": "https://your-domain.example.com",
       "PACT_PUBLIC_BASE_URL": "https://your-domain.example.com",
       "PACT_POSTGRES_DSN": os.environ["POSTGRES_DSN"],
       "PACT_ROOT_CERTIFICATE_PEM": os.environ["ROOT_CERT"],
       "PACT_INTERMEDIATE_CERTIFICATE_PEM": os.environ["INTERMEDIATE_CERT"],
       "PACT_INTERMEDIATE_PRIVATE_KEY_PEM": os.environ["INTERMEDIATE_KEY"],
       "PACT_OPRF_SERVER_SECRET": os.environ["OPRF_SECRET"],
       "PACT_ADMIN_PUBLIC_JWKS": os.environ["ADMIN_JWKS"],
       "PACT_ALLOWED_HOSTS": "your-domain.example.com",
       "PACT_CORS_ORIGINS": "",
       "PACT_API_GATEWAY_BASE_PATH": "/",
       "PACT_ENABLE_WORKSPACE": "true",
       "PACT_DOCS_DIRECTORY": "/var/task/docs/_build/html",
       "PACT_LOG_LEVEL": "INFO",
       "PACT_LOG_FORMAT": "json",
   }
   print(json.dumps({"Variables": env}))
   PY

``deploy/lambdas/.env.example`` lists the same runtime variables as a template.
Do not commit a filled-in copy.

Create the Lambda function
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   aws lambda create-function \
     --function-name $PACT_FUNCTION_NAME \
     --package-type Image \
     --code "ImageUri=${PACT_FULL_IMAGE}" \
     --role $LAMBDA_ROLE_ARN \
     --architectures x86_64 \
     --timeout 30 \
     --memory-size 512 \
     --vpc-config "SubnetIds=${SUBNET_IDS},SecurityGroupIds=${LAMBDA_SG_ID}" \
     --environment file:///tmp/pact-lambda-env.json \
     --region $AWS_REGION

   aws lambda wait function-active \
     --function-name $PACT_FUNCTION_NAME \
     --region $AWS_REGION

Expose the registry
~~~~~~~~~~~~~~~~~~~

A Lambda Function URL is enough for a direct HTTPS endpoint:

.. code-block:: bash

   aws lambda create-function-url-config \
     --function-name $PACT_FUNCTION_NAME \
     --auth-type NONE \
     --cors '{
       "AllowOrigins": ["https://your-domain.example.com"],
       "AllowMethods": ["GET","POST","OPTIONS"],
       "AllowHeaders": ["content-type","authorization","x-request-id"],
       "MaxAge": 300
     }' \
     --region $AWS_REGION

   aws lambda add-permission \
     --function-name $PACT_FUNCTION_NAME \
     --statement-id FunctionURLAllowPublicAccess \
     --action lambda:InvokeFunctionUrl \
     --principal '*' \
     --function-url-auth-type NONE \
     --region $AWS_REGION

   export FUNCTION_URL=$(aws lambda get-function-url-config \
     --function-name $PACT_FUNCTION_NAME \
     --query FunctionUrl \
     --output text \
     --region $AWS_REGION)

If you place API Gateway and a custom domain in front of Lambda, make the
custom domain route to the Lambda integration and keep PACT's public routes
under ``/pact``. If API Gateway sends stage-prefixed paths such as
``/prod/pact``, set ``PACT_API_GATEWAY_BASE_PATH=/prod``. If the custom domain
already strips the stage, leave ``PACT_API_GATEWAY_BASE_PATH=/``.

``PACT_ALLOWED_HOSTS`` must contain the host users actually call, for example
``ncryptai.com``. Add the raw Function URL or execute-api host only if you
intend to allow direct access through that hostname.

Cognito hosted-account login
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PACT can use an API Gateway HTTP API JWT authorizer backed by Cognito as hosted
account evidence. Keep public registry routes public, and attach the authorizer
only to:

.. code-block:: text

   POST /pact/api/v1/profiles/me/hosted-login

The request still must contain a normal PACT signed mutation body. API Gateway
validates the Cognito JWT, and the app records hosted-account evidence only when
the JWT claims match the configured issuer and app client. The stored evidence
contains the provider, issuer, app client ID, email-verification flag, and a
hash of the Cognito subject. It does not store the raw Cognito subject or email.

Set these Lambda environment variables:

.. code-block:: bash

   PACT_AUTH_PROVIDER=cognito
   PACT_AWS_REGION=us-east-2
   PACT_COGNITO_USER_POOL_ID=us-east-2_example
   PACT_COGNITO_APP_CLIENT_ID=exampleclientid
   PACT_COGNITO_ISSUER=https://cognito-idp.us-east-2.amazonaws.com/us-east-2_example
   PACT_COGNITO_HOSTED_UI_DOMAIN=https://your-domain.auth.us-east-2.amazoncognito.com
   PACT_COGNITO_CALLBACK_URL=https://your-domain.example.com/pact/auth/callback

If you use Cognito Hosted UI or any OAuth redirect flow, Cognito requires at
least one exact callback URL on the app client. Use the URL that your browser
login code actually handles, for example:

.. code-block:: text

   https://your-domain.example.com/pact/auth/callback

If you do not build a Hosted UI/OAuth callback and instead obtain tokens with a
custom frontend flow, the API route still only needs the final
``Authorization: Bearer <token>`` header.

Test the deployment
~~~~~~~~~~~~~~~~~~~

PACT routes are under ``/pact``:

.. code-block:: bash

   curl -i "${FUNCTION_URL}pact"
   curl -s "${FUNCTION_URL}pact/api/v1/registry" | python3 -m json.tool
   curl -s "${FUNCTION_URL}pact/api/v1/server/info" | python3 -m json.tool
   curl -s "${FUNCTION_URL}pact/api/v1/server/routes" | python3 -m json.tool

With a custom domain:

.. code-block:: bash

   curl -i https://your-domain.example.com/pact
   curl -s https://your-domain.example.com/pact/api/v1/server/info | python3 -m json.tool

A healthy registry reports ``deployment_mode`` as ``aws_lambda`` and
``store_backend`` as ``postgres``. The first request may be slow while Lambda
creates a VPC network interface and opens the Postgres connection.

Redeploy
~~~~~~~~

.. code-block:: bash

   docker buildx build \
     --platform linux/amd64 \
     --provenance=false \
     --sbom=false \
     -f deploy/lambdas/Dockerfile \
     -t "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PACT_IMAGE_NAME}:latest" \
     --push \
     .

   export NEW_DIGEST=$(aws ecr describe-images \
     --repository-name $PACT_IMAGE_NAME \
     --region $AWS_REGION \
     --query 'sort_by(imageDetails, &imagePushedAt)[-1].imageDigest' \
     --output text)

   aws lambda update-function-code \
     --function-name $PACT_FUNCTION_NAME \
     --image-uri "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PACT_IMAGE_NAME}@${NEW_DIGEST}" \
     --region $AWS_REGION

   aws lambda wait function-updated \
     --function-name $PACT_FUNCTION_NAME \
     --region $AWS_REGION

Operational notes
~~~~~~~~~~~~~~~~~

Use AWS WAF, API Gateway throttling, or another edge-level rate limiter for
production traffic. The in-process rate limiter does not coordinate across
concurrent Lambda execution environments.

If RDS connection counts become a problem, place RDS Proxy or PgBouncer between
Lambda and Postgres. Each warm Lambda execution environment can hold its own
database connection.

Rotate the intermediate CA key, OPRF secret, and Postgres password on a
documented schedule. Update Secrets Manager, regenerate the Lambda environment
file, and update the function configuration so new cold starts pick up the
values. The offline root key should only be used for CA rotations.

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

- RDS ingress allows TCP ``5432`` from only the Lambda security group
- the Lambda function uses an immutable image digest, not a mutable ``latest``
  tag
- ``PACT_ALLOWED_HOSTS`` contains exact production hosts and not wildcards
- ``PACT_REGISTRY_URL`` and ``PACT_PUBLIC_BASE_URL`` match the final public
  hostname
- ``PACT_API_GATEWAY_BASE_PATH`` matches the actual path API Gateway forwards
  to Lambda
- ``/pact/api/v1/server/info`` reports the expected deployment mode, store
  backend, and commit SHA
- public routes are intentionally accessible, including the OPRF endpoint,
  inspection, and public proof pages
- edge-level rate limiting is enabled for production traffic
- Forwarding headers are stripped and rewritten by the gateway; the app trusts
  them only from configured proxy peers
- Upload and inspection logs do not retain private claim content
- Registry CA material comes from a secret manager and is not baked into an
  image or template
- ``PACT_OPRF_SERVER_SECRET`` is set to a dedicated secret separate from CA keys
- Database backups, retention, and CA key rotation procedures are documented

Validate tests and documentation:

.. code-block:: bash

   uv run python -m pytest tests -q
   uv run sphinx-build -W -b html docs docs/_build/html
