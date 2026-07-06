"""AWS Lambda entrypoint for the registry API."""

from __future__ import annotations

import importlib
import os
from functools import lru_cache
from typing import Any, cast

from pact.registry.app import RegistryCertificateAuthority, RegistryService
from pact.server.config import RuntimeConfig
from pact.server.logging import configure_logging, server_logger
from pact.server.runtime import create_registry_store
from pact.web import create_app

LOGGER = server_logger("lambda")


@lru_cache(maxsize=1)
def _handler():
    try:
        mangum = importlib.import_module("mangum")
    except ImportError as error:
        raise RuntimeError(
            "AWS Lambda support requires the pact[aws] optional dependencies"
        ) from error
    mangum_module = cast(Any, mangum)
    config = RuntimeConfig.from_env()
    configure_logging(config.logging)
    if config.oprf_server_secret is None:
        raise RuntimeError(
            "PACT_OPRF_SERVER_SECRET is required for AWS Lambda deployments"
        )
    LOGGER.info(
        "initializing lambda registry app",
        extra={
            "deployment_mode": config.mode.value,
            "registry_url": config.registry_url,
            "store_backend": config.store_backend.value,
        },
    )
    service = RegistryService(
        config.registry_url,
        store=create_registry_store(config),
        certificate_authority=RegistryCertificateAuthority(
            registry_url=config.registry_url,
            root_certificate_pem=_pem_env("PACT_ROOT_CERTIFICATE_PEM"),
            root_private_key_pem=None,
            intermediate_certificate_pem=_pem_env(
                "PACT_INTERMEDIATE_CERTIFICATE_PEM"
            ),
            intermediate_private_key_pem=_pem_env(
                "PACT_INTERMEDIATE_PRIVATE_KEY_PEM"
            ),
        ),
        oprf_server_secret=config.oprf_server_secret.encode("utf-8"),
        admin_public_jwks=config.admin_public_jwks,
    )
    app = create_app(
        service,
        public_base_url=config.public_base_url,
        local_mode=False,
        enable_workspace=_bool_env("PACT_ENABLE_WORKSPACE"),
        allowed_hosts=config.security.allowed_hosts,
        cors_allowed_origins=config.security.cors_origins,
        docs_directory=os.getenv("PACT_DOCS_DIRECTORY"),
        logging_config=config.logging,
        cognito_authorizer_config=config.security.cognito,
    )
    return mangum_module.Mangum(
        app,
        api_gateway_base_path=os.getenv("PACT_API_GATEWAY_BASE_PATH", "/"),
    )


def lambda_handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    """Handle one AWS API Gateway Lambda event."""

    return _handler()(event, context)


def _pem_env(name: str) -> bytes:
    value = os.environ[name]
    return value.replace("\\n", "\n").encode("utf-8")


def _bool_env(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}
