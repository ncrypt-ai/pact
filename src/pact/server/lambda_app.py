"""AWS Lambda entrypoint for the registry API."""

from __future__ import annotations

import importlib
import os
from functools import lru_cache
from typing import Any, cast

from pact.registry.app import RegistryCertificateAuthority, RegistryService
from pact.server.config import RuntimeConfig
from pact.server.runtime import create_registry_store
from pact.web import create_app


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
    )
    app = create_app(
        service,
        public_base_url=config.public_base_url,
        local_mode=False,
    )
    return mangum_module.Mangum(app)


def lambda_handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    """Handle one AWS API Gateway Lambda event."""

    return _handler()(event, context)


def _pem_env(name: str) -> bytes:
    value = os.environ[name]
    return value.replace("\\n", "\n").encode("utf-8")
