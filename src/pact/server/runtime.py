"""Runtime construction helpers for registry deployments."""

from __future__ import annotations

from pathlib import Path

from pact.registry.store import (
    FileRegistryStore,
    PostgresRegistryStore,
    RegistryStore,
    RegistryStoreError,
    SqliteRegistryStore,
)
from pact.server.config import RuntimeConfig, StoreBackend
from pact.server.logging import server_logger

LOGGER = server_logger("runtime")


def create_registry_store(config: RuntimeConfig) -> RegistryStore:
    """Create the registry store selected by runtime configuration."""

    if config.store_backend is StoreBackend.FILE:
        if config.file_store_directory is None:
            raise RegistryStoreError(
                "file_store_directory is required for file storage"
            )
        LOGGER.info(
            "creating registry store",
            extra={"store_backend": config.store_backend.value},
        )
        return FileRegistryStore(Path(config.file_store_directory))
    if config.store_backend is StoreBackend.SQLITE:
        LOGGER.info(
            "creating registry store",
            extra={"store_backend": config.store_backend.value},
        )
        return SqliteRegistryStore(config.sqlite_database)
    if config.store_backend is StoreBackend.POSTGRES:
        if config.postgres_dsn is None:
            raise RegistryStoreError(
                "postgres_dsn is required for Postgres storage"
            )
        LOGGER.info(
            "creating registry store",
            extra={"store_backend": config.store_backend.value},
        )
        return PostgresRegistryStore(config.postgres_dsn)
    raise RegistryStoreError("unsupported registry store backend")
