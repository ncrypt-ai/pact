import json
from typing import cast

from pact import (
    AuthProvider,
    RuntimeConfig,
    SecurityProfile,
    SqliteRegistryStore,
    StoreBackend,
    create_registry_store,
)
from pact.registry import RegistryEventType


def test_sqlite_registry_store_persists_events_and_batches() -> None:
    store = SqliteRegistryStore(":memory:")

    event = store.append(
        RegistryEventType.PROFILE_REGISTERED,
        "key-1",
        {"key_id": "key-1", "public_jwk": {"kty": "EC"}},
    )

    assert event.sequence == 1
    assert store.list_events()[0].event_id == event.event_id
    assert store.list_batches()[0].first_sequence == 1


def test_runtime_config_creates_sqlite_store() -> None:
    config = RuntimeConfig(
        registry_url="https://registry.example",
        public_base_url="https://registry.example",
        store_backend=StoreBackend.SQLITE,
    )

    store = create_registry_store(config)

    assert isinstance(store, SqliteRegistryStore)


def test_runtime_config_requires_postgres_dsn() -> None:
    config = RuntimeConfig(
        registry_url="https://registry.example",
        public_base_url="https://registry.example",
        store_backend=StoreBackend.POSTGRES,
    )

    try:
        create_registry_store(config)
    except Exception as error:
        assert "postgres_dsn" in str(error)
    else:
        raise AssertionError("Postgres store creation should require a DSN")


def test_runtime_config_loads_admin_public_jwks(monkeypatch) -> None:
    admin_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "example-x",
        "y": "example-y",
    }
    monkeypatch.setenv("PACT_REGISTRY_URL", "https://registry.example")
    monkeypatch.setenv("PACT_PUBLIC_BASE_URL", "https://registry.example")
    monkeypatch.setenv("PACT_ADMIN_PUBLIC_JWKS", json.dumps([admin_jwk]))

    config = RuntimeConfig.from_env()

    assert config.admin_public_jwks == (admin_jwk,)
    assert config.to_dict()["admin_public_jwk_count"] == 1


def test_security_profile_exports_cognito_shape() -> None:
    config = RuntimeConfig(
        registry_url="https://registry.example",
        public_base_url="https://registry.example",
        security=SecurityProfile(auth_provider=AuthProvider.COGNITO),
    )

    exported = config.to_dict()
    security = cast(dict[str, object], exported["security"])

    assert isinstance(security, dict)
    assert security["auth_provider"] == "cognito"
