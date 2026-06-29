"""Open server configuration for monolith and AWS deployments."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from pact.server.logging import LoggingConfig


class DeploymentMode(StrEnum):
    """Supported API deployment modes."""

    MONOLITH = "monolith"
    AWS_LAMBDA = "aws_lambda"


class StoreBackend(StrEnum):
    """Supported registry persistence backends."""

    FILE = "file"
    SQLITE = "sqlite"
    POSTGRES = "postgres"


class AuthProvider(StrEnum):
    """Supported HTTP authorization providers."""

    NONE = "none"
    COGNITO = "cognito"


class RouteAuth(StrEnum):
    """Route authorization requirements."""

    PUBLIC = "public"
    CLAIMANT_SIGNATURE = "claimant_signature"
    ADMIN = "admin"


@dataclass(frozen=True, slots=True)
class CognitoAuthorizerConfig:
    """Cognito settings used by AWS API Gateway authorizers."""

    user_pool_id: str
    app_client_id: str
    region: str
    issuer: str | None = None

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-compatible Cognito authorizer config."""

        result = {
            "user_pool_id": self.user_pool_id,
            "app_client_id": self.app_client_id,
            "region": self.region,
        }
        if self.issuer is not None:
            result["issuer"] = self.issuer
        return result


@dataclass(frozen=True, slots=True)
class SecurityProfile:
    """Security controls applied by an API deployment."""

    auth_provider: AuthProvider = AuthProvider.NONE
    allowed_hosts: tuple[str, ...] = ()
    cors_origins: tuple[str, ...] = ()
    cognito: CognitoAuthorizerConfig | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible security profile."""

        return {
            "auth_provider": self.auth_provider.value,
            "allowed_hosts": list(self.allowed_hosts),
            "cors_origins": list(self.cors_origins),
            "cognito": None
            if self.cognito is None
            else self.cognito.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class RouteConfig:
    """One public API or proof-page route."""

    name: str
    method: str
    path: str
    auth: RouteAuth
    lambda_name: str | None = None
    permission: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible route config."""

        return {
            "name": self.name,
            "method": self.method,
            "path": self.path,
            "auth": self.auth.value,
            "lambda_name": self.lambda_name,
            "permission": self.permission,
        }


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Deployment runtime configuration for the registry API."""

    registry_url: str
    public_base_url: str
    mode: DeploymentMode = DeploymentMode.MONOLITH
    store_backend: StoreBackend = StoreBackend.SQLITE
    file_store_directory: str | None = None
    sqlite_database: str = ":memory:"
    postgres_dsn: str | None = None
    security: SecurityProfile = SecurityProfile()
    logging: LoggingConfig = LoggingConfig()
    routes: tuple[RouteConfig, ...] = ()

    @classmethod
    def from_env(cls) -> RuntimeConfig:
        """Load runtime configuration from environment variables."""

        security = SecurityProfile(
            auth_provider=AuthProvider(
                os.getenv("PACT_AUTH_PROVIDER", "none")
            ),
            allowed_hosts=_csv("PACT_ALLOWED_HOSTS"),
            cors_origins=_csv("PACT_CORS_ORIGINS"),
            cognito=_cognito_from_env(),
        )
        return cls(
            registry_url=os.environ["PACT_REGISTRY_URL"],
            public_base_url=os.environ["PACT_PUBLIC_BASE_URL"],
            mode=DeploymentMode(os.getenv("PACT_DEPLOYMENT_MODE", "monolith")),
            store_backend=StoreBackend(
                os.getenv("PACT_STORE_BACKEND", "sqlite")
            ),
            file_store_directory=os.getenv("PACT_FILE_STORE_DIRECTORY"),
            sqlite_database=os.getenv("PACT_SQLITE_DATABASE", ":memory:"),
            postgres_dsn=os.getenv("PACT_POSTGRES_DSN"),
            security=security,
            logging=LoggingConfig.from_env(),
            routes=default_routes(),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible runtime config."""

        return {
            "registry_url": self.registry_url,
            "public_base_url": self.public_base_url,
            "mode": self.mode.value,
            "store_backend": self.store_backend.value,
            "file_store_directory": self.file_store_directory,
            "sqlite_database": self.sqlite_database,
            "postgres_dsn_configured": self.postgres_dsn is not None,
            "security": self.security.to_dict(),
            "logging": self.logging.to_dict(),
            "routes": [route.to_dict() for route in self.routes],
        }


def default_routes() -> tuple[RouteConfig, ...]:
    """Return the open route and permission map for the registry API."""

    return (
        RouteConfig("home", "GET", "/", RouteAuth.PUBLIC, "home"),
        RouteConfig(
            "registry_info",
            "GET",
            "/api/v1/registry",
            RouteAuth.PUBLIC,
            "registry_info",
        ),
        RouteConfig(
            "server_routes",
            "GET",
            "/api/v1/server/routes",
            RouteAuth.PUBLIC,
            "server_routes",
        ),
        RouteConfig(
            "server_info",
            "GET",
            "/api/v1/server/info",
            RouteAuth.PUBLIC,
            "server_info",
        ),
        RouteConfig(
            "inspect",
            "POST",
            "/api/v1/inspect",
            RouteAuth.PUBLIC,
            "inspect",
        ),
        RouteConfig(
            "issue_challenge",
            "POST",
            "/api/v1/challenges",
            RouteAuth.PUBLIC,
            "issue_challenge",
        ),
        RouteConfig(
            "device_binding_oprf",
            "POST",
            "/api/v1/device-bindings/oprf",
            RouteAuth.PUBLIC,
            "device_binding_oprf",
        ),
        RouteConfig(
            "register_profile",
            "POST",
            "/api/v1/profiles",
            RouteAuth.CLAIMANT_SIGNATURE,
            "register_profile",
            "profiles:write",
        ),
        RouteConfig(
            "get_profile",
            "GET",
            "/api/v1/profiles/{key_id}",
            RouteAuth.PUBLIC,
            "get_profile",
        ),
        RouteConfig(
            "get_profile_evidence",
            "GET",
            "/api/v1/profiles/{key_id}/evidence",
            RouteAuth.PUBLIC,
            "get_profile_evidence",
        ),
        RouteConfig(
            "issue_certificate",
            "POST",
            "/api/v1/certificates",
            RouteAuth.CLAIMANT_SIGNATURE,
            "issue_certificate",
            "certificates:write",
        ),
        RouteConfig(
            "register_claim",
            "POST",
            "/api/v1/claims",
            RouteAuth.CLAIMANT_SIGNATURE,
            "register_claim",
            "claims:write",
        ),
        RouteConfig(
            "get_claim",
            "GET",
            "/api/v1/claims/{claim_id}",
            RouteAuth.PUBLIC,
            "get_claim",
        ),
        RouteConfig(
            "list_claim_reports",
            "GET",
            "/api/v1/claims/{claim_id}/reports",
            RouteAuth.PUBLIC,
            "list_claim_reports",
        ),
        RouteConfig(
            "get_claim_spread",
            "GET",
            "/api/v1/claims/{claim_id}/spread",
            RouteAuth.PUBLIC,
            "get_claim_spread",
        ),
        RouteConfig(
            "revoke_claim",
            "POST",
            "/api/v1/claims/{claim_id}/revoke",
            RouteAuth.CLAIMANT_SIGNATURE,
            "revoke_claim",
            "claims:revoke",
        ),
        RouteConfig(
            "recover_source_candidates",
            "POST",
            "/api/v1/recover",
            RouteAuth.PUBLIC,
            "recover_source_candidates",
        ),
        RouteConfig(
            "submit_avoidance_report",
            "POST",
            "/api/v1/reports/avoidance",
            RouteAuth.PUBLIC,
            "submit_avoidance_report",
        ),
        RouteConfig(
            "get_avoidance_report",
            "GET",
            "/api/v1/reports/{report_id}",
            RouteAuth.PUBLIC,
            "get_avoidance_report",
        ),
        RouteConfig(
            "rotate_key",
            "POST",
            "/api/v1/rotations",
            RouteAuth.CLAIMANT_SIGNATURE,
            "rotate_key",
            "profiles:rotate",
        ),
        RouteConfig(
            "verify_domain",
            "POST",
            "/api/v1/domains/verify",
            RouteAuth.CLAIMANT_SIGNATURE,
            "verify_domain",
            "domains:write",
        ),
        RouteConfig(
            "authorize_hosted_account",
            "POST",
            "/api/v1/profiles/{key_id}/hosted-authorize",
            RouteAuth.ADMIN,
            "authorize_hosted_account",
            "profiles:hosted_authorize",
        ),
        RouteConfig(
            "complete_hosted_account_login",
            "POST",
            "/api/v1/profiles/me/hosted-login",
            RouteAuth.CLAIMANT_SIGNATURE,
            "complete_hosted_account_login",
            "profiles:hosted_login",
        ),
        RouteConfig(
            "attest_third_party_account",
            "POST",
            "/api/v1/profiles/{key_id}/third-party-attest",
            RouteAuth.CLAIMANT_SIGNATURE,
            "attest_third_party_account",
            "profiles:third_party_attest",
        ),
        RouteConfig(
            "open_dispute",
            "POST",
            "/api/v1/disputes",
            RouteAuth.CLAIMANT_SIGNATURE,
            "open_dispute",
            "disputes:write",
        ),
        RouteConfig(
            "get_dispute",
            "GET",
            "/api/v1/disputes/{dispute_id}",
            RouteAuth.PUBLIC,
            "get_dispute",
        ),
        RouteConfig(
            "resolve_dispute",
            "POST",
            "/api/v1/disputes/{dispute_id}/resolve",
            RouteAuth.ADMIN,
            "resolve_dispute",
            "disputes:resolve",
        ),
        RouteConfig(
            "public_profile",
            "GET",
            "/profiles/{key_id}",
            RouteAuth.PUBLIC,
            "public_profile",
        ),
        RouteConfig(
            "public_claim",
            "GET",
            "/claims/{claim_id}",
            RouteAuth.PUBLIC,
            "public_claim",
        ),
        RouteConfig(
            "verify_claim_page",
            "GET",
            "/verify/claim/{claim_id}",
            RouteAuth.PUBLIC,
            "verify_claim_page",
        ),
    )


def _csv(name: str) -> tuple[str, ...]:
    value = os.getenv(name)
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _cognito_from_env() -> CognitoAuthorizerConfig | None:
    user_pool_id = os.getenv("PACT_COGNITO_USER_POOL_ID")
    app_client_id = os.getenv("PACT_COGNITO_APP_CLIENT_ID")
    region = os.getenv("PACT_AWS_REGION")
    if not user_pool_id or not app_client_id or not region:
        return None
    return CognitoAuthorizerConfig(
        user_pool_id=user_pool_id,
        app_client_id=app_client_id,
        region=region,
        issuer=os.getenv("PACT_COGNITO_ISSUER"),
    )
