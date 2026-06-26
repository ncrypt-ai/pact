"""AWS deployment metadata for the registry API."""

from __future__ import annotations

from dataclasses import dataclass

from pact.server.config import RouteAuth, RouteConfig, default_routes


@dataclass(frozen=True, slots=True)
class AwsLambdaRoute:
    """AWS HTTP API route backed by one Lambda function."""

    name: str
    method: str
    path: str
    lambda_name: str
    auth: RouteAuth
    cognito_scope: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible AWS route description."""

        return {
            "name": self.name,
            "method": self.method,
            "path": self.path,
            "lambda_name": self.lambda_name,
            "auth": self.auth.value,
            "cognito_scope": self.cognito_scope,
        }


def aws_lambda_routes(
    routes: tuple[RouteConfig, ...] | None = None,
) -> tuple[AwsLambdaRoute, ...]:
    """Return Lambda route metadata for API Gateway deployment."""

    return tuple(_aws_route(route) for route in (routes or default_routes()))


def _aws_route(route: RouteConfig) -> AwsLambdaRoute:
    lambda_name = route.lambda_name or route.name
    return AwsLambdaRoute(
        name=route.name,
        method=route.method,
        path=route.path,
        lambda_name=f"pact-{lambda_name.replace('_', '-')}",
        auth=route.auth,
        cognito_scope=_scope(route),
    )


def _scope(route: RouteConfig) -> str | None:
    if route.auth is RouteAuth.PUBLIC:
        return None
    if route.permission is None:
        return None
    return f"pact/{route.permission}"
