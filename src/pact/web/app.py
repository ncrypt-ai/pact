"""FastAPI application for the registry API and proof pages."""

import json
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import (
    Body,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pact.crypto import jwk_thumbprint
from pact.inspection import inspect_content
from pact.media import DEFAULT_BINARY_MIME_TYPE, infer_mime_type
from pact.metadata import PACKAGE_VERSION, server_metadata
from pact.registry.app import (
    ChallengePurpose,
    KeyRotationRequest,
    MutationRequest,
    RegistryError,
    RegistryService,
)
from pact.server.config import default_routes
from pact.web.browser_bundle import FEATURE_MODULES, browser_python_archive


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Sliding-window limits for API requests."""

    window_seconds: int = 60
    ip_limit: int = 300
    identity_limit: int = 60
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result of one rate-limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int
    retry_after: int


class SlidingWindowRateLimiter:
    """Small in-process sliding-window limiter."""

    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        self._hits: dict[str, deque[float]] = {}

    def check(
        self, key: str, *, limit: int | None = None
    ) -> RateLimitDecision:
        if not self.config.enabled:
            effective_limit = limit or self.config.ip_limit
            return RateLimitDecision(
                allowed=True,
                limit=effective_limit,
                remaining=effective_limit,
                reset_seconds=0,
                retry_after=0,
            )

        effective_limit = limit or self.config.ip_limit
        now = time.monotonic()
        window = self.config.window_seconds
        hits = self._hits.setdefault(key, deque())
        cutoff = now - window
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= effective_limit:
            retry_after = max(1, int(hits[0] + window - now))
            return RateLimitDecision(
                allowed=False,
                limit=effective_limit,
                remaining=0,
                reset_seconds=retry_after,
                retry_after=retry_after,
            )

        hits.append(now)
        remaining = max(0, effective_limit - len(hits))
        reset_seconds = max(1, int(hits[0] + window - now)) if hits else 0
        return RateLimitDecision(
            allowed=True,
            limit=effective_limit,
            remaining=remaining,
            reset_seconds=reset_seconds,
            retry_after=0,
        )


def _rate_limit_response(decision: RateLimitDecision) -> JSONResponse:
    return JSONResponse(
        {"detail": "rate limit exceeded"},
        status_code=429,
        headers={
            "Retry-After": str(decision.retry_after),
            "X-RateLimit-Limit": str(decision.limit),
            "X-RateLimit-Remaining": str(decision.remaining),
            "X-RateLimit-Reset": str(decision.reset_seconds),
        },
    )


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("forwarded")
    if forwarded:
        for field in forwarded.split(";"):
            name, _, value = field.strip().partition("=")
            if name.lower() == "for" and value:
                return value.strip('"[]')

    for header in ("cf-connecting-ip", "true-client-ip", "x-real-ip"):
        value = request.headers.get(header)
        if value:
            return value.split(",", 1)[0].strip()

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    if request.client is not None:
        return request.client.host
    return "unknown"


def _rate_limit_key_part(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _request_identity_key_values(
    *,
    body: object,
    extra: Iterable[str | None] = (),
) -> tuple[str, ...]:
    keys: list[str | None] = [value for value in extra if value]
    if isinstance(body, BaseModel):
        body = body.model_dump(mode="json")
    if isinstance(body, dict):
        keys.append(_rate_limit_key_part(body.get("challenge_id")))
        keys.append(_rate_limit_key_part(body.get("bound_key_id")))
        public_jwk = body.get("claimant_public_jwk")
        if isinstance(public_jwk, dict):
            try:
                keys.append(
                    "claimant:"
                    + jwk_thumbprint(cast(dict[str, str], public_jwk))
                )
            except Exception:
                keys.append(None)
        for field_name in ("current_public_jwk", "replacement_public_jwk"):
            rotation_jwk = body.get(field_name)
            if isinstance(rotation_jwk, dict):
                try:
                    keys.append(
                        f"{field_name}:"
                        + jwk_thumbprint(cast(dict[str, str], rotation_jwk))
                    )
                except Exception:
                    keys.append(None)
        request_model = body.get("request")
        if isinstance(request_model, dict):
            keys.extend(
                _request_identity_key_values(body=request_model, extra=())
            )
    return tuple(key for key in keys if key)


def _request_identity_keys(
    request: Request,
    *,
    body: object,
    extra: Iterable[str | None] = (),
) -> tuple[str, ...]:
    return tuple(
        f"{request.url.path}:{key}"
        for key in _request_identity_key_values(body=body, extra=extra)
    )


def _templates() -> Jinja2Templates:
    directory = Path(__file__).with_name("templates")
    return Jinja2Templates(directory=str(directory))


def _static_directory() -> Path:
    return Path(__file__).with_name("static")


def _default_docs_directory() -> Path | None:
    docs_directory = (
        Path(__file__).resolve().parents[3] / "docs" / "_build" / "html"
    )
    if (docs_directory / "index.html").is_file():
        return docs_directory
    return None


def _docs_directory(value: str | Path | None) -> Path | None:
    if value is None:
        return _default_docs_directory()
    docs_directory = Path(value)
    if not (docs_directory / "index.html").is_file():
        return None
    return docs_directory


class PrettyJSONResponse(JSONResponse):
    """JSON response formatted for direct browser inspection."""

    def render(self, content: object) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
        ).encode("utf-8")


EXAMPLE_PUBLIC_JWK = {
    "crv": "P-256",
    "kty": "EC",
    "x": "pseudonymous-public-key-x-coordinate",
    "y": "pseudonymous-public-key-y-coordinate",
}
EXAMPLE_CHALLENGE_ID = "018f7f79-7b42-7c00-8000-000000000001"
EXAMPLE_CLAIM_ID = "018f7f79-7b42-7c00-8000-000000000002"
EXAMPLE_DISPUTE_ID = "018f7f79-7b42-7c00-8000-000000000003"
EXAMPLE_SIGNATURE = "base64url-es256-signature"
EXAMPLE_SIGNED_MANIFEST_JSON = (
    '{"manifest":{"version":"1","claim_id":"'
    + EXAMPLE_CLAIM_ID
    + '","registry_url":"https://registry.example"},"signature":{}}'
)

CHALLENGE_EXAMPLES: dict[str, Any] = {
    "profile_registration": {
        "summary": "Challenge for first-time identity registration",
        "value": {
            "purpose": "profile_registration",
            "difficulty": 12,
        },
    },
    "claim_registration": {
        "summary": "Challenge bound to a registered claimant key",
        "value": {
            "purpose": "claim_registration",
            "bound_key_id": "claimant-key-thumbprint",
            "difficulty": 12,
        },
    },
}

MUTATION_EXAMPLES: dict[str, Any] = {
    "profile_registration": {
        "summary": "Register a public claimant profile",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "claimant_public_jwk": EXAMPLE_PUBLIC_JWK,
            "proof_of_work_solution": 271828,
            "payload": {
                "display_name": "Alice Example",
                "device_fingerprint": "registry-scoped-device-fingerprint",
                "hosted_account": False,
            },
            "signature": EXAMPLE_SIGNATURE,
        },
    },
    "claim_registration": {
        "summary": "Register a signed manifest as a public claim",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "claimant_public_jwk": EXAMPLE_PUBLIC_JWK,
            "proof_of_work_solution": 314159,
            "payload": {
                "signed_manifest_json": EXAMPLE_SIGNED_MANIFEST_JSON,
            },
            "signature": EXAMPLE_SIGNATURE,
        },
    },
    "claim_revocation": {
        "summary": "Revoke one of the claimant's registered claims",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "claimant_public_jwk": EXAMPLE_PUBLIC_JWK,
            "proof_of_work_solution": 161803,
            "payload": {
                "reason": "Published in error.",
            },
            "signature": EXAMPLE_SIGNATURE,
        },
    },
    "domain_verification": {
        "summary": "Verify domain control with a DNS TXT record",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "claimant_public_jwk": EXAMPLE_PUBLIC_JWK,
            "proof_of_work_solution": 271828,
            "payload": {
                "domain": "example.com",
                "txt_value": "pact-domain-verification=example-token",
            },
            "signature": EXAMPLE_SIGNATURE,
        },
    },
    "hosted_account_authorization": {
        "summary": "Authorize hosted-account trust as a registry administrator",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "claimant_public_jwk": EXAMPLE_PUBLIC_JWK,
            "proof_of_work_solution": 271828,
            "payload": {
                "target_key_id": "claimant-key-thumbprint",
                "provider": "registry.example",
                "note": "Account passed hosted registry authorization.",
            },
            "signature": EXAMPLE_SIGNATURE,
        },
    },
    "third_party_attestation": {
        "summary": "Attest a claimant as an independent third party",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "claimant_public_jwk": EXAMPLE_PUBLIC_JWK,
            "proof_of_work_solution": 271828,
            "payload": {
                "target_key_id": "claimant-key-thumbprint",
                "documented_rights": False,
                "provider": "Example Attester",
                "note": "Independent account attestation.",
            },
            "signature": EXAMPLE_SIGNATURE,
        },
    },
}

CERTIFICATE_EXAMPLES: dict[str, Any] = {
    "claimant_certificate": {
        "summary": "Issue a claimant certificate after key-possession proof",
        "value": {
            "request": MUTATION_EXAMPLES["profile_registration"]["value"],
            "valid_days": 30,
        },
    }
}

ROTATION_EXAMPLES: dict[str, Any] = {
    "key_rotation": {
        "summary": "Rotate from an old claimant key to a replacement key",
        "value": {
            "challenge_id": EXAMPLE_CHALLENGE_ID,
            "current_public_jwk": EXAMPLE_PUBLIC_JWK,
            "replacement_public_jwk": {
                **EXAMPLE_PUBLIC_JWK,
                "x": "replacement-public-key-x-coordinate",
                "y": "replacement-public-key-y-coordinate",
            },
            "proof_of_work_solution": 424242,
            "payload": {
                "reason": "Routine key rotation.",
            },
            "current_signature": EXAMPLE_SIGNATURE,
            "replacement_signature": EXAMPLE_SIGNATURE,
        },
    }
}

DISPUTE_EXAMPLES: dict[str, Any] = {
    "open_dispute": {
        "summary": "Open a dispute against a registered claim",
        "value": {
            **MUTATION_EXAMPLES["profile_registration"]["value"],
            "payload": {
                "claim_id": EXAMPLE_CLAIM_ID,
                "reason": "The claim appears to reference the wrong source.",
            },
        },
    },
    "resolve_dispute": {
        "summary": "Resolve a dispute as a registry administrator",
        "value": {
            **MUTATION_EXAMPLES["profile_registration"]["value"],
            "payload": {
                "status": "rejected",
                "resolution_note": "Submitted evidence did not match the claim.",
            },
        },
    },
}

OPENAPI_TAGS = [
    {
        "name": "Discovery",
        "description": "Registry metadata, deployment information, and route discovery.",
    },
    {
        "name": "Inspection",
        "description": "Inspect signed manifests, raw carrier files, and embedded claim references.",
    },
    {
        "name": "Challenges",
        "description": "Replay and proof-of-work challenges used before signed mutations.",
    },
    {
        "name": "Profiles",
        "description": "Claimant profiles, evidence summaries, domains, and key rotation.",
    },
    {
        "name": "Certificates",
        "description": "Registry-issued claimant certificates.",
    },
    {
        "name": "Claims",
        "description": "Registered content claims and claim revocation.",
    },
    {
        "name": "Disputes",
        "description": "Public dispute records attached to claims.",
    },
]


def _openapi_examples(value: dict[str, Any]) -> Any:
    return value


def _registry_info(service: RegistryService) -> dict[str, object]:
    authority = service.certificate_authority
    return {
        "registry_url": service.registry_url,
        "root_fingerprint": authority.root_fingerprint,
        "root_certificate_pem": authority.root_certificate_pem.decode("ascii"),
        "intermediate_certificate_pem": authority.intermediate_certificate_pem.decode(
            "ascii"
        ),
        "server": server_metadata(),
    }


def _json_dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], jsonable_encoder(value))


def _infer_upload_mime_type(file: UploadFile, mime_type: str | None) -> str:
    if mime_type:
        return mime_type
    if file.content_type:
        return file.content_type
    if file.filename:
        return infer_mime_type(file.filename, default=DEFAULT_BINARY_MIME_TYPE)
    return DEFAULT_BINARY_MIME_TYPE


def _raise_http_error(error: Exception) -> None:
    if isinstance(error, RegistryError):
        raise HTTPException(status_code=400, detail=str(error)) from error
    raise HTTPException(
        status_code=500, detail="internal server error"
    ) from error


def _content_security_policy(path: str) -> str:
    docs_paths = ("/api/docs", "/api/redoc", "/docs", "/redoc")
    if path.rstrip("/") in docs_paths:
        return (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; img-src 'self' data: "
            "https://fastapi.tiangolo.com; style-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' "
            "'unsafe-eval' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "
            "worker-src 'self'; connect-src 'self' https: http://localhost:* "
            "http://127.0.0.1:*"
        )
    return (
        "default-src 'self'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' "
        "https://cdn.jsdelivr.net; worker-src 'self'; connect-src 'self' "
        "https: http://localhost:* http://127.0.0.1:*"
    )


class ChallengeRequestModel(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [item["value"] for item in CHALLENGE_EXAMPLES.values()]
        }
    }

    purpose: ChallengePurpose = Field(
        description="Mutation this replay/proof-of-work challenge will authorize.",
        examples=["profile_registration"],
    )
    bound_key_id: str | None = Field(
        default=None,
        description="Optional claimant key ID that must sign the later mutation.",
        examples=["claimant-key-thumbprint"],
    )
    difficulty: int = Field(
        default=12,
        ge=0,
        le=255,
        description="Required leading zero bits for the proof-of-work solution.",
        examples=[12],
    )


class MutationRequestModel(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [item["value"] for item in MUTATION_EXAMPLES.values()]
        }
    }

    challenge_id: UUID = Field(
        description="Challenge ID returned by /api/v1/challenges.",
        examples=[EXAMPLE_CHALLENGE_ID],
    )
    claimant_public_jwk: dict[str, str] = Field(
        description="P-256 public JWK for the claimant signing this mutation.",
        examples=[EXAMPLE_PUBLIC_JWK],
    )
    proof_of_work_solution: int = Field(
        ge=0,
        description="Integer solution satisfying the challenge difficulty.",
        examples=[314159],
    )
    payload: dict[str, object] = Field(
        description="Mutation-specific data covered by the claimant signature.",
        examples=[{"signed_manifest_json": EXAMPLE_SIGNED_MANIFEST_JSON}],
    )
    signature: str = Field(
        description="ES256 signature over the challenge, public JWK, proof, and payload.",
        examples=[EXAMPLE_SIGNATURE],
    )

    def to_domain(self) -> MutationRequest:
        return MutationRequest(
            challenge_id=self.challenge_id,
            claimant_public_jwk=self.claimant_public_jwk,
            proof_of_work_solution=self.proof_of_work_solution,
            payload=self.payload,
            signature=self.signature,
        )


class CertificateIssueRequestModel(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [
                item["value"] for item in CERTIFICATE_EXAMPLES.values()
            ]
        }
    }

    request: MutationRequestModel = Field(
        description="Claimant-signed certificate issuance request."
    )
    valid_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Certificate validity period requested from the registry.",
        examples=[30],
    )


class RotationRequestModel(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [item["value"] for item in ROTATION_EXAMPLES.values()]
        }
    }

    challenge_id: UUID = Field(
        description="Key-rotation challenge ID returned by /api/v1/challenges.",
        examples=[EXAMPLE_CHALLENGE_ID],
    )
    current_public_jwk: dict[str, str] = Field(
        description="Current claimant public JWK.",
        examples=[EXAMPLE_PUBLIC_JWK],
    )
    replacement_public_jwk: dict[str, str] = Field(
        description="Replacement claimant public JWK.",
        examples=[
            ROTATION_EXAMPLES["key_rotation"]["value"][
                "replacement_public_jwk"
            ]
        ],
    )
    proof_of_work_solution: int = Field(
        ge=0,
        description="Integer solution satisfying the rotation challenge.",
        examples=[424242],
    )
    payload: dict[str, object] = Field(
        description="Rotation metadata covered by both signatures.",
        examples=[{"reason": "Routine key rotation."}],
    )
    current_signature: str = Field(
        description="ES256 signature from the current key.",
        examples=[EXAMPLE_SIGNATURE],
    )
    replacement_signature: str = Field(
        description="ES256 signature from the replacement key.",
        examples=[EXAMPLE_SIGNATURE],
    )

    def to_domain(self) -> KeyRotationRequest:
        return KeyRotationRequest(
            challenge_id=self.challenge_id,
            current_public_jwk=self.current_public_jwk,
            replacement_public_jwk=self.replacement_public_jwk,
            proof_of_work_solution=self.proof_of_work_solution,
            payload=self.payload,
            current_signature=self.current_signature,
            replacement_signature=self.replacement_signature,
        )


def create_app(
    service: RegistryService | None = None,
    *,
    public_base_url: str,
    registry_url: str | None = None,
    local_mode: bool = False,
    enable_workspace: bool = False,
    cors_allowed_origins: tuple[str, ...] = (),
    docs_directory: str | Path | None = None,
    rate_limit_config: RateLimitConfig | None = None,
) -> FastAPI:
    """Build the registry API and proof-page application."""

    templates = _templates()
    rate_limit = rate_limit_config or RateLimitConfig()
    parsed_public_url = urlsplit(public_base_url)
    normalized_registry_url = (
        service.registry_url if service is not None else registry_url
    )
    if normalized_registry_url is None:
        raise ValueError("registry_url is required when service is omitted")
    allowed_hosts = [parsed_public_url.hostname or "localhost"]
    if local_mode:
        allowed_hosts.extend(["127.0.0.1", "localhost"])
    app = FastAPI(
        title="PACT Registry",
        version=PACKAGE_VERSION,
        summary="Registry API and proof pages for PACT",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        openapi_tags=OPENAPI_TAGS,
        middleware=[
            Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
        ],
    )
    app.state.registry_service = service
    app.state.public_base_url = public_base_url.rstrip("/")
    app.state.registry_url = normalized_registry_url
    app.state.local_mode = local_mode
    app.state.enable_workspace = enable_workspace
    app.state.rate_limiter = SlidingWindowRateLimiter(rate_limit)
    app.state.rate_limit_config = rate_limit
    mounted_docs_directory = _docs_directory(docs_directory)
    app.state.docs_enabled = mounted_docs_directory is not None
    if cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_allowed_origins),
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["content-type"],
        )
    if enable_workspace:
        app.mount(
            "/static",
            StaticFiles(directory=str(_static_directory())),
            name="static",
        )
    if mounted_docs_directory is not None:
        app.mount(
            "/docs",
            StaticFiles(directory=str(mounted_docs_directory), html=True),
            name="docs",
        )

    def enforce_identity_rate(
        request: Request,
        body: object,
        *,
        extra: Iterable[str | None] = (),
    ) -> None:
        if not rate_limit.enabled:
            return
        limiter = cast(SlidingWindowRateLimiter, app.state.rate_limiter)
        for key in _request_identity_keys(request, body=body, extra=extra):
            decision = limiter.check(
                f"identity:{key}",
                limit=rate_limit.identity_limit,
            )
            if not decision.allowed:
                raise HTTPException(
                    status_code=429,
                    detail="rate limit exceeded",
                    headers={
                        "Retry-After": str(decision.retry_after),
                        "X-RateLimit-Limit": str(decision.limit),
                        "X-RateLimit-Remaining": str(decision.remaining),
                        "X-RateLimit-Reset": str(decision.reset_seconds),
                    },
                )

    @app.middleware("http")
    async def rate_limit_requests(request: Request, call_next):
        if (
            rate_limit.enabled
            and request.url.path.startswith("/api/")
            and request.method != "OPTIONS"
        ):
            limiter = cast(SlidingWindowRateLimiter, app.state.rate_limiter)
            decision = limiter.check(
                f"ip:{_client_ip(request)}",
                limit=rate_limit.ip_limit,
            )
            if not decision.allowed:
                return _rate_limit_response(decision)
            response = await call_next(request)
            response.headers.setdefault(
                "X-RateLimit-Limit",
                str(decision.limit),
            )
            response.headers.setdefault(
                "X-RateLimit-Remaining",
                str(decision.remaining),
            )
            response.headers.setdefault(
                "X-RateLimit-Reset",
                str(decision.reset_seconds),
            )
            return response
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            _content_security_policy(request.url.path),
        )
        if local_mode:
            response.headers.setdefault("Cache-Control", "no-store")
        elif parsed_public_url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "home.html",
            {
                "registry_url": app.state.registry_url,
                "workspace_enabled": enable_workspace,
                "public_base_url": app.state.public_base_url,
                "local_mode": local_mode,
                "docs_enabled": app.state.docs_enabled,
            },
        )

    @app.get("/pact", response_class=HTMLResponse)
    async def workspace(request: Request) -> HTMLResponse:
        if not enable_workspace:
            raise HTTPException(status_code=404, detail="workspace disabled")
        return templates.TemplateResponse(
            request,
            "workspace.html",
            {
                "registry_url": app.state.registry_url,
                "public_base_url": app.state.public_base_url,
                "standalone": service is None,
            },
        )

    @app.get("/pact/pact-browser-{feature}.pyz")
    async def browser_python_feature(feature: str) -> Response:
        if not enable_workspace:
            raise HTTPException(status_code=404, detail="workspace disabled")
        if feature not in FEATURE_MODULES:
            raise HTTPException(status_code=404, detail="unknown feature pack")
        return Response(
            browser_python_archive(feature),
            media_type="application/zip",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    if service is None:
        return app

    @app.get(
        "/api/v1/registry",
        tags=["Discovery"],
        summary="Registry metadata",
        description="Return registry certificates, root fingerprint, package version, and deployment metadata.",
    )
    async def registry_info() -> PrettyJSONResponse:
        return PrettyJSONResponse(_registry_info(service))

    @app.get(
        "/api/v1/server/routes",
        tags=["Discovery"],
        summary="Route map",
        description="List public, claimant-signed, and administrator routes exposed by this deployment.",
    )
    async def server_routes() -> PrettyJSONResponse:
        routes = [route.to_dict() for route in default_routes()]
        if app.state.docs_enabled:
            routes.append(
                {
                    "name": "documentation",
                    "method": "GET",
                    "path": "/docs/",
                    "auth": "public",
                    "lambda_name": None,
                    "permission": None,
                }
            )
        return PrettyJSONResponse({"routes": routes})

    @app.get(
        "/api/v1/server/info",
        tags=["Discovery"],
        summary="Server information",
        description="Return public base URL, optional documentation URL, package version, and deployed commit hash.",
    )
    async def server_info() -> PrettyJSONResponse:
        return PrettyJSONResponse(
            {
                "registry_url": app.state.registry_url,
                "public_base_url": app.state.public_base_url,
                "documentation_url": f"{app.state.public_base_url}/docs/"
                if app.state.docs_enabled
                else None,
                "server": server_metadata(),
            }
        )

    @app.post(
        "/api/v1/inspect",
        tags=["Inspection"],
        summary="Inspect a manifest or raw carrier file",
        description=(
            "Upload signed manifest JSON or raw media. The server attempts to "
            "recover embedded PACT manifests, claim locators, watermarks, or "
            "C2PA references, then resolves matching registry claims when possible."
        ),
    )
    async def inspect_upload(
        file: UploadFile = File(
            description="Manifest JSON or raw media carrier to inspect.",
            examples=["signed-manifest.json", "work.txt", "image.png"],
        ),
        mime_type: str | None = Form(
            default=None,
            description="Optional MIME type override for carrier parsing.",
        ),
    ) -> dict[str, object]:
        payload = await file.read()
        try:
            return inspect_content(
                payload,
                mime_type=_infer_upload_mime_type(file, mime_type),
                registry_service=service,
            )
        except Exception as error:
            _raise_http_error(error)
            raise AssertionError("unreachable")

    @app.post(
        "/api/v1/challenges",
        tags=["Challenges"],
        summary="Issue a replay and proof-of-work challenge",
        description=(
            "Create a short-lived challenge that must be included in a later "
            "claimant-signed mutation request."
        ),
    )
    async def issue_challenge(
        request: Request,
        body: Annotated[
            ChallengeRequestModel,
            Body(openapi_examples=_openapi_examples(CHALLENGE_EXAMPLES)),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body, extra=(body.purpose.value,))
        challenge = service.issue_challenge(
            body.purpose,
            bound_key_id=body.bound_key_id,
            difficulty=body.difficulty,
        )
        return _json_dict(challenge.to_dict())

    @app.post(
        "/api/v1/profiles",
        tags=["Profiles"],
        summary="Register a claimant profile",
        description=(
            "Register a claimant public key and device binding. The body must "
            "be signed by the claimant key and paired with a profile-registration challenge."
        ),
    )
    async def register_profile(
        request: Request,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {
                        "profile_registration": MUTATION_EXAMPLES[
                            "profile_registration"
                        ]
                    }
                )
            ),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            profile = service.register_profile(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.get(
        "/api/v1/profiles/{key_id}",
        tags=["Profiles"],
        summary="Get claimant profile",
    )
    async def get_profile(key_id: str) -> dict[str, object]:
        try:
            profile = service.get_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post(
        "/api/v1/profiles/{key_id}/update",
        tags=["Profiles"],
        summary="Update claimant profile",
    )
    async def update_profile(
        request: Request,
        key_id: str,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {
                        "profile_update": {
                            "summary": "Update display name",
                            "value": MUTATION_EXAMPLES["profile_registration"][
                                "value"
                            ],
                        }
                    }
                )
            ),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body, extra=(key_id,))
        if body.to_domain().claimant_key_id != key_id:
            raise HTTPException(
                status_code=400,
                detail="profile update signer must match the path key",
            )
        try:
            profile = service.update_profile(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.get(
        "/api/v1/profiles/{key_id}/evidence",
        tags=["Profiles"],
        summary="Get claimant evidence summary",
    )
    async def get_profile_evidence(key_id: str) -> dict[str, object]:
        try:
            evidence = service.evidence_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(evidence)

    @app.get(
        "/api/v1/profiles/{key_id}/claims",
        tags=["Claims"],
        summary="List claims by claimant profile",
    )
    async def list_profile_claims(key_id: str) -> dict[str, object]:
        try:
            claims = service.list_claims(claimant_key_id=key_id)
        except Exception as error:
            _raise_http_error(error)
        return {"claims": jsonable_encoder(claims)}

    @app.get(
        "/api/v1/profiles/{key_id}/disputes",
        tags=["Disputes"],
        summary="List disputes attached to a claimant profile",
    )
    async def list_profile_disputes(key_id: str) -> dict[str, object]:
        try:
            disputes = service.list_disputes(claimant_key_id=key_id)
        except Exception as error:
            _raise_http_error(error)
        return {"disputes": jsonable_encoder(disputes)}

    @app.post(
        "/api/v1/certificates",
        tags=["Certificates"],
        summary="Issue claimant certificate",
        description="Issue a short-lived claimant certificate after key-possession proof.",
    )
    async def issue_certificate(
        request: Request,
        body: Annotated[
            CertificateIssueRequestModel,
            Body(openapi_examples=_openapi_examples(CERTIFICATE_EXAMPLES)),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            certificate_pem, chain_pem = service.issue_claimant_certificate(
                body.request.to_domain(),
                valid_days=body.valid_days,
            )
        except Exception as error:
            _raise_http_error(error)
        return {
            "certificate_pem": certificate_pem.decode("ascii"),
            "chain_pem": chain_pem.decode("ascii"),
        }

    @app.post(
        "/api/v1/claims",
        tags=["Claims"],
        summary="Register signed claim",
        description="Publish a signed manifest as a registry claim.",
    )
    async def register_claim(
        request: Request,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {
                        "claim_registration": MUTATION_EXAMPLES[
                            "claim_registration"
                        ]
                    }
                )
            ),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            claim = service.register_claim(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(claim)

    @app.get(
        "/api/v1/claims/{claim_id}",
        tags=["Claims"],
        summary="Get registered claim",
    )
    async def get_claim(claim_id: UUID) -> dict[str, object]:
        try:
            claim = service.get_claim(claim_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(claim)

    @app.get(
        "/api/v1/claims/{claim_id}/disputes",
        tags=["Disputes"],
        summary="List disputes attached to a claim",
    )
    async def list_claim_disputes(claim_id: UUID) -> dict[str, object]:
        try:
            disputes = service.list_disputes(claim_id=claim_id)
        except Exception as error:
            _raise_http_error(error)
        return {"disputes": jsonable_encoder(disputes)}

    @app.post(
        "/api/v1/claims/{claim_id}/revoke",
        tags=["Claims"],
        summary="Revoke registered claim",
        description="Revoke an existing claim. The claim ID is supplied in the path and added to the signed mutation payload by the server.",
    )
    async def revoke_claim(
        request: Request,
        claim_id: UUID,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {"claim_revocation": MUTATION_EXAMPLES["claim_revocation"]}
                )
            ),
        ],
    ) -> dict[str, object]:
        request_model = MutationRequest(
            challenge_id=body.challenge_id,
            claimant_public_jwk=body.claimant_public_jwk,
            proof_of_work_solution=body.proof_of_work_solution,
            payload={**body.payload, "claim_id": str(claim_id)},
            signature=body.signature,
        )
        enforce_identity_rate(request, body, extra=(str(claim_id),))
        try:
            claim = service.revoke_claim(request_model)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(claim)

    @app.post(
        "/api/v1/rotations",
        tags=["Profiles"],
        summary="Rotate claimant key",
        description="Rotate a claimant key using signatures from both the current and replacement keys.",
    )
    async def rotate_key(
        request: Request,
        body: Annotated[
            RotationRequestModel,
            Body(openapi_examples=_openapi_examples(ROTATION_EXAMPLES)),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            profile = service.rotate_key(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post(
        "/api/v1/domains/verify",
        tags=["Profiles"],
        summary="Verify claimant domain",
    )
    async def verify_domain(
        request: Request,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {
                        "domain_verification": {
                            "summary": "Attach a DNS-verified domain to a claimant profile",
                            "value": MUTATION_EXAMPLES["domain_verification"][
                                "value"
                            ],
                        }
                    }
                )
            ),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            profile = service.verify_domain(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post(
        "/api/v1/profiles/{key_id}/hosted-authorize",
        tags=["Profiles"],
        summary="Authorize hosted-account trust",
        description=(
            "Administrative endpoint for recording hosted-account evidence. "
            "This produces the same trust tier as a registry-host login flow."
        ),
    )
    async def authorize_hosted_account(
        request: Request,
        key_id: str,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {
                        "hosted_account_authorization": MUTATION_EXAMPLES[
                            "hosted_account_authorization"
                        ]
                    }
                )
            ),
        ],
    ) -> dict[str, object]:
        request_model = MutationRequest(
            challenge_id=body.challenge_id,
            claimant_public_jwk=body.claimant_public_jwk,
            proof_of_work_solution=body.proof_of_work_solution,
            payload={**body.payload, "target_key_id": key_id},
            signature=body.signature,
        )
        enforce_identity_rate(request, body, extra=(key_id,))
        try:
            profile = service.authorize_hosted_account(request_model)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post(
        "/api/v1/profiles/me/hosted-login",
        tags=["Profiles"],
        summary="Complete hosted-account login",
    )
    async def complete_hosted_account_login(
        request: Request,
        body: MutationRequestModel,
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            profile = service.complete_hosted_account_login(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post(
        "/api/v1/profiles/{key_id}/third-party-attest",
        tags=["Profiles"],
        summary="Record third-party account attestation",
    )
    async def attest_third_party_account(
        request: Request,
        key_id: str,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {
                        "third_party_attestation": MUTATION_EXAMPLES[
                            "third_party_attestation"
                        ]
                    }
                )
            ),
        ],
    ) -> dict[str, object]:
        request_model = MutationRequest(
            challenge_id=body.challenge_id,
            claimant_public_jwk=body.claimant_public_jwk,
            proof_of_work_solution=body.proof_of_work_solution,
            payload={**body.payload, "target_key_id": key_id},
            signature=body.signature,
        )
        enforce_identity_rate(request, body, extra=(key_id,))
        try:
            profile = service.attest_third_party_account(request_model)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post(
        "/api/v1/disputes",
        tags=["Disputes"],
        summary="Open claim dispute",
    )
    async def open_dispute(
        request: Request,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {"open_dispute": DISPUTE_EXAMPLES["open_dispute"]}
                )
            ),
        ],
    ) -> dict[str, object]:
        enforce_identity_rate(request, body)
        try:
            dispute = service.open_dispute(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(dispute)

    @app.get(
        "/api/v1/disputes/{dispute_id}",
        tags=["Disputes"],
        summary="Get dispute record",
    )
    async def get_dispute(dispute_id: UUID) -> dict[str, object]:
        try:
            dispute = service.get_dispute(dispute_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(dispute)

    @app.post(
        "/api/v1/disputes/{dispute_id}/resolve",
        tags=["Disputes"],
        summary="Resolve claim dispute",
        description="Administrative endpoint for resolving an open dispute.",
    )
    async def resolve_dispute(
        request: Request,
        dispute_id: UUID,
        body: Annotated[
            MutationRequestModel,
            Body(
                openapi_examples=_openapi_examples(
                    {"resolve_dispute": DISPUTE_EXAMPLES["resolve_dispute"]}
                )
            ),
        ],
    ) -> dict[str, object]:
        request_model = MutationRequest(
            challenge_id=body.challenge_id,
            claimant_public_jwk=body.claimant_public_jwk,
            proof_of_work_solution=body.proof_of_work_solution,
            payload={
                **body.payload,
                "dispute_id": str(dispute_id),
            },
            signature=body.signature,
        )
        enforce_identity_rate(request, body, extra=(str(dispute_id),))
        try:
            dispute = service.resolve_dispute(request_model)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(dispute)

    @app.get("/profiles/{key_id}", response_class=HTMLResponse)
    async def public_profile(request: Request, key_id: str) -> HTMLResponse:
        try:
            profile = service.get_profile(key_id)
            evidence = service.evidence_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return templates.TemplateResponse(
            request,
            "profile.html",
            {
                "profile": jsonable_encoder(profile),
                "evidence": jsonable_encoder(evidence),
                "public_base_url": app.state.public_base_url,
            },
        )

    @app.get("/claims/{claim_id}", response_class=HTMLResponse)
    async def public_claim(request: Request, claim_id: UUID) -> HTMLResponse:
        try:
            claim = service.get_claim(claim_id)
            profile = service.get_profile(claim.claimant_key_id)
        except Exception as error:
            _raise_http_error(error)
        return templates.TemplateResponse(
            request,
            "claim.html",
            {
                "claim": jsonable_encoder(claim),
                "profile": jsonable_encoder(profile),
                "public_base_url": app.state.public_base_url,
            },
        )

    @app.get("/verify/claim/{claim_id}", response_class=HTMLResponse)
    async def verify_claim_page(
        request: Request,
        claim_id: UUID,
    ) -> HTMLResponse:
        try:
            claim = service.get_claim(claim_id)
            profile = service.get_profile(claim.claimant_key_id)
            verification = service.verify_claim(claim_id)
        except Exception as error:
            _raise_http_error(error)
        return templates.TemplateResponse(
            request,
            "verify_claim.html",
            {
                "claim": jsonable_encoder(claim),
                "profile": jsonable_encoder(profile),
                "verification": jsonable_encoder(verification),
            },
        )

    return app
