"""FastAPI application for the registry API and proof pages."""

import asyncio
import hashlib
import io
import ipaddress
import json
import time
import zipfile
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

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
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pact.canonical import JsonValue, canonical_json
from pact.crypto import jwk_thumbprint, public_key_from_jwk, verify_es256
from pact.inspection import inspect_content
from pact.manifest import SignedManifest
from pact.media import DEFAULT_BINARY_MIME_TYPE, infer_mime_type
from pact.metadata import PACKAGE_VERSION, server_metadata
from pact.oprf import OprfError
from pact.registry.app import (
    AvoidanceReportLabel,
    ChallengePurpose,
    KeyRotationRequest,
    MutationRequest,
    RegistryError,
    RegistryService,
)
from pact.server.config import default_routes
from pact.server.logging import (
    LoggingConfig,
    configure_logging,
    monotonic_ms,
    request_log_extra,
    server_logger,
)
from pact.web.browser_bundle import FEATURE_MODULES, browser_python_archive

LOGGER = server_logger("web")


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Sliding-window limits for API requests."""

    window_seconds: int = 60
    ip_limit: int = 300
    identity_limit: int = 60
    anonymous_upload_limit: int = 20
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class UploadLimitConfig:
    max_request_body_bytes: int = 25 * 1024 * 1024
    max_upload_bytes: int = 20 * 1024 * 1024
    media_parse_timeout_seconds: float = 10.0
    max_zip_entries: int = 100
    max_zip_uncompressed_bytes: int = 50 * 1024 * 1024
    max_zip_compression_ratio: int = 100


@dataclass(frozen=True, slots=True)
class TrustedProxyConfig:
    trusted_proxy_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ChallengeDifficultyConfig:
    default_minimum: int = 4
    profile_registration: int = 4
    account_authorization: int = 8
    claim_registration: int = 4

    def minimum_for(self, purpose: ChallengePurpose) -> int:
        if purpose is ChallengePurpose.PROFILE_REGISTRATION:
            return self.profile_registration
        if purpose is ChallengePurpose.ACCOUNT_AUTHORIZATION:
            return self.account_authorization
        if purpose is ChallengePurpose.CLAIM_REGISTRATION:
            return self.claim_registration
        return self.default_minimum


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


def _request_id(value: str | None) -> str:
    if value is None:
        return uuid4().hex
    normalized = "".join(
        character
        for character in value.strip()
        if character.isascii() and (character.isalnum() or character in "-_.")
    )
    if not normalized:
        return uuid4().hex
    return normalized[:64]


def _client_ip(
    request: Request,
    trusted_proxy_config: TrustedProxyConfig | None = None,
) -> str:
    direct_ip = request.client.host if request.client is not None else None
    if not _trusted_proxy_peer(direct_ip, trusted_proxy_config):
        return direct_ip or "unknown"

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


def _trusted_proxy_peer(
    direct_ip: str | None,
    config: TrustedProxyConfig | None,
) -> bool:
    if direct_ip is None or config is None or not config.trusted_proxy_cidrs:
        return False
    if direct_ip in config.trusted_proxy_cidrs:
        return True
    try:
        address = ipaddress.ip_address(direct_ip)
    except ValueError:
        return False
    for cidr in config.trusted_proxy_cidrs:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


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


def _profile_auth_signed_bytes(
    *,
    challenge: object,
    key_id: str,
    method: str,
    path: str,
    body: object,
) -> bytes:
    if isinstance(body, BaseModel):
        body = body.model_dump(
            mode="json",
            exclude_none=True,
            exclude_unset=True,
        )
    challenge_dict = (
        cast(Any, challenge).to_dict()
        if hasattr(challenge, "to_dict")
        else challenge
    )
    body_bytes = canonical_json(cast(JsonValue, body))
    return canonical_json(
        cast(
            JsonValue,
            {
                "challenge": challenge_dict,
                "profile_key_id": key_id,
                "method": method.upper(),
                "path": path,
                "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            },
        )
    )


def _require_profile_request_auth(
    request: Request,
    service: RegistryService,
    body: object,
) -> str:
    key_id = request.headers.get("x-pact-profile-key-id", "").strip()
    challenge_id_text = request.headers.get("x-pact-challenge-id", "").strip()
    solution_text = request.headers.get(
        "x-pact-proof-of-work-solution", ""
    ).strip()
    signature = request.headers.get("x-pact-signature", "").strip()
    if (
        not key_id
        or not challenge_id_text
        or not solution_text
        or not signature
    ):
        raise HTTPException(
            status_code=401,
            detail="signed registered profile proof is required",
        )
    try:
        challenge_id = UUID(challenge_id_text)
        solution = int(solution_text)
    except ValueError as error:
        raise HTTPException(
            status_code=401,
            detail="profile proof headers are invalid",
        ) from error
    try:
        profile = service.get_profile(key_id)
        challenge = service._consume_challenge(  # noqa: SLF001
            challenge_id,
            ChallengePurpose.ACCOUNT_AUTHORIZATION,
        )
        if (
            challenge.bound_key_id is not None
            and challenge.bound_key_id != key_id
        ):
            raise RegistryError("challenge is bound to a different profile")
        if not challenge.verify_solution(solution):
            raise RegistryError("proof-of-work solution is invalid")
        public_key = public_key_from_jwk(profile.public_jwk)
        signed_bytes = _profile_auth_signed_bytes(
            challenge=challenge,
            key_id=key_id,
            method=request.method,
            path=request.url.path,
            body=body,
        )
        if not verify_es256(public_key, signed_bytes, signature):
            raise RegistryError("profile proof signature is invalid")
    except Exception as error:
        if isinstance(error, HTTPException):
            raise
        raise HTTPException(status_code=401, detail=str(error)) from error
    return key_id


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
    {
        "name": "Reports",
        "description": "Possible provenance avoidance reports for public-verification claims.",
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
    return cast(dict[str, object], _public_jsonable(value))


def _public_jsonable(value: object) -> object:
    encoded = jsonable_encoder(value)
    return _drop_private_public_fields(encoded)


def _drop_private_public_fields(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _drop_private_public_fields(item)
            for key, item in value.items()
            if key not in {"device_fingerprint"}
        }
    if isinstance(value, list):
        return [_drop_private_public_fields(item) for item in value]
    return value


def _infer_upload_mime_type(file: UploadFile, mime_type: str | None) -> str:
    if mime_type:
        return mime_type
    if file.content_type:
        return file.content_type
    if file.filename:
        return infer_mime_type(file.filename, default=DEFAULT_BINARY_MIME_TYPE)
    return DEFAULT_BINARY_MIME_TYPE


async def _read_upload_limited(
    file: UploadFile,
    limits: UploadLimitConfig,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limits.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail="uploaded file is too large",
            )
        chunks.append(chunk)
    payload = b"".join(chunks)
    _check_zip_limits(payload, limits)
    return payload


def _check_zip_limits(payload: bytes, limits: UploadLimitConfig) -> None:
    if not zipfile.is_zipfile(io.BytesIO(payload)):
        return
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as error:
        raise HTTPException(
            status_code=400, detail="invalid ZIP file"
        ) from error
    with archive:
        entries = archive.infolist()
        if len(entries) > limits.max_zip_entries:
            raise HTTPException(
                status_code=413,
                detail="ZIP file contains too many entries",
            )
        uncompressed_total = 0
        for entry in entries:
            if entry.flag_bits & 0x1:
                raise HTTPException(
                    status_code=400,
                    detail="encrypted ZIP entries are not supported",
                )
            if (
                entry.filename.startswith("/")
                or ".." in Path(entry.filename).parts
            ):
                raise HTTPException(
                    status_code=400,
                    detail="unsafe ZIP entry path",
                )
            uncompressed_total += entry.file_size
            if uncompressed_total > limits.max_zip_uncompressed_bytes:
                raise HTTPException(
                    status_code=413,
                    detail="ZIP file expands beyond the configured limit",
                )
            if (
                entry.compress_size
                and entry.file_size / entry.compress_size
                > limits.max_zip_compression_ratio
            ):
                raise HTTPException(
                    status_code=413,
                    detail="ZIP compression ratio is too high",
                )


async def _inspect_content_limited(
    payload: bytes,
    *,
    mime_type: str,
    registry_service: RegistryService,
    limits: UploadLimitConfig,
) -> dict[str, object]:
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                inspect_content,
                payload,
                mime_type=mime_type,
                registry_service=registry_service,
            ),
            timeout=limits.media_parse_timeout_seconds,
        )
    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail="media parsing timed out",
        ) from error


def _raise_http_error(error: Exception) -> None:
    if isinstance(error, HTTPException):
        raise error
    if isinstance(error, RegistryError):
        LOGGER.warning("registry request rejected: %s", error)
        raise HTTPException(status_code=400, detail=str(error)) from error
    LOGGER.exception("unhandled application error")
    raise HTTPException(
        status_code=500, detail="internal server error"
    ) from error


def _content_security_policy(path: str, *, local_mode: bool = False) -> str:
    workspace_connect = (
        "connect-src 'self' blob: https://cdn.jsdelivr.net "
        "https://files.pythonhosted.org"
    )
    if local_mode:
        workspace_connect = (
            f"{workspace_connect} http://localhost:* http://127.0.0.1:*"
        )
    if (
        path == "/pact/web"
        or path.startswith("/pact/web/")
        or path.startswith("/pact/static/")
    ):
        return (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' "
            f"https://cdn.jsdelivr.net blob:; worker-src 'self'; "
            f"{workspace_connect}"
        )
    docs_paths = (
        "/pact/api/docs",
        "/pact/api/redoc",
        "/pact/docs",
        "/pact/redoc",
    )
    if path.rstrip("/") in docs_paths:
        return (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; img-src 'self' data: "
            "https://fastapi.tiangolo.com; style-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; worker-src 'self'; connect-src 'self'"
        )
    return (
        "default-src 'self'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; worker-src 'self'; connect-src 'self'"
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


class DeviceBindingOprfRequestModel(BaseModel):
    blinded: str = Field(
        description="Base64url Ristretto255 blinded OPRF group element.",
        examples=["base64url-blinded-oprf-element"],
    )


class MutationRequestModel(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [item["value"] for item in MUTATION_EXAMPLES.values()]
        }
    }

    challenge_id: UUID = Field(
        description="Challenge ID returned by /pact/api/v1/challenges.",
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
        description="Key-rotation challenge ID returned by /pact/api/v1/challenges.",
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


class AvoidanceEvidenceModel(BaseModel):
    kind: str = Field(
        default="hash_only",
        description="Evidence kind such as submitted_file, screenshot, url_snapshot, html_capture, or hash_only.",
    )
    digest: str = Field(description="Digest of the evidence object.")
    mime_type: str | None = Field(default=None)


class AvoidanceReportRequestModel(BaseModel):
    claim_id: UUID
    observed_url: str | None = Field(default=None)
    observed_at: datetime | None = Field(default=None)
    reason: AvoidanceReportLabel = Field(
        default=AvoidanceReportLabel.POSSIBLE_AVOIDANCE
    )
    description: str | None = Field(default=None)
    evidence: AvoidanceEvidenceModel
    reverse_lookup_score: float | None = Field(default=None, ge=0, le=1)
    reverse_lookup_evidence: list[dict[str, object]] = Field(
        default_factory=list
    )
    reporter_key_id: str | None = Field(default=None)
    reporter_type: str = Field(default="anonymous")


class ClaimMatchRequestModel(BaseModel):
    signed_manifest_json: str = Field(
        description="Signed manifest JSON to compare against registered claims."
    )
    limit: int = Field(default=10, ge=1, le=25)


def create_app(
    service: RegistryService | None = None,
    *,
    public_base_url: str,
    registry_url: str | None = None,
    local_mode: bool = False,
    enable_workspace: bool = False,
    allowed_hosts: tuple[str, ...] = (),
    cors_allowed_origins: tuple[str, ...] = (),
    docs_directory: str | Path | None = None,
    rate_limit_config: RateLimitConfig | None = None,
    upload_limit_config: UploadLimitConfig | None = None,
    trusted_proxy_config: TrustedProxyConfig | None = None,
    challenge_difficulty_config: ChallengeDifficultyConfig | None = None,
    logging_config: LoggingConfig | None = None,
) -> FastAPI:
    """Build the registry API and proof-page application."""

    selected_logging = logging_config or LoggingConfig.from_env()
    configure_logging(selected_logging)
    templates = _templates()
    rate_limit = rate_limit_config or RateLimitConfig()
    upload_limits = upload_limit_config or UploadLimitConfig()
    trusted_proxies = trusted_proxy_config or TrustedProxyConfig()
    challenge_difficulty = (
        challenge_difficulty_config or ChallengeDifficultyConfig()
    )
    parsed_public_url = urlsplit(public_base_url)
    normalized_registry_url = (
        service.registry_url if service is not None else registry_url
    )
    if normalized_registry_url is None:
        raise ValueError("registry_url is required when service is omitted")
    trusted_hosts = list(allowed_hosts) or [
        parsed_public_url.hostname or "localhost"
    ]
    if local_mode:
        trusted_hosts.extend(["127.0.0.1", "localhost"])
    app = FastAPI(
        title="PACT Registry",
        version=PACKAGE_VERSION,
        summary="Registry API and proof pages for PACT",
        docs_url="/pact/api/docs",
        redoc_url="/pact/api/redoc",
        openapi_url="/pact/api/openapi.json",
        openapi_tags=OPENAPI_TAGS,
        middleware=[
            Middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts),
        ],
    )
    app.state.registry_service = service
    app.state.public_base_url = public_base_url.rstrip("/")
    app.state.registry_url = normalized_registry_url
    app.state.local_mode = local_mode
    app.state.enable_workspace = enable_workspace
    app.state.rate_limiter = SlidingWindowRateLimiter(rate_limit)
    app.state.rate_limit_config = rate_limit
    app.state.upload_limit_config = upload_limits
    app.state.trusted_proxy_config = trusted_proxies
    app.state.challenge_difficulty_config = challenge_difficulty
    app.state.logging_config = selected_logging
    LOGGER.info(
        "created web application",
        extra={
            "registry_url": normalized_registry_url,
            "deployment_mode": "local" if local_mode else "hosted",
        },
    )
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
            "/pact/static",
            StaticFiles(directory=str(_static_directory())),
            name="static",
        )
    if mounted_docs_directory is not None:
        app.mount(
            "/pact/docs",
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

    def client_ip(request: Request) -> str:
        return _client_ip(request, trusted_proxies)

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        request_id = _request_id(request.headers.get("x-request-id"))
        request.state.request_id = request_id
        started_ms = monotonic_ms()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            duration_ms = monotonic_ms() - started_ms
            LOGGER.exception(
                "request failed",
                extra=request_log_extra(
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    client_ip=client_ip(request),
                ),
            )
            raise
        finally:
            duration_ms = monotonic_ms() - started_ms
            if selected_logging.access_log:
                level = "warning" if status_code >= 400 else "info"
                getattr(LOGGER, level)(
                    "request complete",
                    extra=request_log_extra(
                        request_id=request_id,
                        method=request.method,
                        path=request.url.path,
                        status_code=status_code,
                        duration_ms=duration_ms,
                        client_ip=client_ip(request),
                    ),
                )

    @app.middleware("http")
    async def enforce_request_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                request_size = int(content_length)
            except ValueError:
                return JSONResponse(
                    {"detail": "content-length is invalid"},
                    status_code=400,
                )
            if request_size > upload_limits.max_request_body_bytes:
                return JSONResponse(
                    {"detail": "request body is too large"},
                    status_code=413,
                )
        return await call_next(request)

    @app.middleware("http")
    async def rate_limit_requests(request: Request, call_next):
        if (
            rate_limit.enabled
            and request.url.path.startswith("/pact/api/")
            and request.method != "OPTIONS"
        ):
            limiter = cast(SlidingWindowRateLimiter, app.state.rate_limiter)
            limit = rate_limit.ip_limit
            if request.url.path in {
                "/pact/api/v1/inspect",
                "/pact/api/v1/recover",
            }:
                limit = rate_limit.anonymous_upload_limit
            decision = limiter.check(
                f"ip:{client_ip(request)}",
                limit=limit,
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
        request_id = getattr(request.state, "request_id", None)
        if request_id is not None:
            response.headers.setdefault("X-Request-ID", request_id)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            _content_security_policy(request.url.path, local_mode=local_mode),
        )
        if local_mode:
            response.headers.setdefault("Cache-Control", "no-store")
        elif parsed_public_url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.get("/", response_class=RedirectResponse)
    async def root() -> RedirectResponse:
        return RedirectResponse("/pact", status_code=308)

    @app.get("/pact", response_class=HTMLResponse)
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

    @app.get("/pact/web", response_class=HTMLResponse)
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

    @app.get("/pact/web/pact-browser-{feature}.pyz")
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
    registry_service = service

    @app.get(
        "/pact/api/v1/registry",
        tags=["Discovery"],
        summary="Registry metadata",
        description="Return registry certificates, root fingerprint, package version, and deployment metadata.",
    )
    async def registry_info() -> PrettyJSONResponse:
        return PrettyJSONResponse(_registry_info(service))

    @app.get(
        "/pact/api/v1/server/routes",
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
                    "path": "/pact/docs/",
                    "auth": "public",
                    "lambda_name": None,
                    "permission": None,
                }
            )
        return PrettyJSONResponse({"routes": routes})

    @app.get(
        "/pact/api/v1/server/info",
        tags=["Discovery"],
        summary="Server information",
        description="Return public base URL, optional documentation URL, package version, and deployed commit hash.",
    )
    async def server_info() -> PrettyJSONResponse:
        return PrettyJSONResponse(
            {
                "registry_url": app.state.registry_url,
                "public_base_url": app.state.public_base_url,
                "documentation_url": f"{app.state.public_base_url}/pact/docs/"
                if app.state.docs_enabled
                else None,
                "server": server_metadata(),
            }
        )

    @app.post(
        "/pact/api/v1/inspect",
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
        try:
            payload = await _read_upload_limited(file, upload_limits)
            return await _inspect_content_limited(
                payload,
                mime_type=_infer_upload_mime_type(file, mime_type),
                registry_service=service,
                limits=upload_limits,
            )
        except Exception as error:
            _raise_http_error(error)
            raise AssertionError("unreachable")

    @app.post(
        "/pact/api/v1/challenges",
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
        difficulty = max(
            body.difficulty,
            challenge_difficulty.minimum_for(body.purpose),
        )
        challenge = service.issue_challenge(
            body.purpose,
            bound_key_id=body.bound_key_id,
            difficulty=difficulty,
        )
        return _json_dict(challenge.to_dict())

    @app.post(
        "/pact/api/v1/device-bindings/oprf",
        tags=["Profiles"],
        summary="Evaluate a blinded device-binding OPRF point",
        description=(
            "Evaluate a client-blinded OPRF element used to derive a private, "
            "registry-scoped device binding token."
        ),
    )
    async def device_binding_oprf(
        request: Request,
        body: DeviceBindingOprfRequestModel,
    ) -> dict[str, str]:
        enforce_identity_rate(request, body)
        try:
            return service.evaluate_device_binding_oprf(body.model_dump())
        except (OprfError, RegistryError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/pact/api/v1/profiles",
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
        "/pact/api/v1/profiles/{key_id}",
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
        "/pact/api/v1/profiles/{key_id}/update",
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
        "/pact/api/v1/profiles/{key_id}/evidence",
        tags=["Profiles"],
        summary="Get claimant evidence summary",
    )
    async def get_profile_evidence(key_id: str) -> dict[str, object]:
        try:
            evidence = service.evidence_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return evidence.to_dict()

    @app.get(
        "/pact/api/v1/profiles/{key_id}/claims",
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
        "/pact/api/v1/profiles/{key_id}/disputes",
        tags=["Disputes"],
        summary="List disputes attached to a claimant profile",
    )
    async def list_profile_disputes(key_id: str) -> dict[str, object]:
        try:
            disputes = service.list_disputes(claimant_key_id=key_id)
        except Exception as error:
            _raise_http_error(error)
        return {
            "disputes": [
                registry_service.public_dispute_dict(dispute)
                for dispute in disputes
            ]
        }

    @app.post(
        "/pact/api/v1/certificates",
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
        "/pact/api/v1/claims",
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

    @app.post(
        "/pact/api/v1/claims/matches",
        tags=["Claims"],
        summary="Find prior claims with matching public fingerprints",
        description="Return advisory exact or perceptual matches for an unpublished signed manifest.",
    )
    async def find_claim_matches(
        request: Request,
        body: ClaimMatchRequestModel,
    ) -> dict[str, object]:
        del request
        try:
            signed_manifest = SignedManifest.from_json(
                body.signed_manifest_json.encode("utf-8")
            )
            matches = service.find_claim_matches(
                signed_manifest,
                limit=body.limit,
            )
        except Exception as error:
            _raise_http_error(error)
        return {"matches": [match.to_dict() for match in matches]}

    @app.get(
        "/pact/api/v1/claims/{claim_id}",
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
        "/pact/api/v1/claims/{claim_id}/disputes",
        tags=["Disputes"],
        summary="List disputes attached to a claim",
    )
    async def list_claim_disputes(claim_id: UUID) -> dict[str, object]:
        try:
            disputes = service.list_disputes(claim_id=claim_id)
        except Exception as error:
            _raise_http_error(error)
        return {
            "disputes": [
                registry_service.public_dispute_dict(dispute)
                for dispute in disputes
            ]
        }

    @app.get(
        "/pact/api/v1/claims/{claim_id}/reports",
        tags=["Reports"],
        summary="List possible provenance avoidance reports for a claim",
    )
    async def list_claim_reports(claim_id: UUID) -> dict[str, object]:
        try:
            reports = service.list_avoidance_reports(claim_id=claim_id)
        except Exception as error:
            _raise_http_error(error)
        return {
            "reports": [
                registry_service.public_avoidance_report_dict(report)
                for report in reports
            ]
        }

    @app.get(
        "/pact/api/v1/claims/{claim_id}/spread",
        tags=["Reports"],
        summary="Get public spread summary for a claim",
    )
    async def get_claim_spread(claim_id: UUID) -> dict[str, object]:
        try:
            spread = service.spread_summary(claim_id)
        except Exception as error:
            _raise_http_error(error)
        return spread.to_dict()

    @app.post(
        "/pact/api/v1/claims/{claim_id}/revoke",
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
        "/pact/api/v1/recover",
        tags=["Reports"],
        summary="Recover possible source claim candidates",
    )
    async def recover_source_candidates(
        file: UploadFile = File(..., description="Suspicious content file."),
        mime_type: Annotated[
            str | None,
            Form(description="Override MIME type."),
        ] = None,
    ) -> dict[str, object]:
        try:
            content = await _read_upload_limited(file, upload_limits)
            inspected = await _inspect_content_limited(
                content,
                mime_type=_infer_upload_mime_type(file, mime_type),
                registry_service=service,
                limits=upload_limits,
            )
            claim = inspected.get("registry_claim")
            matches: list[dict[str, object]] = []
            claim_id_value = (
                claim.get("claim_id") if isinstance(claim, dict) else None
            )
            if isinstance(claim_id_value, str):
                claim_id = UUID(claim_id_value)
                registered_claim = service.get_claim(claim_id)
                reporting_enabled = service.claim_allows_public_reporting(
                    registered_claim
                )
                matches.append(
                    {
                        "claim_id": str(claim_id),
                        "recovery_label": "embedded_reference_recovered",
                        "evidence_type": inspected.get("reference", {}),
                        "score": None,
                        "public_nonce_available": registered_claim.signed_manifest.manifest.content_binding.public_nonce
                        is not None,
                        "reporting_enabled": reporting_enabled,
                        "report_url": None
                        if not reporting_enabled
                        else f"/pact/claims/{claim_id}/report",
                        "reporting_disabled_reason": None
                        if reporting_enabled
                        else "private_nonce_claim",
                    }
                )
            return {
                "embedded_reference": inspected.get("reference"),
                "registry_verification": inspected.get(
                    "registry_verification"
                ),
                "reverse_lookup": {"matches": matches},
            }
        except Exception as error:
            _raise_http_error(error)
            raise AssertionError("unreachable")

    @app.post(
        "/pact/api/v1/reports/avoidance",
        tags=["Reports"],
        summary="Submit possible provenance avoidance report",
    )
    async def submit_avoidance_report(
        request: Request,
        body: AvoidanceReportRequestModel,
    ) -> dict[str, object]:
        reporter_key_id = _require_profile_request_auth(
            request,
            service,
            body,
        )
        enforce_identity_rate(
            request,
            body,
            extra=(str(body.claim_id), reporter_key_id),
        )
        try:
            report = service.submit_avoidance_report(
                claim_id=body.claim_id,
                evidence_type=body.evidence.kind,
                evidence_digest=body.evidence.digest,
                report_label=body.reason,
                reporter_key_id=reporter_key_id,
                reporter_type="registered_profile",
                observed_url=body.observed_url,
                observed_at=body.observed_at,
                reverse_lookup_score=body.reverse_lookup_score,
                reverse_lookup_evidence=tuple(body.reverse_lookup_evidence),
                description=body.description,
            )
        except Exception as error:
            _raise_http_error(error)
        return {
            **service.public_avoidance_report_dict(report),
            "public_visibility": "claimant_visible",
            "owner_notified": True,
        }

    @app.get(
        "/pact/api/v1/reports/{report_id}",
        tags=["Reports"],
        summary="Get possible provenance avoidance report",
    )
    async def get_avoidance_report(report_id: UUID) -> dict[str, object]:
        try:
            report = service.get_avoidance_report(report_id)
        except Exception as error:
            _raise_http_error(error)
        if not report.public_visible:
            raise HTTPException(status_code=404, detail="report not found")
        return service.public_avoidance_report_dict(report)

    @app.post(
        "/pact/api/v1/rotations",
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
        "/pact/api/v1/domains/verify",
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
        "/pact/api/v1/profiles/{key_id}/hosted-authorize",
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
        "/pact/api/v1/profiles/me/hosted-login",
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
        "/pact/api/v1/profiles/{key_id}/third-party-attest",
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
        "/pact/api/v1/disputes",
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
        return service.public_dispute_dict(dispute)

    @app.get(
        "/pact/api/v1/disputes/{dispute_id}",
        tags=["Disputes"],
        summary="Get dispute record",
    )
    async def get_dispute(dispute_id: UUID) -> dict[str, object]:
        try:
            dispute = service.get_dispute(dispute_id)
        except Exception as error:
            _raise_http_error(error)
        return service.public_dispute_dict(dispute)

    @app.post(
        "/pact/api/v1/disputes/{dispute_id}/resolve",
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
        return service.public_dispute_dict(dispute)

    @app.get("/profiles/{key_id}", response_class=RedirectResponse)
    async def legacy_public_profile(key_id: str) -> RedirectResponse:
        return RedirectResponse(f"/pact/profiles/{key_id}", status_code=308)

    @app.get("/pact/profiles/{key_id}", response_class=HTMLResponse)
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
                "profile": _public_jsonable(profile),
                "evidence": evidence.to_dict(),
                "public_base_url": app.state.public_base_url,
            },
        )

    @app.get("/claims/{claim_id}", response_class=RedirectResponse)
    async def legacy_public_claim(claim_id: UUID) -> RedirectResponse:
        return RedirectResponse(f"/pact/claims/{claim_id}", status_code=308)

    @app.get("/pact/claims/{claim_id}", response_class=HTMLResponse)
    async def public_claim(request: Request, claim_id: UUID) -> HTMLResponse:
        try:
            claim = service.get_claim(claim_id)
            profile = service.get_profile(claim.claimant_key_id)
            spread = service.spread_summary(claim_id)
        except Exception as error:
            _raise_http_error(error)
        return templates.TemplateResponse(
            request,
            "claim.html",
            {
                "claim": jsonable_encoder(claim),
                "profile": _public_jsonable(profile),
                "spread": spread.to_dict(),
                "public_base_url": app.state.public_base_url,
            },
        )

    @app.get("/verify/claim/{claim_id}", response_class=RedirectResponse)
    async def legacy_verify_claim_page(
        claim_id: UUID,
    ) -> RedirectResponse:
        return RedirectResponse(
            f"/pact/verify/claim/{claim_id}",
            status_code=308,
        )

    @app.get("/pact/verify/claim/{claim_id}", response_class=HTMLResponse)
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
                "profile": _public_jsonable(profile),
                "verification": jsonable_encoder(verification),
            },
        )

    return app
