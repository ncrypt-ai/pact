"""FastAPI application for the registry API and proof pages."""

from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

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


def _templates() -> Jinja2Templates:
    directory = Path(__file__).with_name("templates")
    return Jinja2Templates(directory=str(directory))


def _static_directory() -> Path:
    return Path(__file__).with_name("static")


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


class ChallengeRequestModel(BaseModel):
    purpose: ChallengePurpose
    bound_key_id: str | None = None
    difficulty: int = Field(default=12, ge=0, le=255)


class MutationRequestModel(BaseModel):
    challenge_id: UUID
    claimant_public_jwk: dict[str, str]
    proof_of_work_solution: int = Field(ge=0)
    payload: dict[str, object]
    signature: str

    def to_domain(self) -> MutationRequest:
        return MutationRequest(
            challenge_id=self.challenge_id,
            claimant_public_jwk=self.claimant_public_jwk,
            proof_of_work_solution=self.proof_of_work_solution,
            payload=self.payload,
            signature=self.signature,
        )


class CertificateIssueRequestModel(BaseModel):
    request: MutationRequestModel
    valid_days: int = Field(default=30, ge=1, le=365)


class RotationRequestModel(BaseModel):
    challenge_id: UUID
    current_public_jwk: dict[str, str]
    replacement_public_jwk: dict[str, str]
    proof_of_work_solution: int = Field(ge=0)
    payload: dict[str, object]
    current_signature: str
    replacement_signature: str

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
) -> FastAPI:
    """Build the registry API and proof-page application."""

    templates = _templates()
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
        middleware=[
            Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
        ],
    )
    app.state.registry_service = service
    app.state.public_base_url = public_base_url.rstrip("/")
    app.state.registry_url = normalized_registry_url
    app.state.local_mode = local_mode
    app.state.enable_workspace = enable_workspace
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

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "
            "worker-src 'self'; connect-src 'self' https: http://localhost:* "
            "http://127.0.0.1:*",
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
            },
        )

    @app.get("/app", response_class=HTMLResponse)
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

    @app.get("/app/pact-browser-{feature}.pyz")
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

    @app.get("/api/v1/registry")
    async def registry_info() -> dict[str, object]:
        return _registry_info(service)

    @app.get("/api/v1/server/routes")
    async def server_routes() -> dict[str, object]:
        return {
            "routes": [route.to_dict() for route in default_routes()],
        }

    @app.get("/api/v1/server/info")
    async def server_info() -> dict[str, object]:
        return {
            "registry_url": app.state.registry_url,
            "public_base_url": app.state.public_base_url,
            "server": server_metadata(),
        }

    @app.post("/api/v1/inspect")
    async def inspect_upload(
        file: UploadFile = File(
            description="Manifest JSON or raw media carrier to inspect."
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

    @app.post("/api/v1/challenges")
    async def issue_challenge(
        body: ChallengeRequestModel,
    ) -> dict[str, object]:
        challenge = service.issue_challenge(
            body.purpose,
            bound_key_id=body.bound_key_id,
            difficulty=body.difficulty,
        )
        return _json_dict(challenge.to_dict())

    @app.post("/api/v1/profiles")
    async def register_profile(
        body: MutationRequestModel,
    ) -> dict[str, object]:
        try:
            profile = service.register_profile(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.get("/api/v1/profiles/{key_id}")
    async def get_profile(key_id: str) -> dict[str, object]:
        try:
            profile = service.get_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.get("/api/v1/profiles/{key_id}/evidence")
    async def get_profile_evidence(key_id: str) -> dict[str, object]:
        try:
            evidence = service.evidence_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(evidence)

    @app.post("/api/v1/certificates")
    async def issue_certificate(
        body: CertificateIssueRequestModel,
    ) -> dict[str, object]:
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

    @app.post("/api/v1/claims")
    async def register_claim(body: MutationRequestModel) -> dict[str, object]:
        try:
            claim = service.register_claim(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(claim)

    @app.get("/api/v1/claims/{claim_id}")
    async def get_claim(claim_id: UUID) -> dict[str, object]:
        try:
            claim = service.get_claim(claim_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(claim)

    @app.post("/api/v1/claims/{claim_id}/revoke")
    async def revoke_claim(
        claim_id: UUID,
        body: MutationRequestModel,
    ) -> dict[str, object]:
        request_model = MutationRequest(
            challenge_id=body.challenge_id,
            claimant_public_jwk=body.claimant_public_jwk,
            proof_of_work_solution=body.proof_of_work_solution,
            payload={**body.payload, "claim_id": str(claim_id)},
            signature=body.signature,
        )
        try:
            claim = service.revoke_claim(request_model)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(claim)

    @app.post("/api/v1/rotations")
    async def rotate_key(body: RotationRequestModel) -> dict[str, object]:
        try:
            profile = service.rotate_key(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post("/api/v1/domains/verify")
    async def verify_domain(body: MutationRequestModel) -> dict[str, object]:
        try:
            profile = service.verify_domain(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(profile)

    @app.post("/api/v1/disputes")
    async def open_dispute(body: MutationRequestModel) -> dict[str, object]:
        try:
            dispute = service.open_dispute(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(dispute)

    @app.get("/api/v1/disputes/{dispute_id}")
    async def get_dispute(dispute_id: UUID) -> dict[str, object]:
        try:
            dispute = service.get_dispute(dispute_id)
        except Exception as error:
            _raise_http_error(error)
        return _json_dict(dispute)

    @app.post("/api/v1/disputes/{dispute_id}/resolve")
    async def resolve_dispute(
        dispute_id: UUID,
        body: MutationRequestModel,
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
