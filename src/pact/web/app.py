"""FastAPI application for the public registry API and web UI."""

from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from pact.registry import (
    ChallengePurpose,
    KeyRotationRequest,
    MutationRequest,
    RegistryError,
    RegistryService,
)


def _templates() -> Jinja2Templates:
    directory = Path(__file__).with_name("templates")
    return Jinja2Templates(directory=str(directory))


def _jsonable(value: object) -> object:
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(cast(Any, value)).items()}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_jsonable(item) for item in value]
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
    }


def _raise_http_error(error: Exception) -> None:
    if isinstance(error, RegistryError):
        raise HTTPException(status_code=400, detail=str(error)) from error
    raise HTTPException(status_code=500, detail="internal server error") from error


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
    service: RegistryService,
    *,
    public_base_url: str,
    local_mode: bool = False,
) -> FastAPI:
    """Create the public registry API and proof-page application."""

    templates = _templates()
    app = FastAPI(
        title="PACT Registry",
        version="0.0.1",
        summary="Public registry, proof pages, and local UI for PACT",
    )
    app.state.registry_service = service
    app.state.public_base_url = public_base_url.rstrip("/")
    app.state.local_mode = local_mode

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "home.html",
            {
                "registry_url": service.registry_url,
                "public_base_url": app.state.public_base_url,
                "local_mode": local_mode,
            },
        )

    @app.get("/api/v1/registry")
    async def registry_info() -> dict[str, object]:
        return _registry_info(service)

    @app.post("/api/v1/challenges")
    async def issue_challenge(body: ChallengeRequestModel) -> dict[str, object]:
        challenge = service.issue_challenge(
            body.purpose,
            bound_key_id=body.bound_key_id,
            difficulty=body.difficulty,
        )
        return cast(dict[str, object], _jsonable(challenge.to_dict()))

    @app.post("/api/v1/profiles")
    async def register_profile(body: MutationRequestModel) -> dict[str, object]:
        try:
            profile = service.register_profile(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(profile))

    @app.get("/api/v1/profiles/{key_id}")
    async def get_profile(key_id: str) -> dict[str, object]:
        try:
            profile = service.get_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(profile))

    @app.get("/api/v1/profiles/{key_id}/evidence")
    async def get_profile_evidence(key_id: str) -> dict[str, object]:
        try:
            evidence = service.evidence_profile(key_id)
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(evidence))

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
        return cast(dict[str, object], _jsonable(claim))

    @app.get("/api/v1/claims/{claim_id}")
    async def get_claim(claim_id: UUID) -> dict[str, object]:
        try:
            claim = service.get_claim(claim_id)
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(claim))

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
        return cast(dict[str, object], _jsonable(claim))

    @app.post("/api/v1/rotations")
    async def rotate_key(body: RotationRequestModel) -> dict[str, object]:
        try:
            profile = service.rotate_key(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(profile))

    @app.post("/api/v1/domains/verify")
    async def verify_domain(body: MutationRequestModel) -> dict[str, object]:
        try:
            profile = service.verify_domain(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(profile))

    @app.post("/api/v1/disputes")
    async def open_dispute(body: MutationRequestModel) -> dict[str, object]:
        try:
            dispute = service.open_dispute(body.to_domain())
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(dispute))

    @app.get("/api/v1/disputes/{dispute_id}")
    async def get_dispute(dispute_id: UUID) -> dict[str, object]:
        try:
            dispute = service.get_dispute(dispute_id)
        except Exception as error:
            _raise_http_error(error)
        return cast(dict[str, object], _jsonable(dispute))

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
        return cast(dict[str, object], _jsonable(dispute))

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
                "profile": _jsonable(profile),
                "evidence": _jsonable(evidence),
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
                "claim": _jsonable(claim),
                "profile": _jsonable(profile),
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
        except Exception as error:
            _raise_http_error(error)
        return templates.TemplateResponse(
            request,
            "verify_claim.html",
            {
                "claim": _jsonable(claim),
                "profile": _jsonable(profile),
                "verification_state": "revoked"
                if claim.revoked_at is not None
                else "current",
            },
        )

    return app
