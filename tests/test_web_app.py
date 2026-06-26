from datetime import datetime
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from pact import (
    CanonicalizationProfile,
    ChallengePurpose,
    ClaimantIdentity,
    FileRegistryStore,
    Manifest,
    MutationRequest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    RegistryCertificateAuthority,
    RegistryService,
    sign_manifest,
)
from pact.registry import MutationChallenge
from pact.web import create_app


def solve_pow(challenge) -> int:
    solution = 0
    while not challenge.verify_solution(solution):
        solution += 1
    return solution


def make_signed_manifest(identity: ClaimantIdentity):
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint="A" * 43,
        content=b"hello",
        mime_type="text/plain",
        canonicalization=CanonicalizationProfile.TEXT_V1,
        policy=Policy(
            (
                PolicyEntry(
                    Permission.GENERATIVE_TRAINING,
                    PermissionValue.NOT_ALLOWED,
                ),
            )
        ),
        nonce=b"\x01" * 32,
    )
    return sign_manifest(manifest, identity)


def make_client(tmp_path: Path) -> tuple[TestClient, ClaimantIdentity]:
    registry_url = "https://registry.example"
    authority = RegistryCertificateAuthority.initialize(registry_url)
    service = RegistryService(
        registry_url,
        store=FileRegistryStore(tmp_path / "store"),
        certificate_authority=authority,
    )
    app = create_app(service, public_base_url="http://testserver")
    return TestClient(app), ClaimantIdentity.generate(registry_url)


def register_profile(client: TestClient, identity: ClaimantIdentity) -> None:
    challenge_response = client.post(
        "/api/v1/challenges",
        json={"purpose": "profile_registration", "difficulty": 4},
    )
    challenge = challenge_response.json()
    challenge_object = MutationChallenge(
        registry_url=challenge["registry_url"],
        challenge_id=UUID(challenge["challenge_id"]),
        purpose=ChallengePurpose(challenge["purpose"]),
        issued_at=datetime.fromisoformat(challenge["issued_at"]),
        expires_at=datetime.fromisoformat(challenge["expires_at"]),
        challenge_nonce=challenge["challenge_nonce"],
        difficulty=challenge["difficulty"],
        bound_key_id=challenge.get("bound_key_id"),
    )
    request = MutationRequest.create(
        identity,
        challenge_object,
        payload={"display_name": "Alice"},
        proof_of_work_solution=solve_pow(challenge_object),
    )
    client.post(
        "/api/v1/profiles",
        json={
            "challenge_id": str(request.challenge_id),
            "claimant_public_jwk": request.claimant_public_jwk,
            "proof_of_work_solution": request.proof_of_work_solution,
            "payload": request.payload,
            "signature": request.signature,
        },
    ).raise_for_status()


def test_web_app_serves_registry_profile_claim_and_verify_pages(tmp_path: Path) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)

    signed = make_signed_manifest(identity)
    challenge = client.post(
        "/api/v1/challenges",
        json={
            "purpose": "claim_registration",
            "difficulty": 4,
            "bound_key_id": identity.key_id,
        },
    ).json()
    challenge_object = MutationChallenge(
        registry_url=challenge["registry_url"],
        challenge_id=UUID(challenge["challenge_id"]),
        purpose=ChallengePurpose(challenge["purpose"]),
        issued_at=datetime.fromisoformat(challenge["issued_at"]),
        expires_at=datetime.fromisoformat(challenge["expires_at"]),
        challenge_nonce=challenge["challenge_nonce"],
        difficulty=challenge["difficulty"],
        bound_key_id=challenge.get("bound_key_id"),
    )
    request = MutationRequest.create(
        identity,
        challenge_object,
        payload={"signed_manifest_json": signed.to_json().decode("utf-8")},
        proof_of_work_solution=solve_pow(challenge_object),
    )
    claim = client.post(
        "/api/v1/claims",
        json={
            "challenge_id": str(request.challenge_id),
            "claimant_public_jwk": request.claimant_public_jwk,
            "proof_of_work_solution": request.proof_of_work_solution,
            "payload": request.payload,
            "signature": request.signature,
        },
    ).json()

    assert client.get("/api/v1/registry").status_code == 200
    assert client.get(f"/api/v1/profiles/{identity.key_id}").status_code == 200
    assert client.get(f"/api/v1/profiles/{identity.key_id}/evidence").status_code == 200
    assert client.get(f"/api/v1/claims/{claim['claim_id']}").status_code == 200

    home = client.get("/")
    assert "PACT Registry" in home.text
    profile_page = client.get(f"/profiles/{identity.key_id}")
    assert identity.key_id in profile_page.text
    claim_page = client.get(f"/claims/{claim['claim_id']}")
    assert claim["claim_id"] in claim_page.text
    verify_page = client.get(f"/verify/claim/{claim['claim_id']}")
    assert "Claim check" in verify_page.text
    assert home.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in home.headers
