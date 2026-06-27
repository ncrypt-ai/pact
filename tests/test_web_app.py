import io
import zipfile
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


def make_client(
    tmp_path: Path,
    *,
    enable_workspace: bool = False,
) -> tuple[TestClient, ClaimantIdentity]:
    registry_url = "https://registry.example"
    authority = RegistryCertificateAuthority.initialize(registry_url)
    service = RegistryService(
        registry_url,
        store=FileRegistryStore(tmp_path / "store"),
        certificate_authority=authority,
    )
    app = create_app(
        service,
        public_base_url="http://testserver",
        enable_workspace=enable_workspace,
    )
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
        payload={
            "display_name": "Alice",
            "device_fingerprint": f"test-device-{identity.key_id}",
        },
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


def test_web_app_serves_registry_profile_claim_and_verify_pages(
    tmp_path: Path,
) -> None:
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
    routes = client.get("/api/v1/server/routes")
    assert routes.status_code == 200
    route_names = {route["name"] for route in routes.json()["routes"]}
    assert {"registry_info", "register_claim", "verify_claim_page"}.issubset(
        route_names
    )
    assert client.get(f"/api/v1/profiles/{identity.key_id}").status_code == 200
    assert (
        client.get(f"/api/v1/profiles/{identity.key_id}/evidence").status_code
        == 200
    )
    assert client.get(f"/api/v1/claims/{claim['claim_id']}").status_code == 200

    home = client.get("/")
    assert "PACT Registry" in home.text
    profile_page = client.get(f"/profiles/{identity.key_id}")
    assert identity.key_id in profile_page.text
    claim_page = client.get(f"/claims/{claim['claim_id']}")
    assert claim["claim_id"] in claim_page.text
    verify_page = client.get(f"/verify/claim/{claim['claim_id']}")
    assert "Claim check" in verify_page.text
    assert "verified_claim" in verify_page.text
    assert "unauthenticated_device" in verify_page.text
    assert home.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in home.headers


def test_web_workspace_is_optional_and_serves_pyodide_assets(
    tmp_path: Path,
) -> None:
    disabled_client, _identity = make_client(tmp_path / "disabled")
    assert disabled_client.get("/app").status_code == 404

    enabled_client, _identity = make_client(
        tmp_path / "enabled",
        enable_workspace=True,
    )
    workspace = enabled_client.get("/app")
    assert workspace.status_code == 200
    assert "PACT Workspace" in workspace.text
    assert "Pyodide worker" in workspace.text
    assert "<script>" not in workspace.text
    assert 'data-page="identity"' in workspace.text
    assert 'data-page="sign"' in workspace.text
    assert "Display name (optional)" in workspace.text
    assert "Unlock saved identity" in workspace.text
    assert "Vault password" in workspace.text
    csp = workspace.headers["Content-Security-Policy"]
    assert "'wasm-unsafe-eval'" in csp
    assert "script-src 'self' 'wasm-unsafe-eval' https://cdn.jsdelivr.net" in csp
    package = enabled_client.get("/app/pact-browser-core.pyz")
    assert package.status_code == 200
    assert package.headers["content-type"] == "application/zip"
    core_names = zipfile.ZipFile(io.BytesIO(package.content)).namelist()
    assert "pact/browser.py" in core_names
    assert "pact/carriers/c2pa_text.py" not in core_names

    documents = enabled_client.get("/app/pact-browser-documents.pyz")
    document_names = zipfile.ZipFile(io.BytesIO(documents.content)).namelist()
    assert "pact/carriers/c2pa.py" in document_names
    assert "pact/carriers/c2pa_text.py" not in document_names


def test_web_workspace_can_run_without_local_registry_service() -> None:
    app = create_app(
        None,
        public_base_url="http://testserver",
        registry_url="https://registry.example",
        enable_workspace=True,
    )
    client = TestClient(app)

    workspace = client.get("/app")
    assert workspace.status_code == 200
    assert "standalone web interface" in workspace.text
    assert "https://registry.example" in workspace.text
    assert client.get("/api/v1/registry").status_code == 404
