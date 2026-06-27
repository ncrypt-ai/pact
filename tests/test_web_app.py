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
    embed_text_carrier,
    sign_manifest,
)
from pact.metadata import PACKAGE_VERSION
from pact.registry import MutationChallenge
from pact.web import RateLimitConfig, create_app


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
    rate_limit_config: RateLimitConfig | None = None,
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
        rate_limit_config=rate_limit_config,
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


def register_claim(
    client: TestClient,
    identity: ClaimantIdentity,
    signed,
) -> dict[str, object]:
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
    response = client.post(
        "/api/v1/claims",
        json={
            "challenge_id": str(request.challenge_id),
            "claimant_public_jwk": request.claimant_public_jwk,
            "proof_of_work_solution": request.proof_of_work_solution,
            "payload": request.payload,
            "signature": request.signature,
        },
    )
    response.raise_for_status()
    return response.json()


def open_dispute(
    client: TestClient,
    identity: ClaimantIdentity,
    claim_id: str,
    *,
    misuse_url: str | None = None,
) -> dict[str, object]:
    challenge = client.post(
        "/api/v1/challenges",
        json={
            "purpose": "dispute_open",
            "difficulty": 4,
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
        payload={
            "claim_id": claim_id,
            "reason": "Found on an unauthorized page.",
            **({"misuse_url": misuse_url} if misuse_url else {}),
        },
        proof_of_work_solution=solve_pow(challenge_object),
    )
    response = client.post(
        "/api/v1/disputes",
        json={
            "challenge_id": str(request.challenge_id),
            "claimant_public_jwk": request.claimant_public_jwk,
            "proof_of_work_solution": request.proof_of_work_solution,
            "payload": request.payload,
            "signature": request.signature,
        },
    )
    response.raise_for_status()
    return response.json()


def update_profile(
    client: TestClient,
    identity: ClaimantIdentity,
    display_name: str | None,
) -> dict[str, object]:
    challenge = client.post(
        "/api/v1/challenges",
        json={
            "purpose": "profile_update",
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
        payload={"display_name": display_name},
        proof_of_work_solution=solve_pow(challenge_object),
    )
    response = client.post(
        f"/api/v1/profiles/{identity.key_id}/update",
        json={
            "challenge_id": str(request.challenge_id),
            "claimant_public_jwk": request.claimant_public_jwk,
            "proof_of_work_solution": request.proof_of_work_solution,
            "payload": request.payload,
            "signature": request.signature,
        },
    )
    response.raise_for_status()
    return response.json()


def test_web_app_serves_registry_profile_claim_and_verify_pages(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("PACT_COMMIT_SHA", "abc123def456")
    client, identity = make_client(tmp_path)
    register_profile(client, identity)

    signed = make_signed_manifest(identity)
    claim = register_claim(client, identity, signed)

    registry_response = client.get("/api/v1/registry")
    assert registry_response.status_code == 200
    assert '{\n  "registry_url":' in registry_response.text
    routes = client.get("/api/v1/server/routes")
    assert routes.status_code == 200
    assert '{\n  "routes": [' in routes.text
    route_names = {route["name"] for route in routes.json()["routes"]}
    assert {
        "registry_info",
        "register_claim",
        "server_info",
        "verify_claim_page",
    }.issubset(route_names)
    registry_info = registry_response.json()
    assert registry_info["server"]["version"] == PACKAGE_VERSION
    assert registry_info["server"]["commit"] == "abc123def456"
    server_info = client.get("/api/v1/server/info")
    assert server_info.status_code == 200
    assert '{\n  "registry_url":' in server_info.text
    assert server_info.json()["server"] == registry_info["server"]
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


def test_web_app_can_self_host_built_documentation(tmp_path: Path) -> None:
    docs_directory = tmp_path / "docs"
    docs_directory.mkdir()
    (docs_directory / "index.html").write_text(
        "<!doctype html><title>PACT Documentation</title>",
        encoding="utf-8",
    )
    client, _identity = make_client(tmp_path / "registry")

    app = create_app(
        client.app.state.registry_service,
        public_base_url="http://testserver",
        docs_directory=docs_directory,
    )
    docs_client = TestClient(app)

    home = docs_client.get("/")
    assert '<a href="/docs">PACT library</a>' in home.text
    assert '<a href="/api/docs">API Surface</a>' in home.text
    docs = docs_client.get("/docs/")
    assert docs.status_code == 200
    assert "PACT Documentation" in docs.text
    assert docs_client.get("/api/docs").status_code == 200
    route_names = {
        route["name"]
        for route in docs_client.get("/api/v1/server/routes").json()["routes"]
    }
    assert "documentation" in route_names
    assert (
        docs_client.get("/api/v1/server/info").json()["documentation_url"]
        == "http://testserver/docs/"
    )


def test_api_docs_have_scoped_content_security_policy(tmp_path: Path) -> None:
    client, _identity = make_client(tmp_path)

    home_csp = client.get("/").headers["Content-Security-Policy"]
    docs_csp = client.get("/api/docs").headers["Content-Security-Policy"]
    docs_slash_csp = client.get("/api/docs/").headers[
        "Content-Security-Policy"
    ]
    default_docs_csp = client.get("/docs").headers["Content-Security-Policy"]

    assert (
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" in docs_csp
    )
    assert "img-src 'self' data: https://fastapi.tiangolo.com" in docs_csp
    assert "'unsafe-inline'" in docs_csp
    assert "https://cdn.jsdelivr.net" in docs_slash_csp
    assert "https://cdn.jsdelivr.net" in default_docs_csp
    assert "https://fastapi.tiangolo.com" not in home_csp


def test_web_updates_profile_display_name(tmp_path: Path) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)

    profile = update_profile(client, identity, "Alice Updated")

    assert profile["display_name"] == "Alice Updated"
    loaded = client.get(f"/api/v1/profiles/{identity.key_id}").json()
    assert loaded["display_name"] == "Alice Updated"


def test_openapi_schema_includes_actionable_examples(tmp_path: Path) -> None:
    client, _identity = make_client(tmp_path)

    schema = client.get("/api/openapi.json").json()

    challenge_examples = schema["paths"]["/api/v1/challenges"]["post"][
        "requestBody"
    ]["content"]["application/json"]["examples"]
    assert "profile_registration" in challenge_examples
    assert "claim_registration" in challenge_examples
    assert (
        challenge_examples["claim_registration"]["value"]["purpose"]
        == "claim_registration"
    )

    profile_examples = schema["paths"]["/api/v1/profiles"]["post"][
        "requestBody"
    ]["content"]["application/json"]["examples"]
    assert profile_examples["profile_registration"]["value"]["payload"][
        "device_fingerprint"
    ]

    claim_examples = schema["paths"]["/api/v1/claims"]["post"]["requestBody"][
        "content"
    ]["application/json"]["examples"]
    assert (
        "signed_manifest_json"
        in claim_examples["claim_registration"]["value"]["payload"]
    )

    tags = {tag["name"] for tag in schema["tags"]}
    assert {"Discovery", "Challenges", "Claims", "Profiles"}.issubset(tags)


def test_web_inspect_accepts_raw_text_carrier(tmp_path: Path) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)
    signed = make_signed_manifest(identity)
    claim = register_claim(client, identity, signed)
    carrier = embed_text_carrier(b"hello", signed, nonce=b"\x01" * 32)

    response = client.post(
        "/api/v1/inspect",
        files={
            "file": (
                "work.txt",
                carrier,
                "text/plain",
            )
        },
    )

    assert response.status_code == 200
    inspected = response.json()
    assert inspected["recognized"] is True
    assert inspected["reference"]["carrier"] == "text:both"
    assert inspected["reference"]["claim_id"] == claim["claim_id"]
    assert inspected["registry_claim"]["claim_id"] == claim["claim_id"]
    assert inspected["registry_verification"]["label"] == "verified_claim"
    assert inspected["source_material"]["content_binding_checked"] is True
    assert inspected["source_material"]["verification"]["valid"] is True


def test_web_lists_profile_claims_and_disputes(tmp_path: Path) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)
    signed = make_signed_manifest(identity)
    claim = register_claim(client, identity, signed)
    dispute = open_dispute(
        client,
        identity,
        claim["claim_id"],
        misuse_url="https://example.com/copied-media",
    )
    assert dispute["misuse_url"] == "https://example.com/copied-media"

    claims_response = client.get(f"/api/v1/profiles/{identity.key_id}/claims")
    assert claims_response.status_code == 200
    claims = claims_response.json()["claims"]
    assert [item["claim_id"] for item in claims] == [claim["claim_id"]]

    profile_disputes = client.get(
        f"/api/v1/profiles/{identity.key_id}/disputes"
    )
    assert profile_disputes.status_code == 200
    assert profile_disputes.json()["disputes"][0]["misuse_url"] == (
        "https://example.com/copied-media"
    )

    claim_disputes = client.get(f"/api/v1/claims/{claim['claim_id']}/disputes")
    assert claim_disputes.status_code == 200
    assert (
        claim_disputes.json()["disputes"][0]["dispute_id"]
        == (dispute["dispute_id"])
    )


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
    assert "Output" not in workspace.text
    assert "<script>" not in workspace.text
    assert 'data-page="identity"' in workspace.text
    assert 'data-page="sign"' in workspace.text
    assert 'data-page="mutations"' in workspace.text
    assert "Display name (optional)" in workspace.text
    assert "Passcode" in workspace.text
    assert "PACT will not create a passcode" in workspace.text
    assert "Continue" in workspace.text
    assert "Recovery and account options" in workspace.text
    assert "Log out" in workspace.text
    assert "Saved browser profile" in workspace.text
    assert "Check public registry profile" in workspace.text
    assert "Sign and publish" in workspace.text
    assert "Register edits" in workspace.text
    assert "Inspect or verify" in workspace.text
    assert "Look up records" in workspace.text
    assert 'data-page="lookup"' in workspace.text
    assert 'id="lookup-profile-key"' in workspace.text
    assert 'id="lookup-claim-id"' in workspace.text
    assert 'id="lookup-dispute-id"' in workspace.text
    workspace_js = Path("src/pact/web/static/workspace.js").read_text(
        encoding="utf-8"
    )
    assert "Generative AI training" in workspace_js
    assert "Search indexing" in workspace_js
    assert "Redistribution" in workspace_js
    assert "Where did you see the misuse?" in workspace.text
    assert "Invisible marks" in workspace.text
    assert "protected text copy" in workspace.text
    assert "claim locator" in workspace.text
    assert "proof JSON" in workspace.text
    assert "c2pa.cropped" not in workspace.text
    assert "c2pa.resized" not in workspace.text
    assert "Disputes" in workspace.text
    assert "Model checks" not in workspace.text
    assert 'autocomplete="username"' in workspace.text
    csp = workspace.headers["Content-Security-Policy"]
    assert "'unsafe-eval'" in csp
    assert "'wasm-unsafe-eval'" in csp
    assert (
        "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' https://cdn.jsdelivr.net"
        in csp
    )
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


def test_api_rate_limit_uses_forwarded_client_ip(tmp_path: Path) -> None:
    client, _identity = make_client(
        tmp_path,
        rate_limit_config=RateLimitConfig(
            window_seconds=60,
            ip_limit=2,
            identity_limit=100,
        ),
    )

    headers = {"X-Forwarded-For": "203.0.113.10"}

    assert client.get("/api/v1/registry", headers=headers).status_code == 200
    assert client.get("/api/v1/registry", headers=headers).status_code == 200
    limited = client.get("/api/v1/registry", headers=headers)

    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "59"
    assert (
        client.get(
            "/api/v1/registry",
            headers={"X-Forwarded-For": "203.0.113.11"},
        ).status_code
        == 200
    )


def test_api_rate_limit_uses_claimant_identity_across_ips(
    tmp_path: Path,
) -> None:
    client, identity = make_client(
        tmp_path,
        rate_limit_config=RateLimitConfig(
            window_seconds=60,
            ip_limit=100,
            identity_limit=1,
        ),
    )

    def profile_request(challenge_id: str) -> dict[str, object]:
        return {
            "challenge_id": challenge_id,
            "claimant_public_jwk": identity.public_jwk,
            "proof_of_work_solution": 0,
            "payload": {
                "device_fingerprint": f"test-device-{identity.key_id}"
            },
            "signature": "invalid",
        }

    first = client.post(
        "/api/v1/profiles",
        json=profile_request("018f7f79-7b42-7c00-8000-000000000001"),
        headers={"X-Forwarded-For": "203.0.113.20"},
    )
    second = client.post(
        "/api/v1/profiles",
        json=profile_request("018f7f79-7b42-7c00-8000-000000000002"),
        headers={"X-Forwarded-For": "203.0.113.21"},
    )

    assert first.status_code == 400
    assert second.status_code == 429
