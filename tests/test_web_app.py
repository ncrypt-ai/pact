import hashlib
import io
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from fastapi.testclient import TestClient
from pypdf import PdfWriter

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
from pact.canonical import JsonValue, canonical_json
from pact.carriers.c2pa import embed_c2pa_manifest_in_pdf
from pact.crypto import base64url_encode, sign_es256
from pact.fingerprints import create_content_fingerprints
from pact.metadata import PACKAGE_VERSION
from pact.oprf import device_binding_input, format_device_binding_token
from pact.registry import MutationChallenge
from pact.web import (
    RateLimitConfig,
    TrustedProxyConfig,
    UploadLimitConfig,
    create_app,
)


def device_binding_token(identity: ClaimantIdentity) -> str:
    return format_device_binding_token(identity.key_id)


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


def make_private_signed_manifest(identity: ClaimantIdentity):
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
        disclose_nonce=False,
    )
    return sign_manifest(manifest, identity)


def make_fingerprinted_manifest(
    identity: ClaimantIdentity,
    content: bytes,
):
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint="A" * 43,
        content=content,
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
        fingerprints=create_content_fingerprints(
            content,
            "text/plain",
            CanonicalizationProfile.TEXT_V1,
        ),
        nonce=b"\x02" * 32,
    )
    return sign_manifest(manifest, identity)


def make_client(
    tmp_path: Path,
    *,
    enable_workspace: bool = False,
    rate_limit_config: RateLimitConfig | None = None,
    trusted_proxy_config: TrustedProxyConfig | None = None,
    upload_limit_config: UploadLimitConfig | None = None,
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
        trusted_proxy_config=trusted_proxy_config,
        upload_limit_config=upload_limit_config,
    )
    return TestClient(app), ClaimantIdentity.generate(registry_url)


def register_profile(client: TestClient, identity: ClaimantIdentity) -> None:
    challenge_response = client.post(
        "/pact/api/v1/challenges",
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
            "device_fingerprint": device_binding_token(identity),
        },
        proof_of_work_solution=solve_pow(challenge_object),
    )
    client.post(
        "/pact/api/v1/profiles",
        json={
            "challenge_id": str(request.challenge_id),
            "claimant_public_jwk": request.claimant_public_jwk,
            "proof_of_work_solution": request.proof_of_work_solution,
            "payload": request.payload,
            "signature": request.signature,
        },
    ).raise_for_status()


def profile_auth_headers(
    client: TestClient,
    identity: ClaimantIdentity,
    *,
    method: str,
    path: str,
    body: dict[str, object],
) -> dict[str, str]:
    challenge = client.post(
        "/pact/api/v1/challenges",
        json={
            "purpose": "account_authorization",
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
    solution = solve_pow(challenge_object)
    body_digest = hashlib.sha256(
        canonical_json(cast(JsonValue, body))
    ).hexdigest()
    signed = canonical_json(
        cast(
            JsonValue,
            {
                "challenge": challenge_object.to_dict(),
                "profile_key_id": identity.key_id,
                "method": method,
                "path": path,
                "body_sha256": body_digest,
            },
        )
    )
    return {
        "X-PACT-Profile-Key-Id": identity.key_id,
        "X-PACT-Challenge-Id": str(challenge_object.challenge_id),
        "X-PACT-Proof-Of-Work-Solution": str(solution),
        "X-PACT-Signature": sign_es256(identity.private_key, signed),
    }


def test_device_binding_oprf_endpoint_returns_evaluated_element(
    tmp_path: Path,
) -> None:
    client, _identity = make_client(tmp_path)
    from oblivious.ristretto import python as ristretto

    ristretto_any = cast(Any, ristretto)
    blinded = ristretto_any.scalar() * ristretto_any.point.hash(
        device_binding_input(
            local_secret=b"local-secret",
            registry_root_fingerprint="A" * 43,
            device_fingerprint="browser-fingerprint",
        )
    )

    response = client.post(
        "/pact/api/v1/device-bindings/oprf",
        json={"blinded": base64url_encode(bytes(blinded))},
    )

    assert response.status_code == 200
    assert set(response.json()) == {"evaluated"}


def test_device_binding_oprf_endpoint_rejects_invalid_points(
    tmp_path: Path,
) -> None:
    client, _identity = make_client(tmp_path)

    response = client.post(
        "/pact/api/v1/device-bindings/oprf",
        json={"blinded": "bad"},
    )

    assert response.status_code == 400


def register_claim(
    client: TestClient,
    identity: ClaimantIdentity,
    signed,
) -> dict[str, object]:
    challenge = client.post(
        "/pact/api/v1/challenges",
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
        "/pact/api/v1/claims",
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
        "/pact/api/v1/challenges",
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
        "/pact/api/v1/disputes",
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
        "/pact/api/v1/challenges",
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
        f"/pact/api/v1/profiles/{identity.key_id}/update",
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

    registry_response = client.get("/pact/api/v1/registry")
    assert registry_response.status_code == 200
    assert '{\n  "registry_url":' in registry_response.text
    routes = client.get("/pact/api/v1/server/routes")
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
    server_info = client.get("/pact/api/v1/server/info")
    assert server_info.status_code == 200
    assert '{\n  "registry_url":' in server_info.text
    assert server_info.json()["server"] == registry_info["server"]
    assert (
        client.get(f"/pact/api/v1/profiles/{identity.key_id}").status_code
        == 200
    )
    assert (
        client.get(
            f"/pact/api/v1/profiles/{identity.key_id}/evidence"
        ).status_code
        == 200
    )
    evidence_response = client.get(
        f"/pact/api/v1/profiles/{identity.key_id}/evidence"
    )
    evidence = evidence_response.json()
    assert evidence["trust_tier"] == "unauthenticated_device"
    assert evidence["trust_labels"] == ["unauthenticated_device"]
    assert (
        client.get(f"/pact/api/v1/claims/{claim['claim_id']}").status_code
        == 200
    )

    root = client.get("/", follow_redirects=False)
    assert root.status_code == 308
    assert root.headers["location"] == "/pact"
    home = client.get("/pact")
    assert "PACT Registry" in home.text
    profile_page = client.get(f"/pact/profiles/{identity.key_id}")
    assert identity.key_id in profile_page.text
    assert "device_fingerprint" not in profile_page.text
    assert "<strong>Trust tier:</strong> unauthenticated_device" in profile_page.text
    assert "<strong>Auth level:</strong>" not in profile_page.text
    assert (
        client.get(
            f"/profiles/{identity.key_id}", follow_redirects=False
        ).headers["location"]
        == f"/pact/profiles/{identity.key_id}"
    )
    claim_page = client.get(f"/pact/claims/{claim['claim_id']}")
    assert claim["claim_id"] in claim_page.text
    assert "<summary>Signed manifest</summary>" in claim_page.text
    assert '{\n  "manifest":' in claim_page.text
    verify_page = client.get(f"/pact/verify/claim/{claim['claim_id']}")
    assert "Claim check" in verify_page.text
    assert "claim_verified_content_unchecked" in verify_page.text
    assert "unauthenticated_device" in verify_page.text
    assert home.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in home.headers


def test_web_avoidance_report_flow_requires_public_nonce(
    tmp_path: Path,
) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)
    public_claim = register_claim(
        client, identity, make_signed_manifest(identity)
    )

    report_body = {
        "claim_id": public_claim["claim_id"],
        "observed_url": "https://example.com/repost",
        "reason": "embedded_reference_removed",
        "description": "Manifest appears stripped.",
        "evidence": {
            "kind": "hash_only",
            "digest": "sha256-example",
            "mime_type": "text/plain",
        },
    }
    unsigned_report = client.post(
        "/pact/api/v1/reports/avoidance",
        json=report_body,
    )
    assert unsigned_report.status_code == 401

    report_response = client.post(
        "/pact/api/v1/reports/avoidance",
        json=report_body,
        headers=profile_auth_headers(
            client,
            identity,
            method="POST",
            path="/pact/api/v1/reports/avoidance",
            body=report_body,
        ),
    )
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["status"] == "submitted"
    assert report["public_visibility"] == "claimant_visible"
    assert report["reporter_key_id"] == identity.key_id
    assert report["reporter_type"] == "registered_profile"
    assert report["reporter_credibility"]["submitted_dispute_count"] == 0
    assert "observed_url" not in report
    assert "evidence_digest" not in report

    listed = client.get(
        f"/pact/api/v1/claims/{public_claim['claim_id']}/reports"
    ).json()["reports"]
    assert listed == []
    fetched = client.get(f"/pact/api/v1/reports/{report['report_id']}")
    assert fetched.status_code == 404

    spread = client.get(
        f"/pact/api/v1/claims/{public_claim['claim_id']}/spread"
    ).json()
    assert spread["status"] == "no_reports"
    assert spread["report_count"] == 0
    assert spread["domain_count"] == 0

    private_claim = register_claim(
        client,
        identity,
        make_private_signed_manifest(identity),
    )
    rejected_body = {
        "claim_id": private_claim["claim_id"],
        "evidence": {"kind": "hash_only", "digest": "sha256-example"},
    }
    rejected = client.post(
        "/pact/api/v1/reports/avoidance",
        json=rejected_body,
        headers=profile_auth_headers(
            client,
            identity,
            method="POST",
            path="/pact/api/v1/reports/avoidance",
            body=rejected_body,
        ),
    )
    assert rejected.status_code == 400
    assert "public content verification" in rejected.text


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
    assert '<a href="/pact/docs">PACT library</a>' in home.text
    assert '<a href="/pact/api/docs">API Surface</a>' in home.text
    docs = docs_client.get("/pact/docs/")
    assert docs.status_code == 200
    assert "PACT Documentation" in docs.text
    assert docs_client.get("/pact/api/docs").status_code == 200
    route_names = {
        route["name"]
        for route in docs_client.get("/pact/api/v1/server/routes").json()[
            "routes"
        ]
    }
    assert "documentation" in route_names
    assert (
        docs_client.get("/pact/api/v1/server/info").json()["documentation_url"]
        == "http://testserver/pact/docs/"
    )


def test_api_docs_have_scoped_content_security_policy(tmp_path: Path) -> None:
    client, _identity = make_client(tmp_path)

    home_csp = client.get("/").headers["Content-Security-Policy"]
    docs_csp = client.get("/pact/api/docs").headers["Content-Security-Policy"]
    docs_slash_csp = client.get("/pact/api/docs/").headers[
        "Content-Security-Policy"
    ]
    default_docs_csp = client.get("/pact/docs").headers[
        "Content-Security-Policy"
    ]

    assert (
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" in docs_csp
    )
    assert "img-src 'self' data: https://fastapi.tiangolo.com" in docs_csp
    assert "'unsafe-inline'" in docs_csp
    assert "https://cdn.jsdelivr.net" in docs_slash_csp
    assert "https://cdn.jsdelivr.net" in default_docs_csp
    assert "http://localhost:" not in docs_csp
    assert "http://127.0.0.1:" not in docs_csp
    assert "https://fastapi.tiangolo.com" not in home_csp


def test_workspace_csp_allows_localhost_only_in_local_mode(
    tmp_path: Path,
) -> None:
    hosted_client, _identity = make_client(
        tmp_path / "hosted",
        enable_workspace=True,
    )
    landing_csp = hosted_client.get("/pact").headers["Content-Security-Policy"]
    assert "'unsafe-eval'" not in landing_csp
    hosted_csp = hosted_client.get("/pact/web").headers[
        "Content-Security-Policy"
    ]
    assert "http://localhost:" not in hosted_csp
    assert "http://127.0.0.1:" not in hosted_csp

    registry_url = "http://127.0.0.1:8000"
    app = create_app(
        None,
        public_base_url=registry_url,
        registry_url=registry_url,
        local_mode=True,
        enable_workspace=True,
    )
    local_csp = (
        TestClient(app).get("/pact/web").headers["Content-Security-Policy"]
    )
    assert "http://localhost:*" in local_csp
    assert "http://127.0.0.1:*" in local_csp


def test_request_id_header_is_bounded_and_sanitized(tmp_path: Path) -> None:
    client, _identity = make_client(tmp_path)

    response = client.get(
        "/pact/api/v1/registry",
        headers={"X-Request-ID": "abc\nbad" + "x" * 200},
    )

    request_id = response.headers["X-Request-ID"]
    assert len(request_id) <= 64
    assert "\n" not in request_id
    assert request_id.startswith("abc")


def test_web_updates_profile_display_name(tmp_path: Path) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)

    profile = update_profile(client, identity, "Alice Updated")

    assert profile["display_name"] == "Alice Updated"
    loaded = client.get(f"/pact/api/v1/profiles/{identity.key_id}").json()
    assert loaded["display_name"] == "Alice Updated"
    assert "device_fingerprint" not in loaded


def test_openapi_schema_includes_actionable_examples(tmp_path: Path) -> None:
    client, _identity = make_client(tmp_path)

    schema = client.get("/pact/api/openapi.json").json()

    challenge_examples = schema["paths"]["/pact/api/v1/challenges"]["post"][
        "requestBody"
    ]["content"]["application/json"]["examples"]
    assert "profile_registration" in challenge_examples
    assert "claim_registration" in challenge_examples
    assert (
        challenge_examples["claim_registration"]["value"]["purpose"]
        == "claim_registration"
    )

    profile_examples = schema["paths"]["/pact/api/v1/profiles"]["post"][
        "requestBody"
    ]["content"]["application/json"]["examples"]
    assert profile_examples["profile_registration"]["value"]["payload"][
        "device_fingerprint"
    ]

    claim_examples = schema["paths"]["/pact/api/v1/claims"]["post"][
        "requestBody"
    ]["content"]["application/json"]["examples"]
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
        "/pact/api/v1/inspect",
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
    assert (
        inspected["registry_verification"]["label"] == "content_claim_verified"
    )
    assert inspected["source_material"]["content_binding_checked"] is True
    assert inspected["source_material"]["verification"]["valid"] is True
    assert (
        inspected["source_material"]["verification"]["overall_verdict"]
        == "content_verified"
    )


def test_web_inspect_resolves_embedded_pdf_manifest_sidecar(
    tmp_path: Path,
) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)
    signed = make_signed_manifest(identity)
    claim = register_claim(client, identity, signed)
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    source = io.BytesIO()
    writer.write(source)
    embedded = embed_c2pa_manifest_in_pdf(
        source.getvalue(),
        signed.to_json(),
    )

    response = client.post(
        "/pact/api/v1/inspect",
        files={
            "file": (
                "work.pact.pdf",
                embedded.asset_bytes,
                "application/pdf",
            )
        },
    )

    assert response.status_code == 200
    inspected = response.json()
    assert inspected["recognized"] is True
    assert inspected["reference"]["carrier"] == "pdf_c2pa_sidecar"
    assert inspected["reference"]["claim_id"] == claim["claim_id"]
    assert inspected["registry_claim"]["claim_id"] == claim["claim_id"]
    assert inspected["signed_manifest"]["manifest"]["claim_id"] == claim[
        "claim_id"
    ]


def test_web_inspect_rejects_oversized_upload(tmp_path: Path) -> None:
    client, _identity = make_client(
        tmp_path,
        upload_limit_config=UploadLimitConfig(
            max_request_body_bytes=10_000,
            max_upload_bytes=8,
        ),
    )

    response = client.post(
        "/pact/api/v1/inspect",
        files={"file": ("work.txt", b"too-large-for-limit", "text/plain")},
    )

    assert response.status_code == 413


def test_api_rejects_oversized_request_body(tmp_path: Path) -> None:
    client, _identity = make_client(
        tmp_path,
        upload_limit_config=UploadLimitConfig(max_request_body_bytes=20),
    )

    response = client.post(
        "/pact/api/v1/challenges",
        json={
            "purpose": "profile_registration",
            "difficulty": 4,
            "padding": "x" * 100,
        },
    )

    assert response.status_code == 413
    assert "request body is too large" in response.text


def test_challenge_endpoint_enforces_server_difficulty_floor(
    tmp_path: Path,
) -> None:
    client, _identity = make_client(tmp_path)

    response = client.post(
        "/pact/api/v1/challenges",
        json={"purpose": "account_authorization", "difficulty": 0},
    )

    assert response.status_code == 200
    assert response.json()["difficulty"] == 8


def test_web_inspect_rejects_zip_bomb_shape(tmp_path: Path) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED
    ) as zip_file:
        zip_file.writestr("entry.txt", b"a" * 200)
    client, _identity = make_client(
        tmp_path,
        upload_limit_config=UploadLimitConfig(
            max_request_body_bytes=10_000,
            max_upload_bytes=10_000,
            max_zip_uncompressed_bytes=100,
        ),
    )

    response = client.post(
        "/pact/api/v1/inspect",
        files={
            "file": (
                "carrier.zip",
                archive.getvalue(),
                "application/zip",
            )
        },
    )

    assert response.status_code == 413
    assert "ZIP file expands" in response.text


def test_web_lists_profile_claims_and_disputes(tmp_path: Path) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)
    signed = make_signed_manifest(identity)
    claim = register_claim(client, identity, signed)
    claim_id = cast(str, claim["claim_id"])
    dispute = open_dispute(
        client,
        identity,
        claim_id,
        misuse_url="https://example.com/copied-media",
    )
    assert dispute["misuse_url"] == "https://example.com/copied-media"
    assert dispute["claim_dispute_count"] == 1
    dispute_credibility = cast(
        dict[str, object],
        dispute["reporter_credibility"],
    )
    assert dispute_credibility["submitted_dispute_count"] == 1
    assert dispute["opened_by_key_id"] == identity.key_id

    claims_response = client.get(
        f"/pact/api/v1/profiles/{identity.key_id}/claims"
    )
    assert claims_response.status_code == 200
    claims = claims_response.json()["claims"]
    assert [item["claim_id"] for item in claims] == [claim_id]

    profile_disputes = client.get(
        f"/pact/api/v1/profiles/{identity.key_id}/disputes"
    )
    assert profile_disputes.status_code == 200
    assert profile_disputes.json()["disputes"][0]["misuse_url"] == (
        "https://example.com/copied-media"
    )

    claim_disputes = client.get(f"/pact/api/v1/claims/{claim_id}/disputes")
    assert claim_disputes.status_code == 200
    assert (
        claim_disputes.json()["disputes"][0]["dispute_id"]
        == (dispute["dispute_id"])
    )
    assert (
        claim_disputes.json()["disputes"][0]["reporter_credibility"][
            "open_dispute_count"
        ]
        == 1
    )


def test_web_claim_match_endpoint_returns_prior_fingerprint_match(
    tmp_path: Path,
) -> None:
    client, identity = make_client(tmp_path)
    register_profile(client, identity)
    original = make_fingerprinted_manifest(identity, b"hello similar world")
    claim = register_claim(client, identity, original)
    candidate = make_fingerprinted_manifest(identity, b"hello similar world")

    response = client.post(
        "/pact/api/v1/claims/matches",
        json={"signed_manifest_json": candidate.to_json().decode("utf-8")},
    )

    assert response.status_code == 200
    matches = response.json()["matches"]
    assert matches[0]["claim_id"] == claim["claim_id"]
    assert matches[0]["score"] == 1.0
    assert matches[0]["matches"][0]["fingerprint_id"] in {
        "pact.exact.sha256.v1",
        "pact.text.simhash.v1",
    }


def test_web_workspace_is_optional_and_serves_pyodide_assets(
    tmp_path: Path,
) -> None:
    disabled_client, _identity = make_client(tmp_path / "disabled")
    assert disabled_client.get("/pact").status_code == 200
    assert disabled_client.get("/pact/web").status_code == 404

    enabled_client, _identity = make_client(
        tmp_path / "enabled",
        enable_workspace=True,
    )
    landing = enabled_client.get("/pact")
    assert landing.status_code == 200
    assert "/pact/web" in landing.text
    workspace = enabled_client.get("/pact/web")
    assert workspace.status_code == 200
    assert "PACT Workspace" in workspace.text
    assert "Output" not in workspace.text
    assert "<script>" not in workspace.text
    assert 'data-page="identity"' in workspace.text
    assert 'data-page="sign"' in workspace.text
    assert 'data-page="mutations"' in workspace.text
    assert "Display name (optional)" in workspace.text
    assert 'id="identity-display-name-field"' in workspace.text
    assert 'id="identity-guidance"' in workspace.text
    assert "Passcode" in workspace.text
    assert "Create profile" in workspace.text
    assert "Recovery and account options" in workspace.text
    assert "Log out" in workspace.text
    assert "Trust upgrades" in workspace.text
    assert workspace.text.index(
        "Recovery and account options"
    ) < workspace.text.index("Trust upgrades")
    assert "<summary>Domain to verify</summary>" in workspace.text
    assert "Sign and publish" in workspace.text
    assert 'id="source-url"' in workspace.text
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
    worker_js = Path("src/pact/web/static/pyodide-worker.js").read_text(
        encoding="utf-8"
    )
    assert "Generative AI training" in workspace_js
    assert "Search indexing" in workspace_js
    assert "Redistribution" in workspace_js
    assert '["Display name", current.display_name || "Anonymous"]' in workspace_js
    assert "pact-signed" not in workspace_js
    assert "optional-protection-fieldset" in workspace_js
    assert "textAvailable" in workspace_js
    assert "imageAvailable" in workspace_js
    assert "embeddedAvailable" in workspace_js
    assert '["Auth level"' not in workspace_js
    assert '["Trust tier", trustTier]' in workspace_js
    assert "create_device_binding_oprf_request\", [\n      base64(localInput)" in workspace_js
    assert "Where did you see the misuse?" in workspace.text
    assert "Invisible marks" in workspace.text
    assert "protected text copy" in workspace.text
    assert "claim locator" in workspace.text
    assert "proof JSON" in workspace.text
    assert "c2pa.cropped" not in workspace.text
    assert "c2pa.resized" not in workspace.text
    assert "Disputes" in workspace.text
    assert 'id="view-dispute-id"' not in workspace.text
    assert 'id="view-dispute"' not in workspace.text
    assert "Model checks" not in workspace.text
    assert 'autocomplete="username"' in workspace.text
    assert "PYODIDE_SHA384" in worker_js
    assert "integrity check failed" in worker_js
    assert "indexURL: PYODIDE_BASE_URL" in worker_js
    assert "pypi.org" not in worker_js
    assert "rfc8785-0.1.4-py3-none-any.whl" in worker_js
    assert "fe25519-1.5.0-py3-none-any.whl" in worker_js
    assert "ge25519-1.5.1-py3-none-any.whl" in worker_js
    assert "parts-1.7.0-py3-none-any.whl" in worker_js
    assert "oblivious-7.0.0-py3-none-any.whl" in worker_js
    csp = workspace.headers["Content-Security-Policy"]
    assert "'unsafe-eval'" in csp
    assert "'wasm-unsafe-eval'" in csp
    assert (
        "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' https://cdn.jsdelivr.net blob:"
        in csp
    )
    assert (
        "connect-src 'self' blob: https://cdn.jsdelivr.net "
        "https://files.pythonhosted.org" in csp
    )
    assert "connect-src 'self' https:" not in csp
    package = enabled_client.get("/pact/web/pact-browser-core.pyz")
    assert package.status_code == 200
    assert package.headers["content-type"] == "application/zip"
    core_names = zipfile.ZipFile(io.BytesIO(package.content)).namelist()
    assert "bn254/__init__.py" in core_names
    assert "pact/browser.py" in core_names
    assert "pact/oprf.py" in core_names
    assert "pact/registry/app.py" not in core_names
    assert "pact/registry/store.py" not in core_names
    assert "pact/carriers/c2pa_text.py" not in core_names

    documents = enabled_client.get("/pact/web/pact-browser-documents.pyz")
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

    workspace = client.get("/pact/web")
    assert workspace.status_code == 200
    assert "standalone web interface" in workspace.text
    assert "https://registry.example" in workspace.text
    assert client.get("/pact/api/v1/registry").status_code == 404


def test_api_rate_limit_ignores_forwarded_client_ip_by_default(
    tmp_path: Path,
) -> None:
    client, _identity = make_client(
        tmp_path,
        rate_limit_config=RateLimitConfig(
            window_seconds=60,
            ip_limit=2,
            identity_limit=100,
        ),
    )

    headers = {"X-Forwarded-For": "203.0.113.10"}

    assert (
        client.get("/pact/api/v1/registry", headers=headers).status_code == 200
    )
    assert (
        client.get("/pact/api/v1/registry", headers=headers).status_code == 200
    )
    limited = client.get("/pact/api/v1/registry", headers=headers)

    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "59"
    assert (
        client.get(
            "/pact/api/v1/registry",
            headers={"X-Forwarded-For": "203.0.113.11"},
        ).status_code
        == 429
    )


def test_api_rate_limit_uses_forwarded_client_ip_for_trusted_proxy(
    tmp_path: Path,
) -> None:
    client, _identity = make_client(
        tmp_path,
        rate_limit_config=RateLimitConfig(
            window_seconds=60,
            ip_limit=2,
            identity_limit=100,
        ),
        trusted_proxy_config=TrustedProxyConfig(
            trusted_proxy_cidrs=("testclient",)
        ),
    )

    headers = {"X-Forwarded-For": "203.0.113.10"}

    assert (
        client.get("/pact/api/v1/registry", headers=headers).status_code == 200
    )
    assert (
        client.get("/pact/api/v1/registry", headers=headers).status_code == 200
    )
    limited = client.get("/pact/api/v1/registry", headers=headers)

    assert limited.status_code == 429
    assert (
        client.get(
            "/pact/api/v1/registry",
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
            "payload": {"device_fingerprint": device_binding_token(identity)},
            "signature": "invalid",
        }

    first = client.post(
        "/pact/api/v1/profiles",
        json=profile_request("018f7f79-7b42-7c00-8000-000000000001"),
        headers={"X-Forwarded-For": "203.0.113.20"},
    )
    second = client.post(
        "/pact/api/v1/profiles",
        json=profile_request("018f7f79-7b42-7c00-8000-000000000002"),
        headers={"X-Forwarded-For": "203.0.113.21"},
    )

    assert first.status_code == 400
    assert second.status_code == 429
