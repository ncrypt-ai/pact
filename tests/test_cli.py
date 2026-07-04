import json
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest

import pact.cli as cli
from pact import (
    CanonicalizationProfile,
    CarrierMode,
    ClaimantIdentity,
    Manifest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    base64url_encode,
    browser,
    embed_text_carrier,
    extract_text_carrier,
    sign_manifest,
)
from pact.cli import build_parser, main
from pact.crypto import base64url_decode
from pact.metadata import PACKAGE_VERSION
from pact.oprf import device_binding_input, evaluate_device_oprf
from pact.registry.store import RegistryEventType


@pytest.fixture(autouse=True)
def isolated_device_binding_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        "PACT_DEVICE_BINDING_DIR",
        str(tmp_path / "device-bindings"),
    )


def test_cli_identity_sign_verify_and_inspect_flow(
    tmp_path: Path, capsys
) -> None:
    identity_file = tmp_path / "identities"
    registry = "https://registry.example"

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    identity_output = json.loads(capsys.readouterr().out)
    assert identity_output["registry_url"] == registry

    assert (
        main(
            [
                "identity",
                "show",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    identity_show = json.loads(capsys.readouterr().out)
    public_jwk_path = tmp_path / "public_jwk.json"
    public_jwk_path.write_text(
        json.dumps(identity_show["public_jwk"]), encoding="utf-8"
    )

    content_path = tmp_path / "work.txt"
    content_path.write_text("hello\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    nonce_path = tmp_path / "nonce.bin"
    assert (
        main(
            [
                "sign",
                str(content_path),
                "--registry",
                registry,
                "--registry-root-fingerprint",
                "A" * 43,
                "--output",
                str(manifest_path),
                "--nonce-out",
                str(nonce_path),
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    assert manifest_path.exists()
    assert not nonce_path.exists()
    sign_output = json.loads(capsys.readouterr().out)
    carrier_path = tmp_path / "work.pact.txt"
    assert sign_output["manifest"] == str(manifest_path)
    assert sign_output["carrier"] == str(carrier_path)
    assert sign_output["nonce"] is None
    assert sign_output["nonce_disclosure"] == "public"
    assert sign_output["public_content_verifiable"] is True
    assert carrier_path.exists()
    carrier = extract_text_carrier(carrier_path.read_bytes())
    assert carrier.content == b"hello\n"
    assert carrier.mode is CarrierMode.VISIBLE
    assert carrier.signed_manifest is not None
    assert carrier.signed_manifest.manifest.claim_id == UUID(
        sign_output["claim_id"]
    )

    default_content_path = tmp_path / "default-name.txt"
    default_content_path.write_text("hello again\n", encoding="utf-8")
    assert (
        main(
            [
                "sign",
                str(default_content_path),
                "--registry",
                registry,
                "--registry-root-fingerprint",
                "A" * 43,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    default_output = json.loads(capsys.readouterr().out)
    assert default_output["manifest"] == str(
        tmp_path / "default-name.manifest.json"
    )
    assert default_output["carrier"] == str(tmp_path / "default-name.pact.txt")
    assert default_output["nonce"] is None
    assert (tmp_path / "default-name.manifest.json").exists()
    assert (tmp_path / "default-name.pact.txt").exists()
    assert not (tmp_path / "default-name.nonce").exists()

    private_manifest_path = tmp_path / "private-manifest.json"
    private_nonce_path = tmp_path / "private-nonce.bin"
    assert (
        main(
            [
                "sign",
                str(default_content_path),
                "--registry",
                registry,
                "--registry-root-fingerprint",
                "A" * 43,
                "--output",
                str(private_manifest_path),
                "--nonce-out",
                str(private_nonce_path),
                "--private-nonce",
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    private_output = json.loads(capsys.readouterr().out)
    assert private_output["nonce"] == str(private_nonce_path)
    assert private_output["nonce_disclosure"] == "private"
    assert private_nonce_path.exists()

    assert (
        main(
            [
                "verify",
                str(manifest_path),
                "--public-jwk",
                str(public_jwk_path),
                "--content",
                str(content_path),
            ]
        )
        == 0
    )
    verify_output = json.loads(capsys.readouterr().out)
    assert verify_output["signature_valid"] is True

    assert main(["inspect", str(manifest_path)]) == 0
    raw_inspect_output = capsys.readouterr().out
    assert raw_inspect_output.startswith("{\n  ")
    assert '\n  "manifest": {' in raw_inspect_output
    inspect_output = json.loads(raw_inspect_output)
    assert inspect_output["manifest"]["registry_url"] == registry

    identity = ClaimantIdentity.generate(registry)
    nonce = b"\x02" * 32
    carrier_content = b"carrier text\n"
    carrier_manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint="A" * 43,
        content=carrier_content,
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
        nonce=nonce,
    )
    carrier_path = tmp_path / "carrier.txt"
    carrier_path.write_bytes(
        embed_text_carrier(
            carrier_content,
            sign_manifest(carrier_manifest, identity),
            nonce=nonce,
        )
    )
    assert main(["inspect", str(carrier_path)]) == 0
    carrier_output = json.loads(capsys.readouterr().out)
    assert carrier_output["recognized"] is True
    assert carrier_output["reference"]["carrier"] == "text:both"
    assert carrier_output["manifest"]["claim_id"] == str(
        carrier_manifest.claim_id
    )
    assert carrier_output["reference"]["locator"]["public_nonce"] == (
        base64url_encode(nonce)
    )
    assert (
        carrier_output["source_material"]["content_binding_checked"] is False
    )

    assert (
        main(
            [
                "privacy",
                "audit",
                str(manifest_path),
                "--content",
                str(content_path),
            ]
        )
        == 0
    )
    privacy_output = json.loads(capsys.readouterr().out)
    assert privacy_output["passed"] is True


def test_cli_identity_init_blocks_second_identity_for_same_device(
    tmp_path: Path,
) -> None:
    registry = "https://registry.example"

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(tmp_path / "identities"),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )

    with pytest.raises(SystemExit, match="already has an identity"):
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(tmp_path / "other-identities"),
                "--identity-password",
                "secret",
            ]
        )


def test_cli_identity_rotate_preserves_device_fingerprint(
    tmp_path: Path,
    capsys,
) -> None:
    identity_file = tmp_path / "identities"
    registry = "https://registry.example"

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)

    assert (
        main(
            [
                "identity",
                "rotate",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    rotated = json.loads(capsys.readouterr().out)

    assert rotated["previous_key_id"] == created["key_id"]
    assert rotated["replacement_key_id"] != created["key_id"]
    assert rotated["device_fingerprint"] == created["device_fingerprint"]


def test_cli_registry_device_binding_token_uses_blinded_oprf(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry = "https://registry.example"
    identity = ClaimantIdentity.generate(registry)
    store = cli.LocalDeviceBindingStore(tmp_path / "bindings")
    store.bind_new_identity(identity)
    blinded_requests: list[dict[str, object]] = []

    monkeypatch.setattr(
        cli,
        "_registry_info",
        lambda _registry_url: {"root_fingerprint": "A" * 43},
    )

    def fake_request_json(
        registry_url: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        assert registry_url == registry
        assert path == "/api/v1/device-bindings/oprf"
        assert payload is not None
        assert headers is None
        blinded_requests.append(payload)
        assert set(payload) == {"blinded"}
        return cast(
            dict[str, object],
            evaluate_device_oprf(payload, server_scalar=b"\x07" * 32),
        )

    monkeypatch.setattr(cli, "_request_json", fake_request_json)

    first = cli._registry_device_binding_token(registry, store)
    second = cli._registry_device_binding_token(registry, store)

    assert first == second
    assert first.startswith("pact-device-binding-v2.")
    assert blinded_requests[0] != blinded_requests[1]
    assert store.fingerprint(registry) not in json.dumps(blinded_requests)


def test_cli_report_submits_signed_profile_request(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    registry = "https://registry.example"
    identity_file = tmp_path / "identity-store"
    evidence_file = tmp_path / "suspicious.txt"
    evidence_file.write_text("copied text\n", encoding="utf-8")
    claim_id = "018f7f79-7b42-7c00-9000-000000000123"

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    identity = json.loads(capsys.readouterr().out)
    posted: list[dict[str, object]] = []

    def fake_request_json(
        registry_url: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        assert registry_url == registry
        if path == "/api/v1/challenges":
            assert payload == {
                "purpose": "account_authorization",
                "bound_key_id": identity["key_id"],
            }
            assert headers is None
            issued_at = datetime.now(UTC)
            return {
                "registry_url": registry,
                "challenge_id": "018f7f79-7b42-7c00-9000-000000000124",
                "purpose": "account_authorization",
                "issued_at": issued_at.isoformat(),
                "expires_at": (issued_at + timedelta(minutes=5)).isoformat(),
                "challenge_nonce": "nonce",
                "difficulty": 0,
                "bound_key_id": identity["key_id"],
            }
        assert path == "/api/v1/reports/avoidance"
        assert payload is not None
        assert headers is not None
        assert headers["X-PACT-Profile-Key-Id"] == identity["key_id"]
        assert headers["X-PACT-Challenge-Id"]
        assert headers["X-PACT-Signature"]
        posted.append(payload)
        return {
            "report_id": "018f7f79-7b42-7c00-9000-000000000125",
            "claim_id": payload["claim_id"],
            "status": "submitted",
            "public_visibility": "claimant_visible",
            "owner_notified": True,
        }

    monkeypatch.setattr(cli, "_request_json", fake_request_json)

    assert (
        main(
            [
                "report",
                str(evidence_file),
                "--claim-id",
                claim_id,
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
                "--where",
                "https://example.test/repost",
                "--description",
                "Visible carrier was removed.",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["claim_id"] == claim_id
    assert output["reported_file"] == str(evidence_file)
    assert posted[0]["observed_url"] == "https://example.test/repost"
    assert posted[0]["description"] == "Visible carrier was removed."


def test_cli_web_command_bootstraps_local_app(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: dict[str, object] = {}

    def fake_run(
        app, host: str, port: int, log_level: str, access_log: bool
    ) -> None:
        calls["host"] = host
        calls["port"] = port
        calls["log_level"] = log_level
        calls["access_log"] = access_log
        calls["app_title"] = app.title
        calls["app_version"] = app.version

    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        types.SimpleNamespace(run=fake_run),
    )
    monkeypatch.setenv("PACT_REGISTRY_URL", "http://127.0.0.1:8123")

    assert (
        main(
            [
                "web",
                "--data-dir",
                str(tmp_path / "web-data"),
                "--port",
                "8123",
            ]
        )
        == 0
    )

    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8123
    assert calls["access_log"] is True
    assert calls["app_title"] == "PACT Registry"
    assert calls["app_version"] == PACKAGE_VERSION
    assert not (
        tmp_path / "web-data" / "ca" / "offline_root_private_key.pem"
    ).exists()


def test_cli_registry_init_writes_online_and_offline_ca_material(
    tmp_path: Path,
    capsys,
) -> None:
    data_dir = tmp_path / "registry-data"

    assert (
        main(
            [
                "registry",
                "init",
                "--registry",
                "https://registry.example",
                "--data-dir",
                str(data_dir),
                "--root-key-password",
                "offline-secret",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["registry_url"] == "https://registry.example"
    assert (data_dir / "ca" / "root_certificate.pem").exists()
    assert (data_dir / "ca" / "offline_root_private_key.pem").exists()
    assert (data_dir / "ca" / "intermediate_certificate.pem").exists()
    assert (data_dir / "ca" / "intermediate_private_key.pem").exists()
    assert (data_dir / "ca" / "oprf_server_secret").exists()


def test_cli_registry_init_uses_local_environment_defaults(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "registry-data"
    monkeypatch.setenv("PACT_DATA_DIR", str(data_dir))
    monkeypatch.setenv("PACT_REGISTRY_URL", "http://127.0.0.1:8123")
    monkeypatch.setenv("PACT_ROOT_KEY_PASSWORD", "offline-secret")

    assert main(["registry", "init"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["registry_url"] == "http://127.0.0.1:8123"
    assert (data_dir / "ca" / "root_certificate.pem").exists()
    assert (data_dir / "ca" / "oprf_server_secret").exists()


def test_cli_registry_init_prompts_for_missing_local_values(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "prompted-registry-data"
    answers = iter(("http://127.0.0.1:8124", str(data_dir)))

    monkeypatch.delenv("PACT_DATA_DIR", raising=False)
    monkeypatch.delenv("PACT_REGISTRY_URL", raising=False)
    monkeypatch.delenv("PACT_ROOT_KEY_PASSWORD", raising=False)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "offline-secret")

    assert main(["registry", "init"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["registry_url"] == "http://127.0.0.1:8124"
    assert (data_dir / "ca" / "root_certificate.pem").exists()


def test_cli_registry_teardown_deletes_persistent_local_state(
    tmp_path: Path,
    capsys,
) -> None:
    registry = "https://registry.example"
    data_dir = tmp_path / "registry-data"
    database = tmp_path / "registry.sqlite"
    identity_file = tmp_path / "identity-store"
    replacement_identity_file = tmp_path / "replacement-identity-store"

    assert (
        main(
            [
                "registry",
                "init",
                "--registry",
                registry,
                "--data-dir",
                str(data_dir),
                "--root-key-password",
                "offline-secret",
            ]
        )
        == 0
    )
    capsys.readouterr()

    store = cli.SqliteRegistryStore(database)
    store.append(
        RegistryEventType.PROFILE_REGISTERED,
        actor_key_id="claimant",
        data={"key_id": "claimant"},
    )
    store.connection.close()
    assert database.exists()

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    capsys.readouterr()
    binding_store = cli.LocalDeviceBindingStore()
    binding_path = binding_store.path(registry)
    assert binding_path.exists()

    assert (
        main(
            [
                "registry",
                "teardown",
                "--registry",
                registry,
                "--data-dir",
                str(data_dir),
                "--database",
                str(database),
                "--confirm-registry",
                registry,
                "--confirm-delete",
                f"delete registry {registry}",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["registry_url"] == registry
    assert output["browser_cleanup_url"] == (
        "https://registry.example/workspace?"
        "teardown_registry=https%3A%2F%2Fregistry.example"
    )
    assert not (data_dir / "ca" / "root_certificate.pem").exists()
    assert not (data_dir / "ca" / "intermediate_private_key.pem").exists()
    assert not database.exists()
    assert not binding_path.exists()

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(replacement_identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )


def test_cli_file_identity_uses_registry_and_password_environment(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    identity_file = tmp_path / "identities"
    monkeypatch.setenv("PACT_REGISTRY_URL", "https://registry.example")
    monkeypatch.setenv("PACT_IDENTITY_PASSWORD", "secret")

    assert (
        main(
            [
                "identity",
                "init",
                "--identity-file",
                str(identity_file),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["registry_url"] == "https://registry.example"


def test_cli_identity_public_jwk_writes_admin_file(
    tmp_path: Path,
    capsys,
) -> None:
    identity_file = tmp_path / "admin-identity.pem"
    admin_jwk = tmp_path / "admin.public.jwk.json"

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                "https://registry.example",
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        main(
            [
                "identity",
                "public-jwk",
                "--registry",
                "https://registry.example",
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
                "--out",
                str(admin_jwk),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    public_jwk = json.loads(admin_jwk.read_text(encoding="utf-8"))
    assert output["output"] == str(admin_jwk)
    assert public_jwk["kty"] == "EC"
    assert public_jwk["crv"] == "P-256"
    assert public_jwk["x"]
    assert public_jwk["y"]


def test_cli_recovery_json_preserves_profile_continuity_secret(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    registry = "https://registry.example"
    identity_file = tmp_path / "identity.pem"
    imported_identity_file = tmp_path / "imported-identity.pem"
    recovery_file = tmp_path / "pact-profile-recovery.json"

    assert (
        main(
            [
                "identity",
                "init",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        main(
            [
                "identity",
                "export",
                "--registry",
                registry,
                "--identity-file",
                str(identity_file),
                "--identity-password",
                "secret",
                "--export-password",
                "secret",
                "--recovery-json",
                "--out",
                str(recovery_file),
            ]
        )
        == 0
    )
    capsys.readouterr()
    recovery = json.loads(recovery_file.read_text(encoding="utf-8"))
    assert recovery["registry_url"] == registry
    assert recovery["encrypted_pkcs8_b64"]
    continuity_secret = recovery["continuity_secret"]
    assert len(base64url_decode(continuity_secret, length=32)) == 32

    monkeypatch.setenv(
        "PACT_DEVICE_BINDING_DIR",
        str(tmp_path / "imported-device-bindings"),
    )
    assert (
        main(
            [
                "identity",
                "import",
                "--source",
                str(recovery_file),
                "--import-password",
                "secret",
                "--identity-file",
                str(imported_identity_file),
                "--identity-password",
                "secret",
            ]
        )
        == 0
    )

    imported = json.loads(capsys.readouterr().out)
    binding_store = cli.LocalDeviceBindingStore()
    binding = binding_store.load(registry)
    assert binding is not None
    assert binding.key_id == imported["key_id"]
    assert binding.continuity_secret == continuity_secret
    root_fingerprint = "A" * 43
    assert binding_store.private_binding_input(
        registry,
        root_fingerprint,
    ) == device_binding_input(
        local_secret=base64url_decode(continuity_secret, length=32),
        registry_root_fingerprint=root_fingerprint,
        device_fingerprint=f"profile:{imported['key_id']}",
    )


def test_browser_identity_includes_profile_continuity_secret() -> None:
    created = json.loads(
        browser.create_identity("https://registry.example", "secret")
    )

    assert created["registry_url"] == "https://registry.example"
    assert created["encrypted_pkcs8_b64"]
    assert len(base64url_decode(created["continuity_secret"], length=32)) == 32


def test_cli_parser_exposes_registry_serve_command() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "registry",
            "serve",
            "--registry",
            "https://registry.example",
            "--data-dir",
            "./data",
            "--public-base-url",
            "https://registry.example",
        ]
    )
    assert args.command == "registry"
    assert args.registry_command == "serve"
    assert args.database == ":memory:"
    assert not hasattr(args, "store_backend")
    assert not hasattr(args, "sqlite_database")


def test_cli_parser_exposes_registry_teardown_command() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "registry",
            "teardown",
            "--registry",
            "https://registry.example",
            "--data-dir",
            "./data",
            "--database",
            "./registry.sqlite",
            "--confirm-registry",
            "https://registry.example",
            "--confirm-delete",
            "delete registry https://registry.example",
        ]
    )
    assert args.command == "registry"
    assert args.registry_command == "teardown"
    assert args.database == "./registry.sqlite"


def test_cli_help_documents_registry_teardown(capsys) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as error:
        parser.parse_args(["registry", "teardown", "--help"])

    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert "usage: pact registry teardown" in help_text
    assert "--database" in help_text
    assert "--confirm-registry" in help_text
    assert "--confirm-delete" in help_text


def test_cli_parser_exposes_watermark_image_command() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "watermark",
            "image",
            "input.png",
            "--claim-id",
            "018f7f79-7b42-7c00-8000-000000000123",
            "--registry-root-fingerprint",
            "A" * 43,
            "--output",
            "out.png",
        ]
    )
    assert args.command == "watermark"
    assert args.watermark_command == "image"


def test_cli_parser_exposes_watermark_text_command() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "watermark",
            "text",
            "input.txt",
            "--methods",
            "lexical,syntactic",
            "--secret",
            "secret",
            "--output",
            "out.txt",
            "--confirm",
        ]
    )
    assert args.command == "watermark"
    assert args.watermark_command == "text"


def test_cli_probe_create_analyze_and_export_flow(
    tmp_path: Path, capsys
) -> None:
    protected = tmp_path / "protected.txt"
    protected.write_text(
        "The silver orchard opened under the blue evening sky. "
        "Every branch carried a glass bell that chimed when the river fog arrived. "
        "Mara wrote the sound into her notebook before the lighthouse went dark.",
        encoding="utf-8",
    )
    control = tmp_path / "control.txt"
    control.write_text(
        "The public garden opened after the spring rain ended. "
        "Every path carried small signs that explained where visitors should walk. "
        "The caretaker closed the gate before the town clock sounded.",
        encoding="utf-8",
    )
    probe_set = tmp_path / "probes.json"

    assert (
        main(
            [
                "probe",
                "create",
                "--protected",
                str(protected),
                "--control",
                str(control),
                "--target-model",
                "model-a",
                "--output",
                str(probe_set),
            ]
        )
        == 0
    )
    create_output = json.loads(capsys.readouterr().out)
    assert create_output["probe_count"] == 2

    probes = json.loads(probe_set.read_text(encoding="utf-8"))["probes"]
    treatment = next(probe for probe in probes if probe["kind"] == "treatment")
    control_probe = next(
        probe for probe in probes if probe["kind"] == "control"
    )
    responses = tmp_path / "responses.jsonl"
    responses.write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "probe_id": treatment["probe_id"],
                        "response": treatment["expected_continuation"],
                    }
                ),
                json.dumps(
                    {
                        "probe_id": control_probe["probe_id"],
                        "response": "I do not know.",
                    }
                ),
            )
        ),
        encoding="utf-8",
    )
    package = tmp_path / "package.json"

    assert (
        main(
            [
                "probe",
                "analyze",
                str(probe_set),
                "--responses",
                str(responses),
                "--output",
                str(package),
            ]
        )
        == 0
    )
    analyze_output = json.loads(capsys.readouterr().out)
    assert analyze_output["treatment_matches"] == 1
    assert package.exists()

    exported = tmp_path / "exported.json"
    assert (
        main(
            [
                "probe",
                "export",
                str(package),
                "--output",
                str(exported),
            ]
        )
        == 0
    )
    export_output = json.loads(capsys.readouterr().out)
    assert export_output["signed"] is False
    assert exported.exists()
    assert export_output["package_digest"] == analyze_output["package_digest"]
