import json
from pathlib import Path

from pact.cli import build_parser, main


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
    assert nonce_path.exists()
    sign_output = json.loads(capsys.readouterr().out)
    assert sign_output["manifest"] == str(manifest_path)

    assert (
        main(
            [
                "verify",
                str(manifest_path),
                "--public-jwk",
                str(public_jwk_path),
                "--content",
                str(content_path),
                "--nonce",
                str(nonce_path),
            ]
        )
        == 0
    )
    verify_output = json.loads(capsys.readouterr().out)
    assert verify_output["signature_valid"] is True

    assert main(["inspect", str(manifest_path)]) == 0
    inspect_output = json.loads(capsys.readouterr().out)
    assert inspect_output["manifest"]["registry_url"] == registry

    assert (
        main(
            [
                "privacy",
                "audit",
                str(manifest_path),
                "--content",
                str(content_path),
                "--nonce",
                str(nonce_path),
            ]
        )
        == 0
    )
    privacy_output = json.loads(capsys.readouterr().out)
    assert privacy_output["passed"] is True


def test_cli_web_command_bootstraps_local_app(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: dict[str, object] = {}

    def fake_run(app, host: str, port: int, log_level: str) -> None:
        calls["host"] = host
        calls["port"] = port
        calls["log_level"] = log_level
        calls["app_title"] = app.title

    monkeypatch.setattr("pact.cli.uvicorn.run", fake_run)
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
    assert calls["app_title"] == "PACT Registry"
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
