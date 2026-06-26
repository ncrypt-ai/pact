import json
from pathlib import Path

from pact.cli import build_parser, main


def test_cli_identity_sign_verify_and_inspect_flow(tmp_path: Path, capsys) -> None:
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
    public_jwk_path.write_text(json.dumps(identity_show["public_jwk"]), encoding="utf-8")

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
    assert not (tmp_path / "web-data" / "ca" / "offline_root_private_key.pem").exists()


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
