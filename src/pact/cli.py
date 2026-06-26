"""Command-line interface for local PACT workflows and registry hosting."""

import argparse
import json
import mimetypes
import os
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import cast

import uvicorn

from pact.canonical import CanonicalizationProfile
from pact.carriers.c2pa import C2paError, read_c2pa_asset
from pact.identity import (
    ClaimantIdentity,
    EncryptedFileIdentityStore,
    KeyringIdentityStore,
    normalize_registry_url,
)
from pact.manifest import (
    Manifest,
    SignedManifest,
    sign_manifest,
    verify_manifest,
)
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry
from pact.registry import RegistryCertificateAuthority, RegistryService
from pact.registry.store import FileRegistryStore
from pact.web import create_app


def _identity_store(args: argparse.Namespace) -> KeyringIdentityStore | EncryptedFileIdentityStore:
    identity_file = cast(str | None, getattr(args, "identity_file", None))
    if identity_file is None:
        return KeyringIdentityStore()
    return EncryptedFileIdentityStore(Path(identity_file).expanduser())


def _require_password(args: argparse.Namespace, field: str) -> str:
    value = cast(str | None, getattr(args, field, None))
    if not value:
        raise SystemExit(f"{field.replace('_', '-')} is required for file-backed identities")
    return value


def _load_identity(args: argparse.Namespace) -> ClaimantIdentity:
    store = _identity_store(args)
    registry_url = normalize_registry_url(cast(str, args.registry))
    if isinstance(store, KeyringIdentityStore):
        return store.load(registry_url)
    return store.load(registry_url, _require_password(args, "identity_password"))


def _save_identity(args: argparse.Namespace, identity: ClaimantIdentity) -> None:
    store = _identity_store(args)
    if isinstance(store, KeyringIdentityStore):
        store.save(identity)
        return
    store.save(identity, _require_password(args, "identity_password"))


def _serialize_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _default_policy(_name: str) -> Policy:
    return Policy(
        (
            PolicyEntry(Permission.GENERATIVE_TRAINING, PermissionValue.NOT_ALLOWED),
        )
    )


def _infer_mime_type(path: Path) -> str:
    mime_type, _encoding = mimetypes.guess_type(path.name)
    if mime_type is None:
        raise SystemExit("could not infer a MIME type from the input path")
    return mime_type


def _authority_paths(data_dir: Path) -> dict[str, Path]:
    ca_dir = data_dir / "ca"
    return {
        "root_certificate": ca_dir / "root_certificate.pem",
        "root_private_key": ca_dir / "offline_root_private_key.pem",
        "intermediate_certificate": ca_dir / "intermediate_certificate.pem",
        "intermediate_private_key": ca_dir / "intermediate_private_key.pem",
    }


def _load_authority(
    data_dir: Path,
    registry_url: str,
) -> RegistryCertificateAuthority:
    paths = _authority_paths(data_dir)
    required = (
        paths["root_certificate"],
        paths["intermediate_certificate"],
        paths["intermediate_private_key"],
    )
    if not all(path.exists() for path in required):
        raise SystemExit(
            "registry CA material is missing; run `pact registry init` first"
        )
    root_private_key = (
        paths["root_private_key"].read_bytes()
        if paths["root_private_key"].exists()
        else None
    )
    return RegistryCertificateAuthority(
        registry_url=registry_url,
        root_certificate_pem=paths["root_certificate"].read_bytes(),
        root_private_key_pem=root_private_key,
        intermediate_certificate_pem=paths["intermediate_certificate"].read_bytes(),
        intermediate_private_key_pem=paths["intermediate_private_key"].read_bytes(),
    )


def _write_authority(data_dir: Path, authority: RegistryCertificateAuthority) -> None:
    paths = _authority_paths(data_dir)
    paths["root_certificate"].parent.mkdir(parents=True, exist_ok=True)
    paths["root_certificate"].write_bytes(authority.root_certificate_pem)
    if authority.root_private_key_pem is not None:
        paths["root_private_key"].write_bytes(authority.root_private_key_pem)
        os.chmod(paths["root_private_key"], 0o600)
    paths["intermediate_certificate"].write_bytes(authority.intermediate_certificate_pem)
    paths["intermediate_private_key"].write_bytes(authority.intermediate_private_key_pem)
    os.chmod(paths["intermediate_private_key"], 0o600)


def _load_admin_jwks(paths: list[str]) -> tuple[dict[str, str], ...]:
    result: list[dict[str, str]] = []
    for path in paths:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise SystemExit(f"admin JWK file {path} must contain an object")
        result.append(cast(dict[str, str], parsed))
    return tuple(result)


def _bootstrap_service(
    data_dir: Path,
    registry_url: str,
    *,
    admin_jwk_files: list[str] | None = None,
) -> RegistryService:
    authority = _load_authority(data_dir, registry_url).online_material()
    store = FileRegistryStore(data_dir / "store")
    admin_public_jwks = _load_admin_jwks(admin_jwk_files or [])
    return RegistryService(
        registry_url,
        store=store,
        certificate_authority=authority,
        admin_public_jwks=admin_public_jwks,
    )


def _cmd_identity_init(args: argparse.Namespace) -> int:
    identity = ClaimantIdentity.generate(args.registry)
    _save_identity(args, identity)
    print(_serialize_json({"registry_url": identity.registry_url, "key_id": identity.key_id}))
    return 0


def _cmd_identity_show(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    print(
        _serialize_json(
            {
                "registry_url": identity.registry_url,
                "key_id": identity.key_id,
                "public_jwk": identity.public_jwk,
            }
        )
    )
    return 0


def _cmd_identity_export(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    export_password = cast(str, args.export_password)
    Path(args.out).write_bytes(identity.export_pkcs8(export_password))
    return 0


def _cmd_identity_import(args: argparse.Namespace) -> int:
    identity = ClaimantIdentity.import_pkcs8(
        args.registry,
        Path(args.source).read_bytes(),
        cast(str, args.import_password),
    )
    _save_identity(args, identity)
    print(_serialize_json({"registry_url": identity.registry_url, "key_id": identity.key_id}))
    return 0


def _cmd_identity_rotate(args: argparse.Namespace) -> int:
    current = _load_identity(args)
    replacement = current.rotate()
    _save_identity(args, replacement)
    print(
        _serialize_json(
            {
                "registry_url": replacement.registry_url,
                "previous_key_id": current.key_id,
                "replacement_key_id": replacement.key_id,
                "public_jwk": replacement.public_jwk,
            }
        )
    )
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    input_path = Path(args.input)
    content = input_path.read_bytes()
    mime_type = cast(str | None, args.mime_type) or _infer_mime_type(input_path)
    nonce = secrets.token_bytes(32)
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=cast(str, args.registry_root_fingerprint),
        content=content,
        mime_type=mime_type,
        canonicalization=CanonicalizationProfile(args.canonicalization),
        policy=_default_policy(args.policy),
        carriers=(args.carrier,) if args.carrier else (),
        nonce=nonce,
    )
    signed = sign_manifest(manifest, identity)
    Path(args.output).write_bytes(signed.to_json())
    Path(args.nonce_out).write_bytes(nonce)
    return 0


def _cmd_registry_init(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir).expanduser()
    authority = RegistryCertificateAuthority.initialize(
        normalize_registry_url(args.registry),
        root_private_key_password=cast(str, args.root_key_password),
    )
    _write_authority(data_dir, authority)
    print(
        _serialize_json(
            {
                "registry_url": authority.registry_url,
                "root_fingerprint": authority.root_fingerprint,
                "ca_directory": str((_authority_paths(data_dir)["root_certificate"]).parent),
            }
        )
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    signed = SignedManifest.from_json(Path(args.manifest).read_bytes())
    public_jwk = json.loads(Path(args.public_jwk).read_text(encoding="utf-8"))
    if not isinstance(public_jwk, dict):
        raise SystemExit("public JWK input must be a JSON object")
    content = Path(args.content).read_bytes() if args.content else None
    nonce = Path(args.nonce).read_bytes() if args.nonce else None
    report = verify_manifest(
        signed,
        cast(dict[str, object], public_jwk),
        content=content,
        nonce=nonce,
    )
    print(_serialize_json(asdict(report)))
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    target = Path(args.input)
    payload = target.read_bytes()
    try:
        signed = SignedManifest.from_json(payload)
        print(_serialize_json(signed.to_dict()))
        return 0
    except Exception:
        pass
    try:
        result = read_c2pa_asset(payload, mime_type=args.mime_type or _infer_mime_type(target))
    except C2paError as error:
        raise SystemExit(str(error)) from error
    print(_serialize_json(result.manifest_store_json))
    return 0


def _serve(
    *,
    data_dir: Path,
    registry_url: str,
    host: str,
    port: int,
    public_base_url: str,
    local_mode: bool,
    admin_jwk_files: list[str],
) -> int:
    service = _bootstrap_service(
        data_dir,
        registry_url,
        admin_jwk_files=admin_jwk_files,
    )
    app = create_app(
        service,
        public_base_url=public_base_url,
        local_mode=local_mode,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def _cmd_registry_serve(args: argparse.Namespace) -> int:
    return _serve(
        data_dir=Path(args.data_dir).expanduser(),
        registry_url=normalize_registry_url(args.registry),
        host=args.host,
        port=args.port,
        public_base_url=args.public_base_url,
        local_mode=False,
        admin_jwk_files=args.admin_jwk_file,
    )


def _cmd_web(args: argparse.Namespace) -> int:
    port = args.port
    public_base_url = f"http://127.0.0.1:{port}"
    data_dir = Path(args.data_dir).expanduser()
    try:
        _load_authority(data_dir, normalize_registry_url(args.registry))
    except SystemExit:
        _write_authority(
            data_dir,
            RegistryCertificateAuthority.initialize(
                normalize_registry_url(args.registry)
            ).online_material(),
        )
    return _serve(
        data_dir=data_dir,
        registry_url=normalize_registry_url(args.registry),
        host="127.0.0.1",
        port=port,
        public_base_url=public_base_url,
        local_mode=True,
        admin_jwk_files=args.admin_jwk_file,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pact")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity_subparsers = identity.add_subparsers(dest="identity_command", required=True)
    for name, handler in {
        "init": _cmd_identity_init,
        "show": _cmd_identity_show,
        "export": _cmd_identity_export,
        "import": _cmd_identity_import,
        "rotate": _cmd_identity_rotate,
    }.items():
        subparser = identity_subparsers.add_parser(name)
        subparser.add_argument("--registry", required=True)
        subparser.add_argument("--identity-file")
        subparser.add_argument("--identity-password")
        if name == "export":
            subparser.add_argument("--export-password", required=True)
            subparser.add_argument("--out", required=True)
        if name == "import":
            subparser.add_argument("--source", required=True)
            subparser.add_argument("--import-password", required=True)
        subparser.set_defaults(handler=handler)

    sign = subparsers.add_parser("sign")
    sign.add_argument("input")
    sign.add_argument("--registry", required=True)
    sign.add_argument("--registry-root-fingerprint", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--nonce-out", required=True)
    sign.add_argument("--policy", default="no-ai-training")
    sign.add_argument("--carrier", default="visible")
    sign.add_argument("--canonicalization", default="pact.text.v1")
    sign.add_argument("--mime-type")
    sign.add_argument("--identity-file")
    sign.add_argument("--identity-password")
    sign.set_defaults(handler=_cmd_sign)

    verify = subparsers.add_parser("verify")
    verify.add_argument("manifest")
    verify.add_argument("--public-jwk", required=True)
    verify.add_argument("--content")
    verify.add_argument("--nonce")
    verify.set_defaults(handler=_cmd_verify)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("input")
    inspect.add_argument("--mime-type")
    inspect.set_defaults(handler=_cmd_inspect)

    registry = subparsers.add_parser("registry")
    registry_subparsers = registry.add_subparsers(dest="registry_command", required=True)
    registry_init = registry_subparsers.add_parser("init")
    registry_init.add_argument("--registry", required=True)
    registry_init.add_argument("--data-dir", required=True)
    registry_init.add_argument("--root-key-password", required=True)
    registry_init.set_defaults(handler=_cmd_registry_init)
    serve = registry_subparsers.add_parser("serve")
    serve.add_argument("--registry", required=True)
    serve.add_argument("--data-dir", required=True)
    serve.add_argument("--public-base-url", required=True)
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--admin-jwk-file", action="append", default=[])
    serve.set_defaults(handler=_cmd_registry_serve)

    web = subparsers.add_parser("web")
    web.add_argument("--registry", default="http://127.0.0.1:8000")
    web.add_argument("--data-dir", required=True)
    web.add_argument("--port", type=int, default=8000)
    web.add_argument("--admin-jwk-file", action="append", default=[])
    web.set_defaults(handler=_cmd_web)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return cast(int, args.handler(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
