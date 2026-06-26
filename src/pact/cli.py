"""Command-line entry point for signing, inspection, and registry hosting."""

import argparse
import json
import mimetypes
import os
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import UUID

import uvicorn

from pact.canonical import CanonicalizationProfile
from pact.carriers.c2pa import C2paError, read_c2pa_asset
from pact.detection import (
    ProbeEvidencePackage,
    ProbeSet,
    analyze_probe_responses,
    create_probe_set,
    responses_from_jsonl,
)
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
from pact.privacy import audit_signed_manifest_publication
from pact.registry import (
    RegistryCertificateAuthority,
    RegistryService,
    SqliteRegistryStore,
)
from pact.registry.store import FileRegistryStore
from pact.watermarks import (
    CanaryPhrasePlugin,
    InvisibleFramePlugin,
    LexicalSubstitutionPlugin,
    SemanticParaphrasePlugin,
    StatisticalSentencePatternPlugin,
    SyntacticVariationPlugin,
    TextWatermarkParameters,
    apply_text_watermark_plugins,
    decode_image_soft_binding,
    embed_image_soft_binding,
)
from pact.web import create_app

if TYPE_CHECKING:
    from pact.watermarks.base import TextWatermarkPlugin


def _identity_store(
    args: argparse.Namespace,
) -> KeyringIdentityStore | EncryptedFileIdentityStore:
    identity_file = cast(str | None, getattr(args, "identity_file", None))
    if identity_file is None:
        return KeyringIdentityStore()
    return EncryptedFileIdentityStore(Path(identity_file).expanduser())


def _require_password(args: argparse.Namespace, field: str) -> str:
    value = cast(str | None, getattr(args, field, None))
    if not value:
        raise SystemExit(
            f"{field.replace('_', '-')} is required for file-backed identities"
        )
    return value


def _load_identity(args: argparse.Namespace) -> ClaimantIdentity:
    store = _identity_store(args)
    registry_url = normalize_registry_url(cast(str, args.registry))
    if isinstance(store, KeyringIdentityStore):
        return store.load(registry_url)
    return store.load(
        registry_url, _require_password(args, "identity_password")
    )


def _save_identity(
    args: argparse.Namespace, identity: ClaimantIdentity
) -> None:
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
            PolicyEntry(
                Permission.GENERATIVE_TRAINING, PermissionValue.NOT_ALLOWED
            ),
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
        intermediate_certificate_pem=paths[
            "intermediate_certificate"
        ].read_bytes(),
        intermediate_private_key_pem=paths[
            "intermediate_private_key"
        ].read_bytes(),
    )


def _write_authority(
    data_dir: Path, authority: RegistryCertificateAuthority
) -> None:
    paths = _authority_paths(data_dir)
    paths["root_certificate"].parent.mkdir(parents=True, exist_ok=True)
    paths["root_certificate"].write_bytes(authority.root_certificate_pem)
    if authority.root_private_key_pem is not None:
        paths["root_private_key"].write_bytes(authority.root_private_key_pem)
        os.chmod(paths["root_private_key"], 0o600)
    paths["intermediate_certificate"].write_bytes(
        authority.intermediate_certificate_pem
    )
    paths["intermediate_private_key"].write_bytes(
        authority.intermediate_private_key_pem
    )
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
    store_backend: str = "file",
    sqlite_database: str = ":memory:",
) -> RegistryService:
    authority = _load_authority(data_dir, registry_url).online_material()
    if store_backend == "file":
        store = FileRegistryStore(data_dir / "store")
    elif store_backend == "sqlite":
        store = SqliteRegistryStore(sqlite_database)
    else:
        raise SystemExit("store backend must be file or sqlite")
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
    print(
        _serialize_json(
            {"registry_url": identity.registry_url, "key_id": identity.key_id}
        )
    )
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
    print(
        _serialize_json(
            {"registry_url": identity.registry_url, "key_id": identity.key_id}
        )
    )
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
    mime_type = cast(str | None, args.mime_type) or _infer_mime_type(
        input_path
    )
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
                "ca_directory": str(
                    (_authority_paths(data_dir)["root_certificate"]).parent
                ),
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
    mime_type = args.mime_type or _infer_mime_type(target)
    if mime_type.startswith("image/"):
        try:
            decoded = decode_image_soft_binding(payload, mime_type)
        except Exception:
            pass
        else:
            print(_serialize_json(decoded.to_dict()))
            return 0
    try:
        result = read_c2pa_asset(payload, mime_type=mime_type)
    except C2paError as error:
        raise SystemExit(str(error)) from error
    print(_serialize_json(result.manifest_store_json))
    return 0


def _cmd_watermark_image(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    mime_type = cast(str | None, args.mime_type) or _infer_mime_type(
        input_path
    )
    result = embed_image_soft_binding(
        input_path.read_bytes(),
        mime_type,
        claim_id=UUID(cast(str, args.claim_id)),
        registry_root_fingerprint=cast(str, args.registry_root_fingerprint),
        strength=cast(float, args.strength),
    )
    Path(args.output).write_bytes(result.image_bytes)
    print(_serialize_json(result.to_dict()))
    return 0


def _text_watermark_plugins(methods: str) -> tuple["TextWatermarkPlugin", ...]:
    available = {
        "invisible": InvisibleFramePlugin,
        "lexical": LexicalSubstitutionPlugin,
        "syntactic": SyntacticVariationPlugin,
        "semantic": SemanticParaphrasePlugin,
        "canary": CanaryPhrasePlugin,
        "statistical": StatisticalSentencePatternPlugin,
    }
    plugins = []
    for name in [item.strip() for item in methods.split(",") if item.strip()]:
        plugin = available.get(name)
        if plugin is None:
            raise SystemExit(f"unknown text watermark method: {name}")
        plugins.append(plugin())
    if not plugins:
        raise SystemExit("at least one text watermark method is required")
    return tuple(plugins)


def _cmd_watermark_text(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    content = input_path.read_text(encoding="utf-8")
    parameters = TextWatermarkParameters(
        user_confirmation=bool(args.confirm),
        allow_semantic_methods=bool(args.allow_semantic),
        approved_canary_phrase=cast(str | None, args.canary_phrase),
        max_changes=args.max_changes,
        selection_stride=args.selection_stride,
    )
    pipeline = apply_text_watermark_plugins(
        content,
        cast(str, args.secret),
        _text_watermark_plugins(args.methods),
        parameters,
    )
    Path(args.output).write_text(
        pipeline.transformed_content, encoding="utf-8"
    )
    print(_serialize_json(pipeline.to_dict()))
    return 0


def _cmd_probe_create(args: argparse.Namespace) -> int:
    protected_texts = tuple(
        Path(path).read_text(encoding="utf-8")
        for path in cast(list[str], args.protected)
    )
    control_texts = tuple(
        Path(path).read_text(encoding="utf-8")
        for path in cast(list[str], args.control)
    )
    probe_set = create_probe_set(
        protected_texts=protected_texts,
        control_texts=control_texts,
        target_model=cast(str, args.target_model),
        claim_id=cast(str | None, args.claim_id),
        prefix_chars=cast(int, args.prefix_chars),
        withheld_chars=cast(int, args.withheld_chars),
    )
    Path(args.output).write_text(
        _serialize_json(probe_set.to_dict()), encoding="utf-8"
    )
    print(
        _serialize_json(
            {
                "commitment": probe_set.commitment,
                "probe_count": len(probe_set.probes),
                "output": args.output,
            }
        )
    )
    return 0


def _cmd_probe_analyze(args: argparse.Namespace) -> int:
    probe_set_data = json.loads(
        Path(args.probe_set).read_text(encoding="utf-8")
    )
    if not isinstance(probe_set_data, dict):
        raise SystemExit("probe set must be a JSON object")
    probe_set = ProbeSet.from_dict(cast(dict[str, object], probe_set_data))
    responses = responses_from_jsonl(
        Path(args.responses).read_text(encoding="utf-8")
    )
    analysis = analyze_probe_responses(
        probe_set,
        responses,
        false_positive_threshold=cast(float, args.false_positive_threshold),
    )
    package = ProbeEvidencePackage.create(
        probe_set=probe_set,
        responses=responses,
        analysis=analysis,
    )
    Path(args.output).write_text(
        _serialize_json(package.to_dict()), encoding="utf-8"
    )
    print(
        _serialize_json(
            {
                "conclusion": analysis.conclusion.value,
                "treatment_matches": analysis.treatment_matches,
                "control_matches": analysis.control_matches,
                "package_digest": package.package_digest,
                "output": args.output,
            }
        )
    )
    return 0


def _cmd_probe_export(args: argparse.Namespace) -> int:
    package_data = json.loads(Path(args.package).read_text(encoding="utf-8"))
    if not isinstance(package_data, dict):
        raise SystemExit("probe evidence package must be a JSON object")
    package = ProbeEvidencePackage.from_dict(
        cast(dict[str, object], package_data)
    )
    signed_package = (
        package.with_signature(_load_identity(args))
        if args.identity_file
        else package
    )
    Path(args.output).write_text(
        _serialize_json(signed_package.to_dict()),
        encoding="utf-8",
    )
    print(
        _serialize_json(
            {
                "package_digest": signed_package.package_digest,
                "signed": signed_package.signature is not None,
                "output": args.output,
            }
        )
    )
    return 0


def _cmd_privacy_audit(args: argparse.Namespace) -> int:
    signed = SignedManifest.from_json(Path(args.manifest).read_bytes())
    content = Path(args.content).read_bytes() if args.content else None
    nonce = Path(args.nonce).read_bytes() if args.nonce else None
    private_values = tuple(
        Path(path).read_bytes() for path in cast(list[str], args.private_value)
    )
    report = audit_signed_manifest_publication(
        signed,
        content=content,
        nonce=nonce,
        private_values=private_values,
    )
    print(_serialize_json(report.to_dict()))
    return 0 if report.passed else 1


def _serve(
    *,
    data_dir: Path,
    registry_url: str,
    host: str,
    port: int,
    public_base_url: str,
    local_mode: bool,
    admin_jwk_files: list[str],
    store_backend: str,
    sqlite_database: str,
) -> int:
    service = _bootstrap_service(
        data_dir,
        registry_url,
        admin_jwk_files=admin_jwk_files,
        store_backend=store_backend,
        sqlite_database=sqlite_database,
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
        store_backend=args.store_backend,
        sqlite_database=args.sqlite_database,
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
        store_backend=args.store_backend,
        sqlite_database=args.sqlite_database,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pact")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity_subparsers = identity.add_subparsers(
        dest="identity_command", required=True
    )
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

    watermark = subparsers.add_parser("watermark")
    watermark_subparsers = watermark.add_subparsers(
        dest="watermark_command",
        required=True,
    )
    watermark_image = watermark_subparsers.add_parser("image")
    watermark_image.add_argument("input")
    watermark_image.add_argument("--claim-id", required=True)
    watermark_image.add_argument("--registry-root-fingerprint", required=True)
    watermark_image.add_argument("--output", required=True)
    watermark_image.add_argument("--strength", type=float, default=1.0)
    watermark_image.add_argument("--mime-type")
    watermark_image.set_defaults(handler=_cmd_watermark_image)
    watermark_text = watermark_subparsers.add_parser("text")
    watermark_text.add_argument("input")
    watermark_text.add_argument("--methods", required=True)
    watermark_text.add_argument("--secret", required=True)
    watermark_text.add_argument("--output", required=True)
    watermark_text.add_argument("--confirm", action="store_true")
    watermark_text.add_argument("--allow-semantic", action="store_true")
    watermark_text.add_argument("--canary-phrase")
    watermark_text.add_argument("--max-changes", type=int, default=8)
    watermark_text.add_argument("--selection-stride", type=int, default=3)
    watermark_text.set_defaults(handler=_cmd_watermark_text)

    probe = subparsers.add_parser("probe")
    probe_subparsers = probe.add_subparsers(
        dest="probe_command", required=True
    )
    probe_create = probe_subparsers.add_parser("create")
    probe_create.add_argument("--protected", action="append", required=True)
    probe_create.add_argument("--control", action="append", required=True)
    probe_create.add_argument("--target-model", required=True)
    probe_create.add_argument("--output", required=True)
    probe_create.add_argument("--claim-id")
    probe_create.add_argument("--prefix-chars", type=int, default=160)
    probe_create.add_argument("--withheld-chars", type=int, default=220)
    probe_create.set_defaults(handler=_cmd_probe_create)
    probe_analyze = probe_subparsers.add_parser("analyze")
    probe_analyze.add_argument("probe_set")
    probe_analyze.add_argument("--responses", required=True)
    probe_analyze.add_argument("--output", required=True)
    probe_analyze.add_argument(
        "--false-positive-threshold", type=float, default=0.05
    )
    probe_analyze.set_defaults(handler=_cmd_probe_analyze)
    probe_export = probe_subparsers.add_parser("export")
    probe_export.add_argument("package")
    probe_export.add_argument("--output", required=True)
    probe_export.add_argument("--identity-file")
    probe_export.add_argument("--identity-password")
    probe_export.add_argument("--registry", default="https://registry.example")
    probe_export.set_defaults(handler=_cmd_probe_export)

    privacy = subparsers.add_parser("privacy")
    privacy_subparsers = privacy.add_subparsers(
        dest="privacy_command", required=True
    )
    privacy_audit = privacy_subparsers.add_parser("audit")
    privacy_audit.add_argument("manifest")
    privacy_audit.add_argument("--content")
    privacy_audit.add_argument("--nonce")
    privacy_audit.add_argument("--private-value", action="append", default=[])
    privacy_audit.set_defaults(handler=_cmd_privacy_audit)

    registry = subparsers.add_parser("registry")
    registry_subparsers = registry.add_subparsers(
        dest="registry_command", required=True
    )
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
    serve.add_argument(
        "--store-backend", choices=("file", "sqlite"), default="file"
    )
    serve.add_argument("--sqlite-database", default=":memory:")
    serve.set_defaults(handler=_cmd_registry_serve)

    web = subparsers.add_parser("web")
    web.add_argument("--registry", default="http://127.0.0.1:8000")
    web.add_argument("--data-dir", required=True)
    web.add_argument("--port", type=int, default=8000)
    web.add_argument("--admin-jwk-file", action="append", default=[])
    web.add_argument(
        "--store-backend", choices=("file", "sqlite"), default="sqlite"
    )
    web.add_argument("--sqlite-database", default=":memory:")
    web.set_defaults(handler=_cmd_web)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return cast(int, args.handler(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
