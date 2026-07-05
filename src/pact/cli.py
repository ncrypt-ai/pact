"""Command-line entry point for signing, inspection, and registry hosting."""

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import secrets
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import UUID

from pact.canonical import CanonicalizationProfile, JsonValue, canonical_json
from pact.carriers import CarrierMode, embed_text_carrier
from pact.crypto import base64url_encode, sign_es256
from pact.detection.evidence import ProbeEvidencePackage
from pact.detection.probes import (
    ProbeSet,
    create_probe_set,
    responses_from_jsonl,
)
from pact.detection.statistics import analyze_probe_responses
from pact.identity import (
    ClaimantIdentity,
    DeviceBindingError,
    EncryptedFileIdentityStore,
    IdentityError,
    IdentityNotFoundError,
    IdentityStorageError,
    KeyringIdentityStore,
    LocalDeviceBindingStore,
    normalize_registry_url,
)
from pact.inspection import inspect_content
from pact.manifest import (
    Manifest,
    SignedManifest,
    sign_manifest,
    verify_manifest,
)
from pact.media import infer_mime_type
from pact.oprf import OprfError, device_binding_oprf_token
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry
from pact.privacy import audit_signed_manifest_publication
from pact.registry.app import (
    AvoidanceReportLabel,
    ChallengePurpose,
    MutationChallenge,
    MutationRequest,
    RegistryCertificateAuthority,
    RegistryService,
    domain_verification_txt_name,
    domain_verification_txt_value,
)
from pact.registry.store import SqliteRegistryStore
from pact.server.logging import LogFormat, LoggingConfig, configure_logging
from pact.watermarks import (
    CanaryPhrasePlugin,
    InvisibleFramePlugin,
    LexicalSubstitutionPlugin,
    SemanticParaphrasePlugin,
    StatisticalSentencePatternPlugin,
    SyntacticVariationPlugin,
    TextWatermarkParameters,
    apply_text_watermark_plugins,
    embed_image_soft_binding,
)

if TYPE_CHECKING:
    from pact.watermarks.base import TextWatermarkPlugin


DEFAULT_LOCAL_DATA_DIR = "/tmp/pact-local-registry"
DEFAULT_LOCAL_REGISTRY_URL = "http://127.0.0.1:8000"
DEFAULT_LOCAL_DATABASE = ":memory:"


class HelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawDescriptionHelpFormatter,
):
    """Argparse formatter that keeps examples readable and shows defaults."""


def _prompt_text(label: str, default: str | None = None) -> str:
    prompt = f"{label}"
    if default is not None:
        prompt += f" [{default}]"
    prompt += ": "
    value = input(prompt).strip()
    if value:
        return value
    if default is not None:
        return default
    raise SystemExit(f"{label} is required")


def _prompt_secret(label: str) -> str:
    value = getpass.getpass(f"{label}: ")
    if not value:
        raise SystemExit(f"{label} is required")
    return value


def _resolve_value(
    value: str | None,
    *,
    env_name: str,
    label: str,
    default: str | None = None,
) -> str:
    if value:
        return value
    env_value = os.getenv(env_name)
    if env_value:
        return env_value
    return _prompt_text(label, default)


def _resolve_secret(
    value: str | None,
    *,
    env_name: str,
    label: str,
) -> str:
    if value:
        return value
    env_value = os.getenv(env_name)
    if env_value:
        return env_value
    return _prompt_secret(label)


def _default_manifest_path(input_path: Path) -> Path:
    return input_path.with_suffix(".manifest.json")


def _default_carrier_path(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.stem}.pact{input_path.suffix}")


def _default_nonce_path(input_path: Path) -> Path:
    return input_path.with_suffix(".nonce")


def _resolve_prompted_arg(
    args: argparse.Namespace,
    name: str,
    *,
    label: str,
    default: str | None = None,
) -> str:
    return _resolve_value(
        cast(str | None, getattr(args, name, None)),
        env_name=f"PACT_{name.upper()}",
        label=label,
        default=default,
    )


def _resolve_prompted_list(
    args: argparse.Namespace,
    name: str,
    *,
    label: str,
) -> list[str]:
    values = cast(list[str] | None, getattr(args, name, None))
    if values:
        return values
    return [_prompt_text(label)]


def _resolve_registry_url(args: argparse.Namespace) -> str:
    return normalize_registry_url(
        _resolve_value(
            cast(str | None, getattr(args, "registry", None)),
            env_name="PACT_REGISTRY_URL",
            label="Registry URL",
            default=DEFAULT_LOCAL_REGISTRY_URL,
        )
    )


def _resolve_data_dir(args: argparse.Namespace) -> Path:
    return Path(
        _resolve_value(
            cast(str | None, getattr(args, "data_dir", None)),
            env_name="PACT_DATA_DIR",
            label="Registry data directory",
            default=DEFAULT_LOCAL_DATA_DIR,
        )
    ).expanduser()


def _resolve_database(args: argparse.Namespace) -> str:
    value = cast(str | None, getattr(args, "database", None))
    database = value or os.getenv("PACT_DATABASE") or DEFAULT_LOCAL_DATABASE
    return ":memory:" if database == ":memory" else database


def _request_json(
    registry_url: str,
    path: str,
    *,
    payload: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    url = f"{registry_url}{path}"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    request = Request(
        url,
        data=data,
        headers=request_headers,
        method="GET" if payload is None else "POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            parsed = json.loads(response.read())
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"{url} returned HTTP {error.code}: {detail}"
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        raise SystemExit(
            f"could not reach registry at {url}: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise SystemExit(f"{url} did not return valid JSON") from error
    if not isinstance(parsed, dict):
        raise SystemExit(f"{url} must return a JSON object")
    return cast(dict[str, object], parsed)


def _request_file(
    registry_url: str,
    path: str,
    *,
    file_path: Path,
    mime_type: str,
) -> dict[str, object]:
    url = f"{registry_url}{path}"
    boundary = f"pact-{secrets.token_hex(16)}"
    payload = bytearray()
    payload.extend(f"--{boundary}\r\n".encode("ascii"))
    payload.extend(
        (
            'Content-Disposition: form-data; name="mime_type"\r\n\r\n'
            f"{mime_type}\r\n"
        ).encode()
    )
    payload.extend(f"--{boundary}\r\n".encode("ascii"))
    payload.extend(
        (
            'Content-Disposition: form-data; name="file"; '
            f'filename="{file_path.name}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode()
    )
    payload.extend(file_path.read_bytes())
    payload.extend(f"\r\n--{boundary}--\r\n".encode("ascii"))
    request = Request(
        url,
        data=bytes(payload),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            parsed = json.loads(response.read())
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"{url} returned HTTP {error.code}: {detail}"
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        raise SystemExit(
            f"could not reach registry at {url}: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise SystemExit(f"{url} did not return valid JSON") from error
    if not isinstance(parsed, dict):
        raise SystemExit(f"{url} must return a JSON object")
    return cast(dict[str, object], parsed)


def _registry_info(registry_url: str) -> dict[str, object]:
    return _request_json(registry_url, "/pact/api/v1/registry")


def _registry_root_fingerprint(args: argparse.Namespace) -> str:
    explicit = cast(
        str | None, getattr(args, "registry_root_fingerprint", None)
    )
    if explicit:
        return explicit
    registry_url = _resolve_registry_url(args)
    try:
        value = _registry_info(registry_url).get("root_fingerprint")
    except SystemExit:
        return _prompt_text(
            "Registry root fingerprint",
            None,
        )
    if not isinstance(value, str):
        raise SystemExit(
            f"{registry_url}/pact/api/v1/registry did not include root_fingerprint"
        )
    return value


def _profile_public_jwk(
    registry_url: str,
    key_id: str,
) -> dict[str, object]:
    profile = _request_json(registry_url, f"/pact/api/v1/profiles/{key_id}")
    public_jwk = profile.get("public_jwk")
    if not isinstance(public_jwk, dict):
        raise SystemExit("registry profile did not include public_jwk")
    return cast(dict[str, object], public_jwk)


def _challenge_from_response(value: dict[str, object]) -> MutationChallenge:
    try:
        return MutationChallenge(
            registry_url=cast(str, value["registry_url"]),
            challenge_id=UUID(cast(str, value["challenge_id"])),
            purpose=ChallengePurpose(cast(str, value["purpose"])),
            issued_at=datetime.fromisoformat(cast(str, value["issued_at"])),
            expires_at=datetime.fromisoformat(cast(str, value["expires_at"])),
            challenge_nonce=cast(str, value["challenge_nonce"]),
            difficulty=cast(int, value["difficulty"]),
            bound_key_id=cast(str | None, value.get("bound_key_id")),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("registry returned an invalid challenge") from error


def _solve_pow(challenge: MutationChallenge) -> int:
    solution = 0
    while not challenge.verify_solution(solution):
        solution += 1
    return solution


def _signed_mutation_body(
    identity: ClaimantIdentity,
    challenge: MutationChallenge,
    payload: dict[str, object],
) -> dict[str, object]:
    request = MutationRequest.create(
        identity,
        challenge,
        payload=payload,
        proof_of_work_solution=_solve_pow(challenge),
    )
    return {
        "challenge_id": str(request.challenge_id),
        "claimant_public_jwk": request.claimant_public_jwk,
        "proof_of_work_solution": request.proof_of_work_solution,
        "payload": request.payload,
        "signature": request.signature,
    }


def _profile_auth_headers(
    registry_url: str,
    identity: ClaimantIdentity,
    *,
    method: str,
    path: str,
    body: dict[str, object],
) -> dict[str, str]:
    challenge = _challenge_from_response(
        _request_json(
            registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.ACCOUNT_AUTHORIZATION.value,
                "bound_key_id": identity.key_id,
            },
        )
    )
    solution = _solve_pow(challenge)
    body_digest = hashlib.sha256(
        canonical_json(cast(JsonValue, body))
    ).hexdigest()
    signed = canonical_json(
        cast(
            JsonValue,
            {
                "challenge": challenge.to_dict(),
                "profile_key_id": identity.key_id,
                "method": method,
                "path": path,
                "body_sha256": body_digest,
            },
        )
    )
    return {
        "X-PACT-Profile-Key-Id": identity.key_id,
        "X-PACT-Challenge-Id": str(challenge.challenge_id),
        "X-PACT-Proof-Of-Work-Solution": str(solution),
        "X-PACT-Signature": sign_es256(identity.private_key, signed),
    }


def _identity_store(
    args: argparse.Namespace,
) -> KeyringIdentityStore | EncryptedFileIdentityStore:
    identity_file = cast(str | None, getattr(args, "identity_file", None))
    if identity_file is None:
        return KeyringIdentityStore()
    return EncryptedFileIdentityStore(Path(identity_file).expanduser())


def _device_binding_store() -> LocalDeviceBindingStore:
    return LocalDeviceBindingStore()


def _registry_device_binding_token(
    registry_url: str,
    binding_store: LocalDeviceBindingStore,
) -> str:
    info = _registry_info(registry_url)
    root_fingerprint = info.get("root_fingerprint")
    if not isinstance(root_fingerprint, str):
        raise SystemExit(
            f"{registry_url}/pact/api/v1/registry did not include root_fingerprint"
        )
    local_input = binding_store.private_binding_input(
        registry_url,
        root_fingerprint,
    )
    try:
        return device_binding_oprf_token(
            local_input=local_input,
            evaluator=lambda point: _request_json(
                registry_url,
                "/pact/api/v1/device-bindings/oprf",
                payload=dict(point),
            ),
        )
    except OprfError as error:
        raise SystemExit(
            f"registry device binding OPRF failed: {error}"
        ) from error


def _device_binding_error(error: DeviceBindingError) -> SystemExit:
    return SystemExit(str(error))


def _require_password(args: argparse.Namespace, field: str) -> str:
    if field == "identity_password":
        return _resolve_secret(
            cast(str | None, getattr(args, field, None)),
            env_name="PACT_IDENTITY_PASSWORD",
            label="Identity password",
        )
    return _resolve_secret(
        cast(str | None, getattr(args, field, None)),
        env_name=field.upper(),
        label=field.replace("_", " ").title(),
    )


def _load_identity(args: argparse.Namespace) -> ClaimantIdentity:
    store = _identity_store(args)
    registry_url = _resolve_registry_url(args)
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
            PolicyEntry(
                Permission.NO_COMMERCIAL_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
        )
    )


def _infer_mime_type(path: Path) -> str:
    try:
        return infer_mime_type(path.name)
    except ValueError as error:
        raise SystemExit(str(error)) from error


def _authority_paths(data_dir: Path) -> dict[str, Path]:
    ca_dir = data_dir / "ca"
    return {
        "root_certificate": ca_dir / "root_certificate.pem",
        "root_private_key": ca_dir / "offline_root_private_key.pem",
        "intermediate_certificate": ca_dir / "intermediate_certificate.pem",
        "intermediate_private_key": ca_dir / "intermediate_private_key.pem",
        "oprf_server_secret": ca_dir / "oprf_server_secret",
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
    if not paths["oprf_server_secret"].exists():
        paths["oprf_server_secret"].write_text(
            base64url_encode(secrets.token_bytes(32)),
            encoding="ascii",
        )
        os.chmod(paths["oprf_server_secret"], 0o600)


def _load_oprf_server_secret(
    data_dir: Path,
    override: str | None = None,
) -> bytes:
    value = override or os.getenv("PACT_OPRF_SERVER_SECRET")
    if value:
        return value.encode("utf-8")
    path = _authority_paths(data_dir)["oprf_server_secret"]
    if not path.exists():
        path.write_text(
            base64url_encode(secrets.token_bytes(32)),
            encoding="ascii",
        )
        os.chmod(path, 0o600)
    return path.read_text(encoding="ascii").strip().encode("utf-8")


def _load_admin_jwks(paths: list[str]) -> tuple[dict[str, str], ...]:
    result: list[dict[str, str]] = []
    for path in paths:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise SystemExit(f"admin JWK file {path} must contain an object")
        result.append(cast(dict[str, str], parsed))
    return tuple(result)


def _sqlite_database_paths(database: str) -> tuple[Path, ...]:
    if database in {":memory", ":memory:"}:
        return ()
    path = Path(database).expanduser()
    return (path, Path(f"{path}-wal"), Path(f"{path}-shm"))


def _existing_registry_teardown_targets(
    *,
    data_dir: Path,
    database: str,
    registry_url: str,
    binding_store: LocalDeviceBindingStore,
) -> dict[str, list[str]]:
    authority_paths = _authority_paths(data_dir)
    ca_files = [
        str(path) for path in authority_paths.values() if path.exists()
    ]
    database_files = [
        str(path) for path in _sqlite_database_paths(database) if path.exists()
    ]
    device_binding_files: list[str] = []
    if binding_store.load(registry_url) is not None:
        device_binding_files.append(str(binding_store.path(registry_url)))
    keyring_identities: list[str] = []
    keyring_store = KeyringIdentityStore()
    if keyring_store.exists(registry_url):
        keyring_identities.append(keyring_store.target(registry_url))
    return {
        "ca_files": ca_files,
        "database_files": database_files,
        "device_binding_files": device_binding_files,
        "keyring_identities": keyring_identities,
    }


def _browser_cleanup_url(registry_url: str) -> str:
    return (
        f"{registry_url}/pact/web?"
        f"teardown_registry={quote(registry_url, safe='')}"
    )


def _confirm_registry_teardown(
    args: argparse.Namespace,
    *,
    registry_url: str,
    database: str,
    data_dir: Path,
    targets: dict[str, list[str]],
) -> None:
    print(
        _serialize_json(
            {
                "registry_url": registry_url,
                "data_dir": str(data_dir),
                "database": database,
                "browser_cleanup_url": _browser_cleanup_url(registry_url),
                "will_delete": targets,
            }
        ),
        file=sys.stderr,
    )
    expected_phrase = f"delete registry {registry_url}"
    confirmed_registry = cast(str | None, args.confirm_registry)
    if confirmed_registry is None:
        confirmed_registry = _prompt_text(
            "Type the registry URL to confirm teardown"
        )
    try:
        normalized_confirmed_registry = normalize_registry_url(
            confirmed_registry
        )
    except IdentityError as error:
        raise SystemExit(str(error)) from error
    if normalized_confirmed_registry != registry_url:
        raise SystemExit("registry teardown confirmation did not match")

    confirmed_phrase = cast(str | None, args.confirm_delete)
    if confirmed_phrase is None:
        confirmed_phrase = _prompt_text(
            f'Type "{expected_phrase}" to delete persistent registry state'
        )
    if confirmed_phrase != expected_phrase:
        raise SystemExit("registry teardown delete confirmation did not match")


def _cmd_registry_teardown(args: argparse.Namespace) -> int:
    registry_url = _resolve_registry_url(args)
    data_dir = _resolve_data_dir(args)
    database = _resolve_database(args)
    binding_store = _device_binding_store()
    try:
        targets = _existing_registry_teardown_targets(
            data_dir=data_dir,
            database=database,
            registry_url=registry_url,
            binding_store=binding_store,
        )
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    except IdentityStorageError as error:
        raise SystemExit(str(error)) from error
    _confirm_registry_teardown(
        args,
        registry_url=registry_url,
        database=database,
        data_dir=data_dir,
        targets=targets,
    )

    removed: dict[str, list[str]] = {
        "ca_files": [],
        "database_files": [],
        "device_binding_files": [],
        "keyring_identities": [],
    }
    for path in _authority_paths(data_dir).values():
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        removed["ca_files"].append(str(path))
    ca_dir = data_dir / "ca"
    try:
        ca_dir.rmdir()
    except OSError:
        pass

    for path in _sqlite_database_paths(database):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        removed["database_files"].append(str(path))

    try:
        binding_path = binding_store.path(registry_url)
        if binding_store.delete(registry_url):
            removed["device_binding_files"].append(str(binding_path))
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error

    try:
        keyring_store = KeyringIdentityStore()
        keyring_target = keyring_store.target(registry_url)
        if keyring_store.delete(registry_url):
            removed["keyring_identities"].append(keyring_target)
    except IdentityStorageError as error:
        raise SystemExit(str(error)) from error

    print(
        _serialize_json(
            {
                "registry_url": registry_url,
                "browser_cleanup_url": _browser_cleanup_url(registry_url),
                "removed": removed,
            }
        )
    )
    return 0


def _bootstrap_service(
    data_dir: Path,
    registry_url: str,
    *,
    admin_jwk_files: list[str] | None = None,
    database: str = DEFAULT_LOCAL_DATABASE,
    oprf_server_secret: str | None = None,
) -> RegistryService:
    authority = _load_authority(data_dir, registry_url).online_material()
    store = SqliteRegistryStore(database)
    admin_public_jwks = _load_admin_jwks(admin_jwk_files or [])
    return RegistryService(
        registry_url,
        store=store,
        certificate_authority=authority,
        admin_public_jwks=admin_public_jwks,
        oprf_server_secret=_load_oprf_server_secret(
            data_dir,
            oprf_server_secret,
        ),
    )


def _cmd_identity_init(args: argparse.Namespace) -> int:
    registry_url = _resolve_registry_url(args)
    binding_store = _device_binding_store()
    try:
        binding_store.ensure_can_create_identity(registry_url)
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    try:
        _load_identity(args)
    except IdentityNotFoundError:
        pass
    else:
        raise SystemExit(
            "an identity already exists for this registry; rotate it instead"
        )
    identity = ClaimantIdentity.generate(registry_url)
    _save_identity(args, identity)
    try:
        binding = binding_store.bind_new_identity(identity)
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    print(
        _serialize_json(
            {
                "registry_url": identity.registry_url,
                "key_id": identity.key_id,
                "device_fingerprint": binding.device_fingerprint,
            }
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


def _cmd_identity_public_jwk(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    output_path = cast(str | None, getattr(args, "out", None))
    payload = _serialize_json(identity.public_jwk)
    if output_path:
        Path(output_path).write_text(payload + "\n", encoding="utf-8")
        print(_serialize_json({"output": output_path}))
    else:
        print(payload)
    return 0


def _cmd_identity_export(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    export_password = _resolve_secret(
        cast(str | None, args.export_password),
        env_name="PACT_EXPORT_PASSWORD",
        label="Export password",
    )
    output_path = Path(
        _resolve_prompted_arg(
            args,
            "out",
            label="Export output path",
            default="pact-profile-recovery.json"
            if args.recovery_json
            else "pact-identity.pkcs8.pem",
        )
    )
    exported = identity.export_pkcs8(export_password)
    if args.recovery_json:
        binding_store = _device_binding_store()
        try:
            binding = binding_store.bind_imported_identity(identity)
        except DeviceBindingError as error:
            raise _device_binding_error(error) from error
        output_path.write_text(
            _serialize_json(
                {
                    "registry_url": identity.registry_url,
                    "key_id": identity.key_id,
                    "public_jwk": identity.public_jwk,
                    "encrypted_pkcs8_b64": base64.b64encode(exported).decode(
                        "ascii"
                    ),
                    "continuity_secret": binding.continuity_secret,
                }
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        output_path.write_bytes(exported)
    print(_serialize_json({"output": str(output_path)}))
    return 0


def _import_source_identity(
    args: argparse.Namespace,
    source: Path,
    import_password: str,
) -> tuple[ClaimantIdentity, str | None]:
    raw = source.read_bytes()
    stripped = raw.lstrip()
    if not stripped.startswith(b"{"):
        return (
            ClaimantIdentity.import_pkcs8(
                _resolve_registry_url(args),
                raw,
                import_password,
            ),
            None,
        )
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("identity recovery JSON is invalid") from error
    if not isinstance(data, dict):
        raise SystemExit("identity recovery JSON must be an object")
    registry_value = cast(str | None, getattr(args, "registry", None))
    if registry_value:
        registry_source = registry_value
    else:
        imported_registry = data.get("registry_url")
        if not isinstance(imported_registry, str):
            raise SystemExit(
                "identity recovery JSON is missing registry_url; pass --registry"
            )
        registry_source = imported_registry
    registry_url = normalize_registry_url(registry_source)
    encrypted = data.get("encrypted_pkcs8_b64")
    if not isinstance(encrypted, str):
        raise SystemExit(
            "identity recovery JSON is missing encrypted_pkcs8_b64"
        )
    try:
        pkcs8 = base64.b64decode(encrypted.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as error:
        raise SystemExit("encrypted_pkcs8_b64 is not valid base64") from error
    continuity_secret = data.get("continuity_secret")
    if continuity_secret is not None and not isinstance(
        continuity_secret,
        str,
    ):
        raise SystemExit("continuity_secret must be a string")
    return (
        ClaimantIdentity.import_pkcs8(registry_url, pkcs8, import_password),
        continuity_secret,
    )


def _cmd_identity_import(args: argparse.Namespace) -> int:
    source = _resolve_prompted_arg(
        args,
        "source",
        label="Encrypted identity import path",
    )
    import_password = _resolve_secret(
        cast(str | None, args.import_password),
        env_name="PACT_IMPORT_PASSWORD",
        label="Import password",
    )
    identity, continuity_secret = _import_source_identity(
        args,
        Path(source),
        import_password,
    )
    binding_store = _device_binding_store()
    try:
        existing = binding_store.load(identity.registry_url)
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    if existing is not None and existing.key_id != identity.key_id:
        raise SystemExit(
            "this device is already bound to a different identity for this "
            "registry; rotate the existing identity instead"
        )
    _save_identity(args, identity)
    try:
        binding = binding_store.bind_imported_identity(
            identity,
            continuity_secret=continuity_secret,
        )
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    print(
        _serialize_json(
            {
                "registry_url": identity.registry_url,
                "key_id": identity.key_id,
                "device_fingerprint": binding.device_fingerprint,
            }
        )
    )
    return 0


def _cmd_identity_rotate(args: argparse.Namespace) -> int:
    current = _load_identity(args)
    binding_store = _device_binding_store()
    try:
        binding_store.ensure_can_rotate_identity(current)
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    replacement = current.rotate()
    _save_identity(args, replacement)
    try:
        binding = binding_store.rotate_identity(current, replacement)
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    print(
        _serialize_json(
            {
                "registry_url": replacement.registry_url,
                "previous_key_id": current.key_id,
                "replacement_key_id": replacement.key_id,
                "device_fingerprint": binding.device_fingerprint,
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
    output_path = Path(
        cast(str | None, args.output) or _default_manifest_path(input_path)
    )
    nonce_path = Path(
        cast(str | None, args.nonce_out) or _default_nonce_path(input_path)
    )
    disclose_nonce = not bool(args.private_nonce)
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=_registry_root_fingerprint(args),
        content=content,
        mime_type=mime_type,
        canonicalization=CanonicalizationProfile(args.canonicalization),
        policy=_default_policy(args.policy),
        carriers=(args.carrier,) if args.carrier else (),
        nonce=nonce,
        disclose_nonce=disclose_nonce,
    )
    signed = sign_manifest(manifest, identity)
    output_path.write_bytes(signed.to_json())
    carrier_output: str | None = None
    if (
        args.carrier in {CarrierMode.VISIBLE.value, CarrierMode.BOTH.value}
        and manifest.canonicalization is CanonicalizationProfile.TEXT_V1
    ):
        carrier_path = _default_carrier_path(input_path)
        carrier_mode = (
            CarrierMode.BOTH
            if args.carrier == CarrierMode.BOTH.value
            else CarrierMode.VISIBLE
        )
        carrier_path.write_bytes(
            embed_text_carrier(
                content,
                signed,
                nonce=nonce,
                mode=carrier_mode,
            )
        )
        carrier_output = str(carrier_path)
    if disclose_nonce:
        nonce_output: str | None = None
    else:
        nonce_path.write_bytes(nonce)
        nonce_output = str(nonce_path)
    print(
        _serialize_json(
            {
                "manifest": str(output_path),
                "carrier": carrier_output,
                "nonce": nonce_output,
                "nonce_disclosure": "public" if disclose_nonce else "private",
                "public_content_verifiable": disclose_nonce,
                "claim_id": str(signed.manifest.claim_id),
                "registry_url": signed.manifest.registry_url,
                "claimant_key_id": signed.manifest.claimant_key_id,
            }
        )
    )
    return 0


def _cmd_registry_init(args: argparse.Namespace) -> int:
    registry_url = _resolve_registry_url(args)
    data_dir = _resolve_data_dir(args)
    root_key_password = _resolve_secret(
        cast(str | None, args.root_key_password),
        env_name="PACT_ROOT_KEY_PASSWORD",
        label="Offline root key password",
    )
    authority = RegistryCertificateAuthority.initialize(
        registry_url,
        root_private_key_password=root_key_password,
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
    public_jwk_path = cast(str | None, args.public_jwk)
    if public_jwk_path:
        public_jwk = json.loads(
            Path(public_jwk_path).read_text(encoding="utf-8")
        )
        if not isinstance(public_jwk, dict):
            raise SystemExit("public JWK input must be a JSON object")
    else:
        public_jwk = _profile_public_jwk(
            signed.manifest.registry_url,
            signed.manifest.claimant_key_id,
        )
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


def _cmd_registry_register_profile(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    binding_store = _device_binding_store()
    try:
        binding_store.bind_imported_identity(identity)
    except DeviceBindingError as error:
        raise _device_binding_error(error) from error
    payload: dict[str, object] = {
        "device_fingerprint": _registry_device_binding_token(
            identity.registry_url,
            binding_store,
        ),
    }
    display_name = cast(str | None, args.display_name)
    if display_name:
        payload["display_name"] = display_name
    challenge = _challenge_from_response(
        _request_json(
            identity.registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.PROFILE_REGISTRATION.value,
                "difficulty": args.difficulty,
            },
        )
    )
    profile = _request_json(
        identity.registry_url,
        "/pact/api/v1/profiles",
        payload=_signed_mutation_body(identity, challenge, payload),
    )
    print(_serialize_json(profile))
    return 0


def _cmd_registry_register_claim(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    manifest_path = Path(args.manifest)
    signed = SignedManifest.from_json(manifest_path.read_bytes())
    if signed.manifest.registry_url != identity.registry_url:
        raise SystemExit(
            "manifest registry does not match the selected identity registry"
        )
    if signed.manifest.claimant_key_id != identity.key_id:
        raise SystemExit(
            "manifest claimant does not match the selected identity"
        )
    challenge = _challenge_from_response(
        _request_json(
            identity.registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.CLAIM_REGISTRATION.value,
                "difficulty": args.difficulty,
                "bound_key_id": identity.key_id,
            },
        )
    )
    claim = _request_json(
        identity.registry_url,
        "/pact/api/v1/claims",
        payload=_signed_mutation_body(
            identity,
            challenge,
            {
                "signed_manifest_json": manifest_path.read_text(
                    encoding="utf-8"
                )
            },
        ),
    )
    print(_serialize_json(claim))
    return 0


def _cmd_registry_verify_domain(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    domain = cast(str, args.domain).strip().rstrip(".").lower()
    txt_name = domain_verification_txt_name(domain)
    txt_value = domain_verification_txt_value(
        identity.registry_url,
        identity.key_id,
        domain,
    )
    record = {
        "domain": domain,
        "txt_name": txt_name,
        "txt_value": txt_value,
        "next_step": (
            "Publish this DNS TXT record, wait for it to resolve publicly, "
            "then rerun this command without --show-record-only."
        ),
    }
    if args.show_record_only:
        print(_serialize_json(record))
        return 0
    challenge = _challenge_from_response(
        _request_json(
            identity.registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.DOMAIN_VERIFICATION.value,
                "difficulty": args.difficulty,
                "bound_key_id": identity.key_id,
            },
        )
    )
    profile = _request_json(
        identity.registry_url,
        "/pact/api/v1/domains/verify",
        payload=_signed_mutation_body(
            identity,
            challenge,
            {
                "domain": domain,
                "txt_value": txt_value,
            },
        ),
    )
    print(_serialize_json({"dns_record": record, "profile": profile}))
    return 0


def _cmd_registry_authorize_hosted_account(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    target_key_id = cast(str, args.key_id)
    payload = {
        "target_key_id": target_key_id,
        **({"provider": args.provider} if args.provider else {}),
        **({"note": args.note} if args.note else {}),
    }
    challenge = _challenge_from_response(
        _request_json(
            identity.registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.ACCOUNT_AUTHORIZATION.value,
                "difficulty": args.difficulty,
                "bound_key_id": identity.key_id,
            },
        )
    )
    profile = _request_json(
        identity.registry_url,
        f"/pact/api/v1/profiles/{target_key_id}/hosted-authorize",
        payload=_signed_mutation_body(identity, challenge, payload),
    )
    print(_serialize_json(profile))
    return 0


def _cmd_registry_complete_hosted_login(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    payload = {
        **({"provider": args.provider} if args.provider else {}),
        **({"login_token": args.login_token} if args.login_token else {}),
    }
    challenge = _challenge_from_response(
        _request_json(
            identity.registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.HOSTED_ACCOUNT_AUTHORIZATION.value,
                "difficulty": args.difficulty,
                "bound_key_id": identity.key_id,
            },
        )
    )
    profile = _request_json(
        identity.registry_url,
        "/pact/api/v1/profiles/me/hosted-login",
        payload=_signed_mutation_body(identity, challenge, payload),
    )
    print(_serialize_json(profile))
    return 0


def _cmd_registry_attest_third_party(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    target_key_id = cast(str, args.key_id)
    payload = {
        "target_key_id": target_key_id,
        "documented_rights": bool(args.documented_rights),
        **({"provider": args.provider} if args.provider else {}),
        **({"note": args.note} if args.note else {}),
    }
    challenge = _challenge_from_response(
        _request_json(
            identity.registry_url,
            "/pact/api/v1/challenges",
            payload={
                "purpose": ChallengePurpose.THIRD_PARTY_ATTESTATION.value,
                "difficulty": args.difficulty,
                "bound_key_id": identity.key_id,
            },
        )
    )
    profile = _request_json(
        identity.registry_url,
        f"/pact/api/v1/profiles/{target_key_id}/third-party-attest",
        payload=_signed_mutation_body(identity, challenge, payload),
    )
    print(_serialize_json(profile))
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    target = Path(args.input)
    payload = target.read_bytes()
    mime_type = args.mime_type or _infer_mime_type(target)
    print(_serialize_json(inspect_content(payload, mime_type=mime_type)))
    return 0


def _cmd_recover(args: argparse.Namespace) -> int:
    target = Path(args.input)
    registry_url = _resolve_registry_url(args)
    mime_type = cast(str | None, args.mime_type) or _infer_mime_type(target)
    result = _request_file(
        registry_url,
        "/pact/api/v1/recover",
        file_path=target,
        mime_type=mime_type,
    )
    print(_serialize_json(result))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    target = Path(args.input)
    evidence_path = Path(cast(str | None, args.evidence) or args.input)
    digest = base64url_encode(
        hashlib.sha256(evidence_path.read_bytes()).digest()
    )
    registry_url = _resolve_registry_url(args)
    claim_id = _resolve_prompted_arg(
        args,
        "claim_id",
        label="Claim ID to report",
    )
    reason = AvoidanceReportLabel(cast(str, args.reason))
    payload: dict[str, object] = {
        "claim_id": claim_id,
        "observed_url": cast(str | None, args.where),
        "reason": reason.value,
        "description": cast(str | None, args.description),
        "evidence": {
            "kind": cast(str, args.evidence_kind),
            "digest": digest,
            "mime_type": _infer_mime_type(evidence_path),
        },
    }
    if args.reverse_lookup_score is not None:
        payload["reverse_lookup_score"] = cast(
            float,
            args.reverse_lookup_score,
        )
    result = _request_json(
        registry_url,
        "/pact/api/v1/reports/avoidance",
        payload=payload,
        headers=_profile_auth_headers(
            registry_url,
            identity,
            method="POST",
            path="/pact/api/v1/reports/avoidance",
            body=payload,
        ),
    )
    print(
        _serialize_json(
            {
                "report_id": result["report_id"],
                "claim_id": result["claim_id"],
                "status": result["status"],
                "public_visibility": result["public_visibility"],
                "owner_notified": result["owner_notified"],
                "reported_file": str(target),
            }
        )
    )
    return 0


def _cmd_watermark_image(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    mime_type = cast(str | None, args.mime_type) or _infer_mime_type(
        input_path
    )
    claim_id = UUID(
        _resolve_prompted_arg(
            args,
            "claim_id",
            label="Registry claim ID for this watermark",
        )
    )
    output_path = Path(
        _resolve_prompted_arg(
            args,
            "output",
            label="Watermarked image output path",
            default=f"{input_path}.watermarked",
        )
    )
    result = embed_image_soft_binding(
        input_path.read_bytes(),
        mime_type,
        claim_id=claim_id,
        registry_root_fingerprint=_registry_root_fingerprint(args),
        strength=cast(float, args.strength),
    )
    output_path.write_bytes(result.image_bytes)
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
    methods = _resolve_prompted_arg(
        args,
        "methods",
        label="Watermark methods",
        default="invisible",
    )
    secret = _resolve_secret(
        cast(str | None, args.secret),
        env_name="PACT_WATERMARK_SECRET",
        label="Watermark secret",
    )
    output_path = Path(
        _resolve_prompted_arg(
            args,
            "output",
            label="Watermarked text output path",
            default=f"{input_path}.watermarked",
        )
    )
    parameters = TextWatermarkParameters(
        user_confirmation=bool(args.confirm),
        allow_semantic_methods=bool(args.allow_semantic),
        approved_canary_phrase=cast(str | None, args.canary_phrase),
        max_changes=args.max_changes,
        selection_stride=args.selection_stride,
    )
    pipeline = apply_text_watermark_plugins(
        content,
        secret,
        _text_watermark_plugins(methods),
        parameters,
    )
    output_path.write_text(pipeline.transformed_content, encoding="utf-8")
    print(_serialize_json(pipeline.to_dict()))
    return 0


def _cmd_probe_create(args: argparse.Namespace) -> int:
    protected_texts = tuple(
        Path(path).read_text(encoding="utf-8")
        for path in _resolve_prompted_list(
            args,
            "protected",
            label="Protected text path",
        )
    )
    control_texts = tuple(
        Path(path).read_text(encoding="utf-8")
        for path in _resolve_prompted_list(
            args,
            "control",
            label="Control text path",
        )
    )
    target_model = _resolve_prompted_arg(
        args,
        "target_model",
        label="Target model name",
    )
    output_path = Path(
        _resolve_prompted_arg(
            args,
            "output",
            label="Probe set output path",
            default="pact-probes.json",
        )
    )
    probe_set = create_probe_set(
        protected_texts=protected_texts,
        control_texts=control_texts,
        target_model=target_model,
        claim_id=cast(str | None, args.claim_id),
        prefix_chars=cast(int, args.prefix_chars),
        withheld_chars=cast(int, args.withheld_chars),
    )
    output_path.write_text(
        _serialize_json(probe_set.to_dict()), encoding="utf-8"
    )
    print(
        _serialize_json(
            {
                "commitment": probe_set.commitment,
                "probe_count": len(probe_set.probes),
                "output": str(output_path),
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
    responses_path = _resolve_prompted_arg(
        args,
        "responses",
        label="Model responses JSONL path",
    )
    output_path = Path(
        _resolve_prompted_arg(
            args,
            "output",
            label="Probe evidence output path",
            default="pact-probe-evidence.json",
        )
    )
    responses = responses_from_jsonl(
        Path(responses_path).read_text(encoding="utf-8")
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
    output_path.write_text(
        _serialize_json(package.to_dict()), encoding="utf-8"
    )
    print(
        _serialize_json(
            {
                "conclusion": analysis.conclusion.value,
                "treatment_matches": analysis.treatment_matches,
                "control_matches": analysis.control_matches,
                "package_digest": package.package_digest,
                "output": str(output_path),
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
    output_path = Path(
        _resolve_prompted_arg(
            args,
            "output",
            label="Exported probe package output path",
            default="pact-probe-evidence.exported.json",
        )
    )
    output_path.write_text(
        _serialize_json(signed_package.to_dict()),
        encoding="utf-8",
    )
    print(
        _serialize_json(
            {
                "package_digest": signed_package.package_digest,
                "signed": signed_package.signature is not None,
                "output": str(output_path),
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
    database: str,
    enable_workspace: bool,
    oprf_server_secret: str | None = None,
    cors_allowed_origins: tuple[str, ...] = (),
    logging_config: LoggingConfig | None = None,
) -> int:
    import uvicorn

    from pact.web import create_app

    selected_logging = logging_config or _logging_config_from_args(None)
    configure_logging(selected_logging)
    if database in {":memory", ":memory:"}:
        print(
            "warning: using ephemeral in-memory registry storage; profiles, "
            "claims, reports, and disputes disappear when the server stops",
            file=sys.stderr,
        )
    service = _bootstrap_service(
        data_dir,
        registry_url,
        admin_jwk_files=admin_jwk_files,
        database=database,
        oprf_server_secret=oprf_server_secret,
    )
    app = create_app(
        service,
        public_base_url=public_base_url,
        local_mode=local_mode,
        enable_workspace=enable_workspace,
        cors_allowed_origins=cors_allowed_origins,
        logging_config=selected_logging,
    )
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=selected_logging.level.lower(),
        access_log=selected_logging.access_log,
    )
    return 0


def _serve_workspace_only(
    *,
    registry_url: str,
    host: str,
    port: int,
    public_base_url: str,
    logging_config: LoggingConfig | None = None,
) -> int:
    import uvicorn

    from pact.web import create_app

    selected_logging = logging_config or _logging_config_from_args(None)
    configure_logging(selected_logging)
    app = create_app(
        None,
        public_base_url=public_base_url,
        registry_url=registry_url,
        local_mode=True,
        enable_workspace=True,
        logging_config=selected_logging,
    )
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=selected_logging.level.lower(),
        access_log=selected_logging.access_log,
    )
    return 0


def _logging_config_from_args(
    args: argparse.Namespace | None,
) -> LoggingConfig:
    base = LoggingConfig.from_env()
    return LoggingConfig(
        level=cast(
            str,
            getattr(args, "log_level", None) or base.level,
        ),
        format=LogFormat(
            cast(
                str,
                getattr(args, "log_format", None) or base.format.value,
            )
        ),
        access_log=base.access_log
        and not bool(getattr(args, "no_access_log", False)),
    )


def _cmd_registry_serve(args: argparse.Namespace) -> int:
    registry_url = _resolve_registry_url(args)
    return _serve(
        data_dir=_resolve_data_dir(args),
        registry_url=registry_url,
        host=args.host,
        port=args.port,
        public_base_url=cast(str | None, args.public_base_url)
        or os.getenv("PACT_PUBLIC_BASE_URL")
        or registry_url,
        local_mode=False,
        admin_jwk_files=args.admin_jwk_file,
        database=_resolve_database(args),
        enable_workspace=bool(args.enable_workspace),
        oprf_server_secret=cast(str | None, args.oprf_server_secret),
        cors_allowed_origins=tuple(args.cors_allowed_origin),
        logging_config=_logging_config_from_args(args),
    )


def _cmd_web(args: argparse.Namespace) -> int:
    port = args.port
    remote_registry = cast(str | None, args.remote_registry)
    if remote_registry:
        return _serve_workspace_only(
            registry_url=normalize_registry_url(remote_registry),
            host="127.0.0.1",
            port=port,
            public_base_url=f"http://127.0.0.1:{port}",
            logging_config=_logging_config_from_args(args),
        )
    registry_url = _resolve_registry_url(args)
    public_base_url = f"http://127.0.0.1:{port}"
    data_dir = _resolve_data_dir(args)
    try:
        _load_authority(data_dir, registry_url)
    except SystemExit:
        _write_authority(
            data_dir,
            RegistryCertificateAuthority.initialize(
                registry_url,
            ).online_material(),
        )
    return _serve(
        data_dir=data_dir,
        registry_url=registry_url,
        host="127.0.0.1",
        port=port,
        public_base_url=public_base_url,
        local_mode=True,
        admin_jwk_files=args.admin_jwk_file,
        database=_resolve_database(args),
        enable_workspace=True,
        oprf_server_secret=cast(str | None, args.oprf_server_secret),
        logging_config=_logging_config_from_args(args),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pact",
        formatter_class=HelpFormatter,
        description=(
            "Sign content claims, run a local registry, and publish claims "
            "without needing custom scripts."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser(
        "identity",
        formatter_class=HelpFormatter,
        help="Create, show, import, export, or rotate claimant identities.",
        description="Manage the signing identity scoped to one registry.",
    )
    identity_subparsers = identity.add_subparsers(
        dest="identity_command", required=True
    )
    for name, handler in {
        "init": _cmd_identity_init,
        "show": _cmd_identity_show,
        "public-jwk": _cmd_identity_public_jwk,
        "export": _cmd_identity_export,
        "import": _cmd_identity_import,
        "rotate": _cmd_identity_rotate,
    }.items():
        subparser = identity_subparsers.add_parser(
            name,
            formatter_class=HelpFormatter,
        )
        subparser.add_argument(
            "--registry",
            help=(
                "Registry URL this identity belongs to. Uses "
                "PACT_REGISTRY_URL or prompts when omitted."
            ),
        )
        subparser.add_argument(
            "--identity-file",
            help=(
                "Encrypted local identity store. Omit to use the OS keyring."
            ),
        )
        subparser.add_argument(
            "--identity-password",
            help=(
                "Password for --identity-file. Uses PACT_IDENTITY_PASSWORD "
                "or prompts securely when omitted."
            ),
        )
        if name == "export":
            subparser.add_argument(
                "--recovery-json",
                action="store_true",
                help=(
                    "Write browser-compatible recovery JSON with continuity "
                    "material instead of raw encrypted PKCS#8 PEM."
                ),
            )
            subparser.add_argument(
                "--export-password",
                help="Password used to encrypt the exported PKCS#8 key.",
            )
            subparser.add_argument(
                "--out",
                help="Path where the encrypted private key should be written.",
            )
        if name == "public-jwk":
            subparser.add_argument(
                "--out",
                help="Path where the public JWK object should be written.",
            )
        if name == "import":
            subparser.add_argument(
                "--source",
                help="Encrypted PKCS#8 private key to import.",
            )
            subparser.add_argument(
                "--import-password",
                help="Password for the imported private key.",
            )
        subparser.set_defaults(handler=handler)

    sign = subparsers.add_parser(
        "sign",
        formatter_class=HelpFormatter,
        help="Create a signed manifest for a content file.",
        description=(
            "Create a signed manifest. When --registry-root-fingerprint is "
            "omitted, the CLI fetches it from the registry."
        ),
    )
    sign.add_argument("input", help="Content file to bind into the manifest.")
    sign.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts when omitted.",
    )
    sign.add_argument(
        "--registry-root-fingerprint",
        help=(
            "Expected registry root certificate fingerprint. Usually omitted; "
            "the CLI fetches it from /pact/api/v1/registry."
        ),
    )
    sign.add_argument(
        "--output",
        help="Manifest output path. Defaults to INPUT_STEM.manifest.json.",
    )
    sign.add_argument(
        "--nonce-out",
        help=(
            "Private nonce output path. Used only with --private-nonce and "
            "defaults to INPUT_STEM.nonce."
        ),
    )
    sign.add_argument(
        "--private-nonce",
        action="store_true",
        help=(
            "Do not include the content verification nonce in the signed "
            "proof. Others can verify the claim publicly, but content binding "
            "requires the nonce file."
        ),
    )
    sign.add_argument(
        "--policy",
        default="no-ai-training",
        help="Policy preset to attach to the manifest.",
    )
    sign.add_argument(
        "--carrier",
        default="visible",
        help=(
            "Carrier hint recorded in the manifest. For visible or both text "
            "carriers, pact sign also writes INPUT_STEM.pact.EXT."
        ),
    )
    sign.add_argument(
        "--canonicalization",
        default="pact.text.v1",
        help="Canonicalization profile for the input content.",
    )
    sign.add_argument(
        "--mime-type",
        help="Input MIME type. Omit to infer from the file extension.",
    )
    sign.add_argument(
        "--identity-file",
        help="Encrypted local identity store. Omit to use the OS keyring.",
    )
    sign.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    sign.set_defaults(handler=_cmd_sign)

    verify = subparsers.add_parser(
        "verify",
        formatter_class=HelpFormatter,
        help="Verify a manifest signature and optional content binding.",
        description=(
            "Verify a signed manifest. If --public-jwk is omitted, the CLI "
            "fetches the claimant profile from the manifest's registry."
        ),
    )
    verify.add_argument("manifest", help="Signed manifest JSON to verify.")
    verify.add_argument(
        "--public-jwk",
        help="Claimant public JWK file. Usually omitted for registered claims.",
    )
    verify.add_argument(
        "--content",
        help=(
            "Original content file. Public-nonce proofs need only this file; "
            "private-nonce proofs also need --nonce."
        ),
    )
    verify.add_argument(
        "--nonce",
        help="Nonce file written by pact sign.",
    )
    verify.set_defaults(handler=_cmd_verify)

    inspect = subparsers.add_parser(
        "inspect",
        formatter_class=HelpFormatter,
        help="Read a manifest or supported carrier file.",
    )
    inspect.add_argument(
        "input", help="Manifest or content carrier to inspect."
    )
    inspect.add_argument("--mime-type", help="MIME type for carrier parsing.")
    inspect.set_defaults(handler=_cmd_inspect)

    recover = subparsers.add_parser(
        "recover",
        formatter_class=HelpFormatter,
        help="Ask a registry for possible source claim recovery.",
    )
    recover.add_argument("input", help="Suspicious content file.")
    recover.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    recover.add_argument("--mime-type", help="MIME type for recovery parsing.")
    recover.set_defaults(handler=_cmd_recover)

    report = subparsers.add_parser(
        "report",
        formatter_class=HelpFormatter,
        help="Report possible provenance or fingerprint avoidance.",
    )
    report.add_argument("input", help="Suspicious content file.")
    report.add_argument(
        "--claim-id",
        help="Public-verification claim ID this report is associated with.",
    )
    report.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    report.add_argument(
        "--identity-file",
        help="Encrypted local reporter identity store. Omit to use the OS keyring.",
    )
    report.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    report.add_argument(
        "--where",
        help="Observed URL where the suspicious content appeared.",
    )
    report.add_argument(
        "--evidence",
        help="Evidence file to hash. Defaults to the suspicious input file.",
    )
    report.add_argument(
        "--evidence-kind",
        default="submitted_file",
        choices=(
            "submitted_file",
            "screenshot",
            "url_snapshot",
            "html_capture",
            "hash_only",
        ),
        help="Kind of evidence being submitted.",
    )
    report.add_argument(
        "--reason",
        default=AvoidanceReportLabel.POSSIBLE_AVOIDANCE.value,
        choices=tuple(label.value for label in AvoidanceReportLabel),
        help="Typed report label.",
    )
    report.add_argument(
        "--description",
        help="Optional reporter explanation.",
    )
    report.add_argument(
        "--reverse-lookup-score",
        type=float,
        help="Optional recovery score from a prior lookup, from 0 to 1.",
    )
    report.set_defaults(handler=_cmd_report)

    watermark = subparsers.add_parser(
        "watermark",
        formatter_class=HelpFormatter,
        help="Embed soft-binding watermark evidence.",
        description="Add image or text watermark evidence tied to a claim.",
    )
    watermark_subparsers = watermark.add_subparsers(
        dest="watermark_command",
        required=True,
    )
    watermark_image = watermark_subparsers.add_parser(
        "image",
        formatter_class=HelpFormatter,
        help="Embed an image watermark locator.",
    )
    watermark_image.add_argument("input", help="Image file to watermark.")
    watermark_image.add_argument(
        "--claim-id",
        help="Registry claim ID this watermark should point to.",
    )
    watermark_image.add_argument(
        "--registry",
        help="Registry URL used to fetch the root fingerprint when omitted.",
    )
    watermark_image.add_argument(
        "--registry-root-fingerprint",
        help=(
            "Registry root fingerprint used to bind the watermark locator. "
            "Usually omitted; the CLI fetches it from the registry."
        ),
    )
    watermark_image.add_argument(
        "--output",
        help="Path where the watermarked image should be written.",
    )
    watermark_image.add_argument(
        "--strength",
        type=float,
        default=1.0,
        help="Watermark embedding strength.",
    )
    watermark_image.add_argument(
        "--mime-type",
        help="Image MIME type. Omit to infer from the extension.",
    )
    watermark_image.set_defaults(handler=_cmd_watermark_image)
    watermark_text = watermark_subparsers.add_parser(
        "text",
        formatter_class=HelpFormatter,
        help="Apply one or more text watermark methods.",
    )
    watermark_text.add_argument("input", help="Text file to watermark.")
    watermark_text.add_argument(
        "--methods",
        help=(
            "Comma-separated methods: invisible, lexical, syntactic, "
            "semantic, canary, statistical."
        ),
    )
    watermark_text.add_argument(
        "--secret",
        help="Secret used to make watermark choices reproducible.",
    )
    watermark_text.add_argument(
        "--output",
        help="Path where the transformed text should be written.",
    )
    watermark_text.add_argument(
        "--confirm",
        action="store_true",
        help="Acknowledge that visible text changes are acceptable.",
    )
    watermark_text.add_argument(
        "--allow-semantic",
        action="store_true",
        help="Allow semantic paraphrase watermarking methods.",
    )
    watermark_text.add_argument(
        "--canary-phrase",
        help="Approved phrase to insert when using the canary method.",
    )
    watermark_text.add_argument(
        "--max-changes",
        type=int,
        default=8,
        help="Maximum number of text edits the pipeline may make.",
    )
    watermark_text.add_argument(
        "--selection-stride",
        type=int,
        default=3,
        help="Spacing used when selecting candidate watermark positions.",
    )
    watermark_text.set_defaults(handler=_cmd_watermark_text)

    probe = subparsers.add_parser(
        "probe",
        formatter_class=HelpFormatter,
        help="Create and analyze model training-use probes.",
        description=(
            "Prepare prompts, analyze model responses, and export evidence "
            "packages for possible training-use claims."
        ),
    )
    probe_subparsers = probe.add_subparsers(
        dest="probe_command", required=True
    )
    probe_create = probe_subparsers.add_parser(
        "create",
        formatter_class=HelpFormatter,
        help="Create probe prompts from protected and control text.",
    )
    probe_create.add_argument(
        "--protected",
        action="append",
        help="Protected text file. Repeat for multiple files.",
    )
    probe_create.add_argument(
        "--control",
        action="append",
        help="Control text file. Repeat for multiple files.",
    )
    probe_create.add_argument(
        "--target-model",
        help="Name of the third-party model the probes will be sent to.",
    )
    probe_create.add_argument(
        "--output",
        help="Path where the probe set JSON should be written.",
    )
    probe_create.add_argument(
        "--claim-id",
        help="Optional registry claim ID associated with the protected text.",
    )
    probe_create.add_argument(
        "--prefix-chars",
        type=int,
        default=160,
        help="Characters revealed to the target model in each probe.",
    )
    probe_create.add_argument(
        "--withheld-chars",
        type=int,
        default=220,
        help="Characters held back and later compared with model output.",
    )
    probe_create.set_defaults(handler=_cmd_probe_create)
    probe_analyze = probe_subparsers.add_parser(
        "analyze",
        formatter_class=HelpFormatter,
        help="Analyze model responses against a probe set.",
    )
    probe_analyze.add_argument("probe_set", help="Probe set JSON file.")
    probe_analyze.add_argument(
        "--responses",
        help="JSONL file containing responses collected from the model.",
    )
    probe_analyze.add_argument(
        "--output",
        help="Path where the evidence package should be written.",
    )
    probe_analyze.add_argument(
        "--false-positive-threshold",
        type=float,
        default=0.05,
        help="Maximum tolerated false-positive probability.",
    )
    probe_analyze.set_defaults(handler=_cmd_probe_analyze)
    probe_export = probe_subparsers.add_parser(
        "export",
        formatter_class=HelpFormatter,
        help="Export and optionally sign a probe evidence package.",
    )
    probe_export.add_argument("package", help="Evidence package JSON file.")
    probe_export.add_argument(
        "--output",
        help="Path where the exported package should be written.",
    )
    probe_export.add_argument(
        "--identity-file",
        help="Encrypted local identity store. Include to sign the package.",
    )
    probe_export.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    probe_export.add_argument(
        "--registry",
        help="Registry URL for signing identity lookup.",
    )
    probe_export.set_defaults(handler=_cmd_probe_export)

    privacy = subparsers.add_parser(
        "privacy",
        formatter_class=HelpFormatter,
        help="Audit whether public payloads leak private material.",
    )
    privacy_subparsers = privacy.add_subparsers(
        dest="privacy_command", required=True
    )
    privacy_audit = privacy_subparsers.add_parser(
        "audit",
        formatter_class=HelpFormatter,
        help="Audit a signed manifest before publication.",
    )
    privacy_audit.add_argument("manifest", help="Signed manifest JSON file.")
    privacy_audit.add_argument(
        "--content",
        help="Original content file to check against accidental disclosure.",
    )
    privacy_audit.add_argument(
        "--nonce",
        help="Nonce file to check against accidental disclosure.",
    )
    privacy_audit.add_argument(
        "--private-value",
        action="append",
        default=[],
        help="Additional private file value to check. Repeat as needed.",
    )
    privacy_audit.set_defaults(handler=_cmd_privacy_audit)

    registry = subparsers.add_parser(
        "registry",
        formatter_class=HelpFormatter,
        help="Initialize, run, and publish to a registry.",
        description=(
            "Registry commands use PACT_REGISTRY_URL and PACT_DATA_DIR when "
            "available, then prompt for missing local setup values."
        ),
    )
    registry_subparsers = registry.add_subparsers(
        dest="registry_command", required=True
    )
    registry_init = registry_subparsers.add_parser(
        "init",
        formatter_class=HelpFormatter,
        help="Create local registry CA material.",
        description=(
            "Create the local certificate authority material needed to run a "
            "registry. Missing registry URL, data directory, and root key "
            "password are prompted."
        ),
    )
    registry_init.add_argument(
        "--registry",
        help="Public registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    registry_init.add_argument(
        "--data-dir",
        help="Directory for registry CA material. Uses PACT_DATA_DIR or prompts.",
    )
    registry_init.add_argument(
        "--root-key-password",
        help=(
            "Password for the offline root private key. Uses "
            "PACT_ROOT_KEY_PASSWORD or prompts securely."
        ),
    )
    registry_init.set_defaults(handler=_cmd_registry_init)
    serve = registry_subparsers.add_parser(
        "serve",
        formatter_class=HelpFormatter,
        help="Run the registry API and proof pages locally.",
        description=(
            "Run the monolith registry server with SQLite persistence. Use "
            "--database :memory for throwaway state or a file path to keep "
            "registry events across restarts."
        ),
    )
    serve.add_argument(
        "--registry",
        help="Registry URL served by this process.",
    )
    serve.add_argument(
        "--data-dir",
        help="Directory containing registry CA material.",
    )
    serve.add_argument(
        "--public-base-url",
        help="External base URL shown in pages. Defaults to --registry.",
    )
    serve.add_argument(
        "--host",
        default="0.0.0.0",
        help="Network interface the local server binds to.",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=8000,
        help="TCP port for the local server.",
    )
    serve.add_argument(
        "--admin-jwk-file",
        action="append",
        default=[],
        help=(
            "Public JWK for a registry administrator identity. Create with "
            "`pact identity public-jwk --out admin.public.jwk.json`. Repeat "
            "for multiple admins."
        ),
    )
    serve.add_argument(
        "--database",
        default=DEFAULT_LOCAL_DATABASE,
        help="SQLite database path, or :memory / :memory: for ephemeral state.",
    )
    serve.add_argument(
        "--oprf-server-secret",
        help=(
            "Dedicated OPRF server secret. Defaults to "
            "PACT_OPRF_SERVER_SECRET or the registry data-dir secret file."
        ),
    )
    serve.add_argument(
        "--enable-workspace",
        action="store_true",
        help=(
            "Serve the interactive browser workspace with the registry API. "
            "Omit to expose only the API and proof pages."
        ),
    )
    serve.add_argument(
        "--cors-allowed-origin",
        action="append",
        default=[],
        help=(
            "Browser origin allowed to call this registry API. Repeat for "
            "standalone web interfaces hosted on multiple origins."
        ),
    )
    _add_server_logging_args(serve)
    serve.set_defaults(handler=_cmd_registry_serve)
    teardown = registry_subparsers.add_parser(
        "teardown",
        formatter_class=HelpFormatter,
        help="Delete persistent local state for one registry.",
        description=(
            "Delete local CA/OPRF material, SQLite registry records, the "
            "local device binding, and the keyring identity for one registry. "
            "The command prints the planned deletions and requires two "
            "confirmations."
        ),
    )
    teardown.add_argument(
        "--registry",
        help="Registry URL whose local state should be deleted.",
    )
    teardown.add_argument(
        "--data-dir",
        help="Directory containing registry CA material.",
    )
    teardown.add_argument(
        "--database",
        default=DEFAULT_LOCAL_DATABASE,
        help="SQLite database path used by the registry server.",
    )
    teardown.add_argument(
        "--confirm-registry",
        help=(
            "First confirmation: must equal the normalized registry URL. "
            "Omit to be prompted."
        ),
    )
    teardown.add_argument(
        "--confirm-delete",
        help=(
            "Second confirmation: must be `delete registry <registry-url>`. "
            "Omit to be prompted."
        ),
    )
    teardown.set_defaults(handler=_cmd_registry_teardown)
    register_profile = registry_subparsers.add_parser(
        "register-profile",
        formatter_class=HelpFormatter,
        help="Publish the current identity's public profile.",
        description=(
            "Register the selected identity with the registry so others can "
            "resolve its public JWK and verify manifests without local files."
        ),
    )
    register_profile.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    register_profile.add_argument(
        "--identity-file",
        help="Encrypted local identity store. Omit to use the OS keyring.",
    )
    register_profile.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    register_profile.add_argument(
        "--display-name",
        help="Optional public display name for this claimant profile.",
    )
    register_profile.add_argument(
        "--difficulty",
        type=int,
        default=4,
        help="Proof-of-work difficulty for the local mutation request.",
    )
    register_profile.set_defaults(handler=_cmd_registry_register_profile)
    register_claim = registry_subparsers.add_parser(
        "register-claim",
        formatter_class=HelpFormatter,
        help="Publish a signed manifest as a registry claim.",
        description=(
            "Submit a signed manifest to the registry using the current "
            "identity. This replaces the custom Python registration snippet."
        ),
    )
    register_claim.add_argument(
        "manifest",
        help="Signed manifest JSON created by pact sign.",
    )
    register_claim.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    register_claim.add_argument(
        "--identity-file",
        help="Encrypted local identity store. Omit to use the OS keyring.",
    )
    register_claim.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    register_claim.add_argument(
        "--difficulty",
        type=int,
        default=4,
        help="Proof-of-work difficulty for the local mutation request.",
    )
    register_claim.set_defaults(handler=_cmd_registry_register_claim)
    verify_domain = registry_subparsers.add_parser(
        "verify-domain",
        formatter_class=HelpFormatter,
        help="Upgrade trust by proving DNS control of a domain.",
        description=(
            "Print or submit the DNS TXT challenge that links this identity "
            "to a domain. Verification only succeeds after public DNS returns "
            "the required TXT value."
        ),
    )
    verify_domain.add_argument("domain", help="Domain name to verify.")
    verify_domain.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    verify_domain.add_argument(
        "--identity-file",
        help="Encrypted local identity store. Omit to use the OS keyring.",
    )
    verify_domain.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    verify_domain.add_argument(
        "--show-record-only",
        action="store_true",
        help="Only print the DNS TXT record to create; do not submit.",
    )
    verify_domain.add_argument(
        "--difficulty",
        type=int,
        default=4,
        help="Proof-of-work difficulty for the local mutation request.",
    )
    verify_domain.set_defaults(handler=_cmd_registry_verify_domain)
    authorize_hosted = registry_subparsers.add_parser(
        "authorize-hosted-account",
        formatter_class=HelpFormatter,
        help="Admin-authorize hosted-account trust.",
        description=(
            "Submit an administrator-signed hosted-account authorization "
            "event for a claimant profile. This records the same hosted trust "
            "tier as a registry-host login flow."
        ),
    )
    authorize_hosted.add_argument(
        "key_id",
        help="Claimant profile key ID to authorize.",
    )
    authorize_hosted.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    authorize_hosted.add_argument(
        "--identity-file",
        help="Encrypted local admin identity store. Omit to use the OS keyring.",
    )
    authorize_hosted.add_argument(
        "--identity-password",
        help="Password for --identity-file.",
    )
    authorize_hosted.add_argument(
        "--provider",
        help="Optional hosted-service provider name recorded with the event.",
    )
    authorize_hosted.add_argument(
        "--note",
        help="Optional administrative note recorded with the event.",
    )
    authorize_hosted.add_argument(
        "--difficulty",
        type=int,
        default=4,
        help="Proof-of-work difficulty for the local mutation request.",
    )
    authorize_hosted.set_defaults(
        handler=_cmd_registry_authorize_hosted_account
    )
    hosted_login = registry_subparsers.add_parser(
        "complete-hosted-login",
        formatter_class=HelpFormatter,
        help="Complete a registry-host login trust upgrade.",
        description=(
            "Submit a hosted-login assertion from the registry host. The "
            "server must configure a verifier for this flow."
        ),
    )
    hosted_login.add_argument("--registry", help="Registry URL.")
    hosted_login.add_argument(
        "--identity-file", help="Encrypted identity store."
    )
    hosted_login.add_argument(
        "--identity-password", help="Password for --identity-file."
    )
    hosted_login.add_argument("--provider", help="Hosted identity provider.")
    hosted_login.add_argument(
        "--login-token", help="Opaque login token or code."
    )
    hosted_login.add_argument(
        "--difficulty",
        type=int,
        default=4,
        help="Proof-of-work difficulty for the local mutation request.",
    )
    hosted_login.set_defaults(handler=_cmd_registry_complete_hosted_login)
    third_party = registry_subparsers.add_parser(
        "attest-third-party",
        formatter_class=HelpFormatter,
        help="Attest another claimant as an independent third party.",
    )
    third_party.add_argument(
        "key_id", help="Claimant profile key ID to attest."
    )
    third_party.add_argument("--registry", help="Registry URL.")
    third_party.add_argument(
        "--identity-file", help="Encrypted attester identity store."
    )
    third_party.add_argument(
        "--identity-password", help="Password for --identity-file."
    )
    third_party.add_argument(
        "--documented-rights",
        action="store_true",
        help="Also attest that rights documentation was reviewed.",
    )
    third_party.add_argument(
        "--provider", help="Attester or organization name."
    )
    third_party.add_argument("--note", help="Optional attestation note.")
    third_party.add_argument(
        "--difficulty",
        type=int,
        default=4,
        help="Proof-of-work difficulty for the local mutation request.",
    )
    third_party.set_defaults(handler=_cmd_registry_attest_third_party)

    web = subparsers.add_parser(
        "web",
        formatter_class=HelpFormatter,
        help="Run a local registry web UI with automatic local CA bootstrap.",
        description=(
            "Start a developer web registry. If CA material is missing, this "
            "command creates online-only local material automatically."
        ),
    )
    web.add_argument(
        "--registry",
        help="Registry URL. Uses PACT_REGISTRY_URL or prompts.",
    )
    web.add_argument(
        "--remote-registry",
        help=(
            "Serve only the browser workspace and point it at this external "
            "registry URL."
        ),
    )
    web.add_argument(
        "--data-dir",
        help="Directory for local registry material.",
    )
    web.add_argument(
        "--port",
        type=int,
        default=8000,
        help="TCP port for the local web UI.",
    )
    web.add_argument(
        "--admin-jwk-file",
        action="append",
        default=[],
        help=(
            "Public JWK for a registry administrator identity. Create with "
            "`pact identity public-jwk --out admin.public.jwk.json`. Repeat "
            "for multiple admins."
        ),
    )
    web.add_argument(
        "--database",
        default=DEFAULT_LOCAL_DATABASE,
        help="SQLite database path, or :memory / :memory: for ephemeral state.",
    )
    web.add_argument(
        "--oprf-server-secret",
        help=(
            "Dedicated OPRF server secret. Defaults to "
            "PACT_OPRF_SERVER_SECRET or the registry data-dir secret file."
        ),
    )
    _add_server_logging_args(web)
    web.set_defaults(handler=_cmd_web)

    return parser


def _add_server_logging_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Server log level. Defaults to PACT_LOG_LEVEL or INFO.",
    )
    parser.add_argument(
        "--log-format",
        choices=tuple(item.value for item in LogFormat),
        help="Server log format. Defaults to PACT_LOG_FORMAT or plain.",
    )
    parser.add_argument(
        "--no-access-log",
        action="store_true",
        help="Disable per-request access logs for this server process.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return cast(int, args.handler(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
