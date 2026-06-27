"""Browser-facing helpers used by the Pyodide workspace."""

import base64
import hashlib
import json
import os
from dataclasses import asdict
from typing import cast
from uuid import UUID

from pact.canonical import CanonicalizationProfile, JsonValue, canonical_json
from pact.crypto import sign_es256
from pact.detection.evidence import ProbeEvidencePackage
from pact.detection.probes import (
    ProbeSet,
    create_probe_set,
    responses_from_jsonl,
)
from pact.detection.statistics import analyze_probe_responses
from pact.identity import ClaimantIdentity
from pact.manifest import (
    C2PAAction,
    C2PAIngredient,
    Manifest,
    SignedManifest,
    sign_manifest,
    verify_manifest,
)
from pact.policy import Permission, PermissionValue, Policy, PolicyEntry
from pact.privacy import audit_signed_manifest_publication


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _policy_from_json(value: str | None, fallback: str) -> Policy:
    if value:
        raw = json.loads(value)
        if not isinstance(raw, dict):
            raise ValueError("policy must be a JSON object")
        return Policy.from_dict(cast(dict[str, object], raw))
    permission_value = (
        PermissionValue.NOT_ALLOWED
        if fallback == "no-ai-training"
        else PermissionValue.ALLOWED
    )
    return Policy(
        (
            PolicyEntry(
                Permission.GENERATIVE_TRAINING,
                permission_value,
            ),
        )
    )


def _identity(
    registry_url: str,
    encrypted_pkcs8_b64: str,
    password: str,
) -> ClaimantIdentity:
    return ClaimantIdentity.import_pkcs8(
        registry_url,
        _unb64(encrypted_pkcs8_b64),
        password,
    )


def create_identity(registry_url: str, password: str) -> str:
    """Create a claimant identity and return an encrypted browser vault blob."""

    identity = ClaimantIdentity.generate(registry_url)
    return _json(
        {
            "registry_url": identity.registry_url,
            "key_id": identity.key_id,
            "public_jwk": identity.public_jwk,
            "encrypted_pkcs8_b64": _b64(identity.export_pkcs8(password)),
        }
    )


def import_identity(
    registry_url: str,
    encrypted_pkcs8_b64: str,
    password: str,
) -> str:
    """Validate an encrypted identity export and return public identity data."""

    identity = _identity(registry_url, encrypted_pkcs8_b64, password)
    return _json(
        {
            "registry_url": identity.registry_url,
            "key_id": identity.key_id,
            "public_jwk": identity.public_jwk,
        }
    )


def rotate_identity(
    registry_url: str,
    encrypted_pkcs8_b64: str,
    password: str,
) -> str:
    """Create a replacement claimant identity for the same registry."""

    current = _identity(registry_url, encrypted_pkcs8_b64, password)
    replacement = current.rotate()
    return _json(
        {
            "registry_url": replacement.registry_url,
            "previous_key_id": current.key_id,
            "replacement_key_id": replacement.key_id,
            "public_jwk": replacement.public_jwk,
            "encrypted_pkcs8_b64": _b64(replacement.export_pkcs8(password)),
        }
    )


def challenge_from_json(value: str) -> dict[str, object]:
    """Parse a registry challenge JSON response."""

    data = json.loads(value)
    challenge: dict[str, object] = {
        "registry_url": data["registry_url"],
        "challenge_id": data["challenge_id"],
        "purpose": data["purpose"],
        "issued_at": data["issued_at"],
        "expires_at": data["expires_at"],
        "challenge_nonce": data["challenge_nonce"],
        "difficulty": data["difficulty"],
    }
    if data.get("bound_key_id") is not None:
        challenge["bound_key_id"] = data["bound_key_id"]
    return challenge


def _leading_zero_bits(value: bytes) -> int:
    bits = 0
    for byte in value:
        if byte == 0:
            bits += 8
            continue
        return bits + (8 - byte.bit_length())
    return bits


def _verify_pow(challenge: dict[str, object], solution: int) -> bool:
    if solution < 0:
        return False
    digest = hashlib.sha256(
        canonical_json(cast(JsonValue, challenge))
        + b":"
        + str(solution).encode("ascii")
    ).digest()
    difficulty = challenge["difficulty"]
    if not isinstance(difficulty, int):
        raise ValueError("challenge difficulty must be an integer")
    return _leading_zero_bits(digest) >= difficulty


def solve_pow(challenge_json: str) -> int:
    """Return the first proof-of-work solution for a challenge."""

    challenge = challenge_from_json(challenge_json)
    solution = 0
    while not _verify_pow(challenge, solution):
        solution += 1
    return solution


def create_mutation_request(
    registry_url: str,
    encrypted_pkcs8_b64: str,
    password: str,
    challenge_json: str,
    payload_json: str,
) -> str:
    """Create a signed registry mutation request."""

    identity = _identity(registry_url, encrypted_pkcs8_b64, password)
    challenge = challenge_from_json(challenge_json)
    proof_of_work_solution = solve_pow(challenge_json)
    payload = cast(dict[str, object], json.loads(payload_json))
    signed_bytes = canonical_json(
        cast(
            JsonValue,
            {
                "challenge": challenge,
                "claimant_public_jwk": identity.public_jwk,
                "proof_of_work_solution": proof_of_work_solution,
                "payload": payload,
            },
        )
    )
    return _json(
        {
            "challenge_id": challenge["challenge_id"],
            "claimant_public_jwk": identity.public_jwk,
            "proof_of_work_solution": proof_of_work_solution,
            "payload": payload,
            "signature": sign_es256(identity.private_key, signed_bytes),
        }
    )


def create_rotation_request(
    registry_url: str,
    current_encrypted_pkcs8_b64: str,
    replacement_encrypted_pkcs8_b64: str,
    password: str,
    challenge_json: str,
    payload_json: str,
) -> str:
    """Create a signed registry key-rotation request."""

    current = _identity(registry_url, current_encrypted_pkcs8_b64, password)
    replacement = _identity(
        registry_url,
        replacement_encrypted_pkcs8_b64,
        password,
    )
    challenge = challenge_from_json(challenge_json)
    proof_of_work_solution = solve_pow(challenge_json)
    payload = cast(dict[str, object], json.loads(payload_json))
    signed_bytes = canonical_json(
        cast(
            JsonValue,
            {
                "challenge": challenge,
                "current_public_jwk": current.public_jwk,
                "replacement_public_jwk": replacement.public_jwk,
                "proof_of_work_solution": proof_of_work_solution,
                "payload": payload,
            },
        )
    )
    return _json(
        {
            "challenge_id": challenge["challenge_id"],
            "current_public_jwk": current.public_jwk,
            "replacement_public_jwk": replacement.public_jwk,
            "proof_of_work_solution": proof_of_work_solution,
            "payload": payload,
            "current_signature": sign_es256(current.private_key, signed_bytes),
            "replacement_signature": sign_es256(
                replacement.private_key,
                signed_bytes,
            ),
        }
    )


def sign_content(
    registry_url: str,
    encrypted_pkcs8_b64: str,
    password: str,
    content_b64: str,
    registry_root_fingerprint: str,
    mime_type: str,
    canonicalization: str = "pact.text.v1",
    policy: str = "no-ai-training",
    carrier: str = "visible",
    source_url: str | None = None,
    actions_json: str = "[]",
    ingredients_json: str = "[]",
    policy_json: str | None = None,
) -> str:
    """Create a signed manifest and nonce for browser-selected content."""

    identity = _identity(registry_url, encrypted_pkcs8_b64, password)
    content = _unb64(content_b64)
    nonce = os.urandom(32)
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=registry_root_fingerprint,
        content=content,
        mime_type=mime_type,
        canonicalization=CanonicalizationProfile(canonicalization),
        policy=_policy_from_json(policy_json, policy),
        carriers=(carrier,),
        actions=tuple(
            C2PAAction.from_dict(cast(dict[str, object], item))
            for item in json.loads(actions_json)
        ),
        ingredients=tuple(
            C2PAIngredient.from_dict(cast(dict[str, object], item))
            for item in json.loads(ingredients_json)
        ),
        source_url=source_url or None,
        nonce=nonce,
    )
    signed = sign_manifest(manifest, identity)
    return _json(
        {
            "claim_id": str(signed.manifest.claim_id),
            "manifest_json": signed.to_json().decode("utf-8"),
            "nonce_b64": _b64(nonce),
        }
    )


def verify_manifest_json(
    signed_manifest_json: str,
    public_jwk_json: str,
    content_b64: str | None = None,
    nonce_b64: str | None = None,
) -> str:
    """Verify a signed manifest and optional content binding."""

    report = verify_manifest(
        SignedManifest.from_json(signed_manifest_json.encode("utf-8")),
        cast(dict[str, object], json.loads(public_jwk_json)),
        content=None if content_b64 is None else _unb64(content_b64),
        nonce=None if nonce_b64 is None else _unb64(nonce_b64),
    )
    return _json(asdict(report))


def privacy_audit(
    signed_manifest_json: str,
    content_b64: str | None = None,
    nonce_b64: str | None = None,
) -> str:
    """Audit a signed manifest before it is registered publicly."""

    report = audit_signed_manifest_publication(
        SignedManifest.from_json(signed_manifest_json.encode("utf-8")),
        content=None if content_b64 is None else _unb64(content_b64),
        nonce=None if nonce_b64 is None else _unb64(nonce_b64),
    )
    return _json(report.to_dict())


def create_probes(
    protected_json: str,
    control_json: str,
    target_model: str,
    claim_id: str | None = None,
) -> str:
    """Create a model-probing prompt set from protected and control text."""

    probe_set = create_probe_set(
        protected_texts=tuple(json.loads(protected_json)),
        control_texts=tuple(json.loads(control_json)),
        target_model=target_model,
        claim_id=claim_id,
    )
    return _json(probe_set.to_dict())


def analyze_probes(
    probe_set_json: str,
    responses_jsonl: str,
    false_positive_threshold: float = 0.05,
) -> str:
    """Analyze third-party model responses against a probe set."""

    probe_set = ProbeSet.from_dict(json.loads(probe_set_json))
    responses = responses_from_jsonl(responses_jsonl)
    analysis = analyze_probe_responses(
        probe_set,
        responses,
        false_positive_threshold=false_positive_threshold,
    )
    package = ProbeEvidencePackage.create(
        probe_set=probe_set,
        responses=responses,
        analysis=analysis,
    )
    return _json(package.to_dict())


def watermark_text(
    content: str,
    secret: str,
    methods_json: str = '["invisible"]',
    canary_phrase: str | None = None,
) -> str:
    """Apply text watermark plugins to browser-provided prose."""

    from pact.watermarks.base import TextWatermarkParameters
    from pact.watermarks.canary import CanaryPhrasePlugin
    from pact.watermarks.invisible import InvisibleFramePlugin
    from pact.watermarks.lexical import LexicalSubstitutionPlugin
    from pact.watermarks.statistical import StatisticalSentencePatternPlugin
    from pact.watermarks.syntactic import SyntacticVariationPlugin
    from pact.watermarks.textual import apply_text_watermark_plugins

    available = {
        "invisible": InvisibleFramePlugin,
        "lexical": LexicalSubstitutionPlugin,
        "syntactic": SyntacticVariationPlugin,
        "canary": CanaryPhrasePlugin,
        "statistical": StatisticalSentencePatternPlugin,
    }
    methods = json.loads(methods_json)
    plugins = tuple(available[name]() for name in methods)
    result = apply_text_watermark_plugins(
        content,
        secret,
        plugins,
        TextWatermarkParameters(
            user_confirmation=True,
            approved_canary_phrase=canary_phrase or None,
        ),
    )
    return _json(result.to_dict())


def watermark_image(
    image_b64: str,
    mime_type: str,
    claim_id: str,
    registry_root_fingerprint: str,
    strength: float = 1.0,
) -> str:
    """Embed a TrustMark claim locator into a browser-provided image."""

    from pact.watermarks.image import embed_image_soft_binding

    result = embed_image_soft_binding(
        _unb64(image_b64),
        mime_type,
        claim_id=UUID(claim_id),
        registry_root_fingerprint=registry_root_fingerprint,
        strength=strength,
    )
    return _json(
        {
            **result.to_dict(),
            "image_b64": _b64(result.image_bytes),
        }
    )


def embed_signed_manifest_carrier(
    asset_b64: str,
    mime_type: str,
    signed_manifest_json: str,
) -> str:
    """Embed a PACT signed manifest in a browser-provided asset."""

    from pact.carriers import (
        CarrierMode,
        embed_html_carrier,
        embed_text_carrier,
        embed_xml_carrier,
    )

    asset = _unb64(asset_b64)
    signed = SignedManifest.from_json(signed_manifest_json.encode("utf-8"))
    if mime_type in {"text/html", "application/xhtml+xml"}:
        embedded = embed_html_carrier(asset, signed)
    elif mime_type in {"application/xml", "text/xml", "image/svg+xml"}:
        embedded = embed_xml_carrier(asset, signed)
    elif mime_type.startswith("text/"):
        embedded = embed_text_carrier(
            asset, signed, nonce=b"", mode=CarrierMode.VISIBLE
        )
    elif mime_type == "application/pdf":
        from pact.carriers.c2pa import embed_c2pa_manifest_in_pdf

        embedded = embed_c2pa_manifest_in_pdf(
            asset,
            signed_manifest_json.encode("utf-8"),
        ).asset_bytes
    elif mime_type in {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/epub+zip",
    }:
        from pact.carriers.c2pa import embed_c2pa_manifest_in_zip_document

        embedded = embed_c2pa_manifest_in_zip_document(
            asset,
            mime_type,
            signed_manifest_json.encode("utf-8"),
        ).asset_bytes
    else:
        raise ValueError(
            "embedded proof downloads are available for text, HTML, XML, PDF, "
            "and ZIP-based Office documents"
        )
    return _json({"asset_b64": _b64(embedded), "mime_type": mime_type})


def embed_pdf_manifest(pdf_b64: str, manifest_store_b64: str) -> str:
    """Embed a C2PA manifest store into a PDF embedded file stream."""

    from pact.carriers.c2pa import embed_c2pa_manifest_in_pdf

    result = embed_c2pa_manifest_in_pdf(
        _unb64(pdf_b64),
        _unb64(manifest_store_b64),
    )
    return _json(
        {
            "mime_type": result.mime_type,
            "asset_b64": _b64(result.asset_bytes),
            "manifest_store_b64": _b64(result.manifest_store_bytes),
        }
    )


def extract_pdf_manifest(pdf_b64: str) -> str:
    """Extract a C2PA manifest store from a PDF embedded file stream."""

    from pact.carriers.c2pa import extract_c2pa_manifest_from_pdf

    manifest_store = extract_c2pa_manifest_from_pdf(_unb64(pdf_b64))
    return _json({"manifest_store_b64": _b64(manifest_store)})


def embed_zip_document_manifest(
    asset_b64: str,
    mime_type: str,
    manifest_store_b64: str,
) -> str:
    """Embed a C2PA manifest store into a ZIP-based document."""

    from pact.carriers.c2pa import embed_c2pa_manifest_in_zip_document

    result = embed_c2pa_manifest_in_zip_document(
        _unb64(asset_b64),
        mime_type,
        _unb64(manifest_store_b64),
    )
    return _json(
        {
            "mime_type": result.mime_type,
            "asset_b64": _b64(result.asset_bytes),
            "manifest_store_b64": _b64(result.manifest_store_bytes),
        }
    )


def extract_zip_document_manifest(asset_b64: str) -> str:
    """Extract a C2PA manifest store from a ZIP-based document."""

    from pact.carriers.c2pa import extract_c2pa_manifest_from_zip_document

    return _json(
        {
            "manifest_store_b64": _b64(
                extract_c2pa_manifest_from_zip_document(_unb64(asset_b64))
            )
        }
    )


def unavailable_native_c2pa() -> str:
    """Explain native C2PA limitations in browser runtimes."""

    try:
        __import__("c2pa")
    except ImportError as error:
        from pact.carriers.c2pa import C2paError

        raise C2paError(
            "native C2PA signing/reading is unavailable in this browser "
            "runtime unless the official C2PA SDK can be loaded"
        ) from error
    return _json({"available": True})
