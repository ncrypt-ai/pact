"""Device-binding token helpers backed by pure-Python Ristretto OPRF."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from typing import Any

from pact.crypto import base64url_decode, base64url_encode

DEVICE_BINDING_TOKEN_PREFIX = "pact-device-binding-v2."

OprfEvaluator = Callable[[dict[str, str]], Mapping[str, object]]


class OprfError(ValueError):
    """Raised when device-binding OPRF support is unavailable or invalid."""


def _ristretto() -> Any:
    try:
        from oblivious.ristretto import python
    except Exception as error:
        raise OprfError(
            "oblivious.ristretto pure-Python primitives are unavailable"
        ) from error
    return python


def format_device_binding_token(digest: bytes | str) -> str:
    if isinstance(digest, bytes):
        digest_text = base64url_encode(digest)
    else:
        base64url_decode(digest, length=32)
        digest_text = digest
    return f"{DEVICE_BINDING_TOKEN_PREFIX}{digest_text}"


def device_binding_input(
    *,
    local_secret: bytes,
    registry_root_fingerprint: str,
    device_fingerprint: str,
) -> bytes:
    return hmac.new(
        local_secret,
        b"PACT device binding input v1\0"
        + registry_root_fingerprint.encode("utf-8")
        + b"\0"
        + device_fingerprint.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def device_oprf_server_scalar(
    *,
    registry_url: str,
    registry_root_fingerprint: str,
    server_secret: bytes,
) -> bytes:
    digest = hmac.new(
        server_secret,
        b"PACT device binding OPRF server v1\0"
        + registry_url.encode("utf-8")
        + b"\0"
        + registry_root_fingerprint.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return digest


def evaluate_device_oprf(
    blinded_point: Mapping[str, object],
    *,
    server_scalar: bytes | int,
) -> dict[str, str]:
    blinded_value = blinded_point.get("blinded")
    if not isinstance(blinded_value, str):
        raise OprfError("OPRF request must include blinded")
    if isinstance(server_scalar, int):
        server_key = server_scalar.to_bytes(32, "big", signed=False)
    else:
        server_key = server_scalar
    if len(server_key) != 32:
        raise OprfError("OPRF server key must be 32 bytes")
    oprf = _ristretto()
    try:
        blinded = oprf.point(base64url_decode(blinded_value, length=32))
        server_key_scalar = oprf.scalar(server_key)
        evaluated = server_key_scalar * blinded
    except Exception as error:
        if isinstance(error, OprfError):
            raise
        raise OprfError("OPRF evaluation failed") from error
    return {"evaluated": base64url_encode(bytes(evaluated))}


def device_binding_oprf_token(
    *,
    local_input: bytes,
    evaluator: OprfEvaluator,
) -> str:
    oprf = _ristretto()
    try:
        input_point = oprf.point.hash(local_input)
        blind = oprf.scalar()
        blinded = blind * input_point
        response = evaluator({"blinded": base64url_encode(blinded)})
        evaluated_value = response.get("evaluated")
        if not isinstance(evaluated_value, str):
            raise OprfError("OPRF response must include evaluated")
        evaluated = oprf.point(base64url_decode(evaluated_value, length=32))
        output = (~blind) * evaluated
    except Exception as error:
        if isinstance(error, OprfError):
            raise
        raise OprfError("OPRF token derivation failed") from error
    return format_device_binding_token(bytes(output))
