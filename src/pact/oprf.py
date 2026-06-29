"""Small P-256 OPRF helpers for private registry-scoped device bindings."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping

from pact.crypto import base64url_decode, base64url_encode

# Public NIST P-256/secp256r1 domain parameters, not secret material.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_BASE_POINT = (P256_GX, P256_GY)

P256Point = tuple[int, int] | None
OprfEvaluator = Callable[[dict[str, str]], Mapping[str, object]]


class OprfError(ValueError):
    """Raised when OPRF point input or output is invalid."""


def _mod_inv(value: int, modulus: int) -> int:
    if value % modulus == 0:
        raise OprfError("zero has no modular inverse")
    return pow(value, -1, modulus)


def _is_on_curve(point: P256Point) -> bool:
    if point is None:
        return True
    x, y = point
    if not 0 <= x < P256_P or not 0 <= y < P256_P:
        return False
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def p256_point_add(left: P256Point, right: P256Point) -> P256Point:
    """Add two P-256 points."""

    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + P256_A) * _mod_inv(2 * y1, P256_P)
    else:
        slope = (y2 - y1) * _mod_inv(x2 - x1, P256_P)
    slope %= P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return x3, y3


def p256_point_mul(scalar: int, point: P256Point) -> P256Point:
    """Multiply a P-256 point by a scalar."""

    if scalar % P256_N == 0 or point is None:
        return None
    if not _is_on_curve(point):
        raise OprfError("point is not on P-256")
    result: P256Point = None
    addend = point
    scalar %= P256_N
    while scalar:
        if scalar & 1:
            result = p256_point_add(result, addend)
        addend = p256_point_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise OprfError("point multiplication produced infinity")
    return result


def p256_point_to_wire(point: P256Point) -> dict[str, str]:
    """Encode a non-infinity P-256 point as base64url x/y coordinates."""

    if point is None or not _is_on_curve(point):
        raise OprfError("invalid P-256 point")
    x, y = point
    return {
        "x": base64url_encode(x.to_bytes(32, "big")),
        "y": base64url_encode(y.to_bytes(32, "big")),
    }


def p256_point_from_wire(value: Mapping[str, object]) -> tuple[int, int]:
    """Decode and validate base64url x/y coordinates as a P-256 point."""

    try:
        x_value = value["x"]
        y_value = value["y"]
    except KeyError as error:
        raise OprfError("OPRF point is missing x or y") from error
    if not isinstance(x_value, str) or not isinstance(y_value, str):
        raise OprfError("OPRF point coordinates must be strings")
    try:
        x_bytes = base64url_decode(x_value)
        y_bytes = base64url_decode(y_value)
    except ValueError as error:
        raise OprfError("OPRF point coordinates must be base64url") from error
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise OprfError("OPRF point coordinates must be 32 bytes")
    point = (int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"))
    if not _is_on_curve(point):
        raise OprfError("OPRF point is not on P-256")
    return point


def _scalar_from_bytes(value: bytes) -> int:
    return int.from_bytes(value, "big") % (P256_N - 1) + 1


def device_binding_input(
    *,
    local_secret: bytes,
    registry_root_fingerprint: str,
    device_fingerprint: str,
) -> bytes:
    """Return HMAC(local_secret, registry_root_fingerprint || fingerprint)."""

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
) -> int:
    """Derive the registry's non-verifiable OPRF scalar."""

    digest = hmac.new(
        server_secret,
        b"PACT device binding OPRF server v1\0"
        + registry_url.encode("utf-8")
        + b"\0"
        + registry_root_fingerprint.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _scalar_from_bytes(digest)


def evaluate_device_oprf(
    blinded_point: Mapping[str, object],
    *,
    server_scalar: int,
) -> dict[str, str]:
    """Evaluate a blinded OPRF point."""

    point = p256_point_from_wire(blinded_point)
    evaluated = p256_point_mul(server_scalar, point)
    return p256_point_to_wire(evaluated)


def device_binding_oprf_token(
    *,
    local_input: bytes,
    evaluator: OprfEvaluator,
) -> str:
    """Return the final registry-scoped device binding token."""

    input_scalar = _scalar_from_bytes(hashlib.sha256(local_input).digest())
    blind = secrets.randbelow(P256_N - 1) + 1
    blinded = p256_point_mul(
        (input_scalar * blind) % P256_N,
        P256_BASE_POINT,
    )
    response = evaluator(p256_point_to_wire(blinded))
    evaluated = p256_point_from_wire(response)
    unblinded = p256_point_mul(_mod_inv(blind, P256_N), evaluated)
    if unblinded is None:
        raise OprfError("OPRF evaluation produced infinity")
    x, y = unblinded
    digest = hashlib.sha256(
        b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    ).digest()
    return f"pact-device-binding-v2.{base64url_encode(digest)}"
