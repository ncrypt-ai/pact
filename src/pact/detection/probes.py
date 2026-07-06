"""Local probe generation for training-use evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import UUID, uuid5

from pact.canonical import canonical_json
from pact.crypto import base64url_encode

_PROBE_NAMESPACE = UUID("018f7f79-7b42-7c00-9000-000000000001")
_WHITESPACE = re.compile(r"\s+")


class ProbeKind(StrEnum):
    """Probe group used for protected and comparison material."""

    TREATMENT = "treatment"
    CONTROL = "control"


@dataclass(frozen=True, slots=True)
class Probe:
    """One locally generated prompt and its withheld expected continuation."""

    probe_id: str
    kind: ProbeKind
    prompt: str
    expected_continuation: str
    source_digest: str
    claim_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the prompt and withheld continuation."""

        result: dict[str, object] = {
            "probe_id": self.probe_id,
            "kind": self.kind.value,
            "prompt": self.prompt,
            "expected_continuation": self.expected_continuation,
            "source_digest": self.source_digest,
        }
        if self.claim_id is not None:
            result["claim_id"] = self.claim_id
        return result

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> Probe:
        """Load one probe from exported data."""

        return cls(
            probe_id=_required_string(value, "probe_id"),
            kind=ProbeKind(_required_string(value, "kind")),
            prompt=_required_string(value, "prompt"),
            expected_continuation=_required_string(
                value,
                "expected_continuation",
            ),
            source_digest=_required_string(value, "source_digest"),
            claim_id=_optional_string(value, "claim_id"),
        )


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    """One provider response imported for local analysis."""

    probe_id: str
    response: str
    provider: str | None = None
    model: str | None = None
    observed_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize a collected model response."""

        result: dict[str, object] = {
            "probe_id": self.probe_id,
            "response": self.response,
        }
        if self.provider is not None:
            result["provider"] = self.provider
        if self.model is not None:
            result["model"] = self.model
        if self.observed_at is not None:
            result["observed_at"] = self.observed_at
        return result

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ProbeResponse:
        """Load a provider response from exported data."""

        return cls(
            probe_id=_required_string(value, "probe_id"),
            response=_required_string(value, "response"),
            provider=_optional_string(value, "provider"),
            model=_optional_string(value, "model"),
            observed_at=_optional_string(value, "observed_at"),
        )


@dataclass(frozen=True, slots=True)
class ProbeSet:
    """A committed local probe plan generated before collecting responses."""

    target_model: str
    created_at: str
    probes: tuple[Probe, ...]
    commitment: str
    analysis_plan: str = "pact.local-probe-analysis.v1"

    def to_dict(self) -> dict[str, object]:
        """Serialize the committed probe plan."""

        return {
            "target_model": self.target_model,
            "created_at": self.created_at,
            "analysis_plan": self.analysis_plan,
            "commitment": self.commitment,
            "probes": [probe.to_dict() for probe in self.probes],
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ProbeSet:
        """Load a probe plan and verify its commitment."""

        probes_value = value.get("probes")
        if not isinstance(probes_value, list):
            raise ValueError("probes must be an array")
        probes = tuple(
            Probe.from_dict(_required_object(item, "probe"))
            for item in probes_value
        )
        result = cls(
            target_model=_required_string(value, "target_model"),
            created_at=_required_string(value, "created_at"),
            analysis_plan=_required_string(value, "analysis_plan"),
            commitment=_required_string(value, "commitment"),
            probes=probes,
        )
        if result.commitment != result.compute_commitment():
            raise ValueError("probe set commitment does not match")
        return result

    def commitment_payload(self) -> dict[str, object]:
        """The payload committed before response collection."""

        return {
            "target_model": self.target_model,
            "created_at": self.created_at,
            "analysis_plan": self.analysis_plan,
            "probes": [probe.to_dict() for probe in self.probes],
        }

    def compute_commitment(self) -> str:
        """Base64url SHA-256 commitment for this probe plan."""

        digest = hashlib.sha256(
            canonical_json(self.commitment_payload())
        ).digest()
        return base64url_encode(digest)


def create_probe_set(
    *,
    protected_texts: tuple[str, ...],
    control_texts: tuple[str, ...],
    target_model: str,
    claim_id: str | None = None,
    created_at: datetime | None = None,
    prefix_chars: int = 160,
    withheld_chars: int = 220,
) -> ProbeSet:
    """Create protected and comparison probes with withheld continuations."""

    timestamp = (created_at or datetime.now(UTC)).replace(microsecond=0)
    probes: list[Probe] = []
    for index, text in enumerate(protected_texts):
        probes.append(
            _make_probe(
                text,
                kind=ProbeKind.TREATMENT,
                target_model=target_model,
                index=index,
                claim_id=claim_id,
                prefix_chars=prefix_chars,
                withheld_chars=withheld_chars,
            )
        )
    for index, text in enumerate(control_texts):
        probes.append(
            _make_probe(
                text,
                kind=ProbeKind.CONTROL,
                target_model=target_model,
                index=index,
                claim_id=None,
                prefix_chars=prefix_chars,
                withheld_chars=withheld_chars,
            )
        )
    if not any(probe.kind is ProbeKind.TREATMENT for probe in probes):
        raise ValueError("at least one treatment probe is required")
    if not any(probe.kind is ProbeKind.CONTROL for probe in probes):
        raise ValueError("at least one control probe is required")
    result = ProbeSet(
        target_model=target_model,
        created_at=timestamp.isoformat(),
        probes=tuple(probes),
        commitment="",
    )
    return ProbeSet(
        target_model=result.target_model,
        created_at=result.created_at,
        analysis_plan=result.analysis_plan,
        probes=result.probes,
        commitment=result.compute_commitment(),
    )


def responses_from_jsonl(value: str) -> tuple[ProbeResponse, ...]:
    """Parse provider responses from JSON Lines."""

    responses = []
    for line_number, line in enumerate(value.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parsed = json.loads(stripped)
        if not isinstance(parsed, dict):
            raise ValueError(f"response line {line_number} must be an object")
        responses.append(ProbeResponse.from_dict(parsed))
    return tuple(responses)


def _make_probe(
    text: str,
    *,
    kind: ProbeKind,
    target_model: str,
    index: int,
    claim_id: str | None,
    prefix_chars: int,
    withheld_chars: int,
) -> Probe:
    normalized = _normalize_text(text)
    prefix, expected = _split_probe_text(
        normalized,
        prefix_chars=prefix_chars,
        withheld_chars=withheld_chars,
    )
    source_digest = base64url_encode(
        hashlib.sha256(normalized.encode()).digest()
    )
    probe_id = str(
        uuid5(
            _PROBE_NAMESPACE,
            "|".join((target_model, kind.value, str(index), source_digest)),
        )
    )
    return Probe(
        probe_id=probe_id,
        kind=kind,
        prompt=(
            "A document begins with this excerpt:\n\n"
            f"{prefix}\n\n"
            "If you know the source, quote only what follows. "
            "If you do not know, say exactly: I do not know."
        ),
        expected_continuation=expected,
        source_digest=source_digest,
        claim_id=claim_id,
    )


def _split_probe_text(
    text: str,
    *,
    prefix_chars: int,
    withheld_chars: int,
) -> tuple[str, str]:
    if len(text) < 80:
        raise ValueError(
            "probe source text must contain at least 80 characters"
        )
    prefix_length = min(max(40, prefix_chars), max(40, len(text) // 2))
    expected_start = prefix_length
    expected_end = min(len(text), expected_start + max(20, withheld_chars))
    return text[:prefix_length].strip(), text[
        expected_start:expected_end
    ].strip()


def _normalize_text(value: str) -> str:
    return _WHITESPACE.sub(" ", value).strip()


def _required_string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a nonempty string")
    return item


def _required_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _optional_string(value: dict[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a nonempty string")
    return item
