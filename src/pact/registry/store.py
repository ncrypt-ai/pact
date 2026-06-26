"""Append-only registry event persistence and batch hashing."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Self, cast
from uuid import UUID, uuid4

from pact.canonical import JsonValue, canonical_json
from pact.crypto import base64url_encode


class RegistryStoreError(RuntimeError):
    """Raised when registry persistence data is malformed or unavailable."""


class RegistryEventType(StrEnum):
    """Event types stored in the append-only registry log."""

    PROFILE_REGISTERED = "profile_registered"
    CERTIFICATE_ISSUED = "certificate_issued"
    CLAIM_REGISTERED = "claim_registered"
    KEY_ROTATED = "key_rotated"
    CLAIM_REVOKED = "claim_revoked"
    DOMAIN_VERIFIED = "domain_verified"
    DISPUTE_OPENED = "dispute_opened"
    DISPUTE_RESOLVED = "dispute_resolved"


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _isoformat(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat()


def _parse_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise RegistryStoreError(f"{label} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RegistryStoreError(
            f"{label} must be a valid ISO 8601 string"
        ) from error
    if parsed.tzinfo is None:
        raise RegistryStoreError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _merkle_parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> str:
    """Return the SHA-256 Merkle root for the provided leaf payloads."""

    if not leaves:
        raise RegistryStoreError(
            "cannot compute a Merkle root for zero leaves"
        )
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_merkle_parent(left, right))
        level = next_level
    return base64url_encode(level[0])


@dataclass(frozen=True, slots=True)
class RegistryEvent:
    """One append-only registry mutation event."""

    sequence: int
    event_id: UUID
    event_type: RegistryEventType
    occurred_at: datetime
    actor_key_id: str | None
    data: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible event payload."""

        return {
            "sequence": self.sequence,
            "event_id": str(self.event_id),
            "event_type": self.event_type.value,
            "occurred_at": _isoformat(self.occurred_at),
            "actor_key_id": self.actor_key_id,
            "data": self.data,
        }

    def canonical_bytes(self) -> bytes:
        """Return the canonical bytes covered by batch hashing."""

        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> Self:
        """Parse a persisted event."""

        try:
            sequence = value["sequence"]
            event_id = value["event_id"]
            event_type = value["event_type"]
            actor_key_id = value.get("actor_key_id")
            data = value["data"]
        except KeyError as error:
            raise RegistryStoreError(
                "registry event is missing required fields"
            ) from error
        if not isinstance(sequence, int) or sequence < 1:
            raise RegistryStoreError(
                "event sequence must be a positive integer"
            )
        if not isinstance(event_id, str):
            raise RegistryStoreError("event_id must be a string")
        if not isinstance(event_type, str):
            raise RegistryStoreError("event_type must be a string")
        if actor_key_id is not None and not isinstance(actor_key_id, str):
            raise RegistryStoreError("actor_key_id must be a string or null")
        if not isinstance(data, dict):
            raise RegistryStoreError("event data must be an object")
        return cls(
            sequence=sequence,
            event_id=UUID(event_id),
            event_type=RegistryEventType(event_type),
            occurred_at=_parse_datetime(
                value.get("occurred_at"), "occurred_at"
            ),
            actor_key_id=actor_key_id,
            data=cast(dict[str, object], data),
        )


@dataclass(frozen=True, slots=True)
class RegistryBatch:
    """A signed-time batching unit for append-only event disclosure."""

    batch_id: UUID
    first_sequence: int
    last_sequence: int
    event_ids: tuple[str, ...]
    merkle_root: str
    created_at: datetime

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible batch payload."""

        return {
            "batch_id": str(self.batch_id),
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "event_ids": list(self.event_ids),
            "merkle_root": self.merkle_root,
            "created_at": _isoformat(self.created_at),
        }

    @classmethod
    def from_events(cls, events: list[RegistryEvent]) -> Self:
        """Create a batch from one or more ordered events."""

        if not events:
            raise RegistryStoreError("cannot create a batch with zero events")
        return cls(
            batch_id=uuid4(),
            first_sequence=events[0].sequence,
            last_sequence=events[-1].sequence,
            event_ids=tuple(str(event.event_id) for event in events),
            merkle_root=merkle_root(
                [event.canonical_bytes() for event in events]
            ),
            created_at=_utc_now(),
        )

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> Self:
        """Parse a persisted batch."""

        try:
            batch_id = value["batch_id"]
            first_sequence = value["first_sequence"]
            last_sequence = value["last_sequence"]
            event_ids = value["event_ids"]
            merkle_root_value = value["merkle_root"]
        except KeyError as error:
            raise RegistryStoreError(
                "registry batch is missing required fields"
            ) from error
        if not isinstance(batch_id, str):
            raise RegistryStoreError("batch_id must be a string")
        if not isinstance(first_sequence, int) or first_sequence < 1:
            raise RegistryStoreError(
                "first_sequence must be a positive integer"
            )
        if (
            not isinstance(last_sequence, int)
            or last_sequence < first_sequence
        ):
            raise RegistryStoreError("last_sequence must be >= first_sequence")
        if not isinstance(event_ids, list) or any(
            not isinstance(item, str) for item in event_ids
        ):
            raise RegistryStoreError("event_ids must be an array of strings")
        if not isinstance(merkle_root_value, str):
            raise RegistryStoreError("merkle_root must be a string")
        return cls(
            batch_id=UUID(batch_id),
            first_sequence=first_sequence,
            last_sequence=last_sequence,
            event_ids=tuple(cast(list[str], event_ids)),
            merkle_root=merkle_root_value,
            created_at=_parse_datetime(value.get("created_at"), "created_at"),
        )


class FileRegistryStore:
    """Append-only JSONL-backed persistence for registry events and batches."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.events_path = directory / "events.jsonl"
        self.batches_path = directory / "batches.jsonl"

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

    def _append_jsonl(self, path: Path, value: JsonValue) -> None:
        self._ensure_directory()
        with path.open("ab") as handle:
            handle.write(canonical_json(value))
            handle.write(b"\n")

    def list_events(self) -> tuple[RegistryEvent, ...]:
        """Load every persisted event in order."""

        if not self.events_path.exists():
            return ()
        result: list[RegistryEvent] = []
        for line in self.events_path.read_bytes().splitlines():
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as error:
                raise RegistryStoreError(
                    "registry event log contains invalid JSON"
                ) from error
            if not isinstance(parsed, dict):
                raise RegistryStoreError(
                    "registry event log entries must be objects"
                )
            result.append(RegistryEvent.from_dict(parsed))
        return tuple(result)

    def list_batches(self) -> tuple[RegistryBatch, ...]:
        """Load every persisted batch in order."""

        if not self.batches_path.exists():
            return ()
        result: list[RegistryBatch] = []
        for line in self.batches_path.read_bytes().splitlines():
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as error:
                raise RegistryStoreError(
                    "registry batch log contains invalid JSON"
                ) from error
            if not isinstance(parsed, dict):
                raise RegistryStoreError(
                    "registry batch log entries must be objects"
                )
            result.append(RegistryBatch.from_dict(parsed))
        return tuple(result)

    def append(
        self,
        event_type: RegistryEventType,
        actor_key_id: str | None,
        data: dict[str, object],
    ) -> RegistryEvent:
        """Append one event and one disclosure batch."""

        next_sequence = len(self.list_events()) + 1
        event = RegistryEvent(
            sequence=next_sequence,
            event_id=uuid4(),
            event_type=event_type,
            occurred_at=_utc_now(),
            actor_key_id=actor_key_id,
            data=data,
        )
        self._append_jsonl(
            self.events_path,
            event.to_dict(),
        )
        batch = RegistryBatch.from_events([event])
        self._append_jsonl(
            self.batches_path,
            batch.to_dict(),
        )
        return event
