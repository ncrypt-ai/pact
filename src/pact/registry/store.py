"""Append-only registry event persistence and batch hashing."""

import hashlib
import importlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, Self, cast
from uuid import UUID, uuid4

from pact.canonical import JsonValue, canonical_json
from pact.crypto import base64url_encode


class RegistryStoreError(RuntimeError):
    """Raised when registry persistence data is malformed or unavailable."""


class RegistryEventType(StrEnum):
    """Event types stored in the append-only registry log."""

    PROFILE_REGISTERED = "profile_registered"
    PROFILE_UPDATED = "profile_updated"
    CERTIFICATE_ISSUED = "certificate_issued"
    CLAIM_REGISTERED = "claim_registered"
    KEY_ROTATED = "key_rotated"
    CLAIM_REVOKED = "claim_revoked"
    DOMAIN_VERIFIED = "domain_verified"
    ACCOUNT_AUTHORIZED = "account_authorized"
    DISPUTE_OPENED = "dispute_opened"
    DISPUTE_RESOLVED = "dispute_resolved"
    LOOKUP_SIGNALS_REGISTERED = "lookup_signals_registered"
    AVOIDANCE_REPORT_SUBMITTED = "avoidance_report_submitted"
    AVOIDANCE_REPORT_TRIAGED = "avoidance_report_triaged"
    AVOIDANCE_REPORT_OWNER_CONFIRMED = "avoidance_report_owner_confirmed"
    AVOIDANCE_REPORT_REJECTED = "avoidance_report_rejected"
    AVOIDANCE_REPORT_PUBLICLY_LISTED = "avoidance_report_publicly_listed"


class RegistryStore(Protocol):
    """Persistence interface required by the registry service."""

    def list_events(self) -> tuple["RegistryEvent", ...]:
        """Load every persisted event in order."""
        ...

    def list_batches(self) -> tuple["RegistryBatch", ...]:
        """Load every persisted batch in order."""
        ...

    def latest_sequence(self) -> int:
        """Return the highest persisted registry event sequence."""
        ...

    def append(
        self,
        event_type: RegistryEventType,
        actor_key_id: str | None,
        data: dict[str, object],
    ) -> "RegistryEvent":
        """Append one event and its disclosure batch."""
        ...

    def save_challenge(
        self,
        *,
        challenge_id: UUID,
        expires_at: datetime,
        challenge: dict[str, object],
    ) -> None:
        """Persist a short-lived, one-use mutation challenge."""
        ...

    def take_challenge(
        self,
        challenge_id: UUID,
    ) -> dict[str, object] | None:
        """Atomically load and consume a mutation challenge."""
        ...

    def purge_expired_challenges(self, now: datetime) -> int:
        """Remove expired unconsumed mutation challenges."""
        ...


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


def _parse_stored_json_object(
    payload: object, label: str
) -> dict[str, object]:
    if not isinstance(payload, str | bytes):
        raise RegistryStoreError(f"{label} payload is invalid")
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RegistryStoreError(f"{label} contains invalid JSON") from error
    if not isinstance(parsed, dict):
        raise RegistryStoreError(f"{label} entries must be objects")
    return cast(dict[str, object], parsed)


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


def _new_event_and_batch(
    *,
    sequence: int,
    event_type: RegistryEventType,
    actor_key_id: str | None,
    data: dict[str, object],
) -> tuple[RegistryEvent, RegistryBatch]:
    event = RegistryEvent(
        sequence=sequence,
        event_id=uuid4(),
        event_type=event_type,
        occurred_at=_utc_now(),
        actor_key_id=actor_key_id,
        data=data,
    )
    return event, RegistryBatch.from_events([event])


class FileRegistryStore:
    """Append-only JSONL-backed persistence for registry events and batches."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.events_path = directory / "events.jsonl"
        self.batches_path = directory / "batches.jsonl"
        self.challenges_path = directory / "challenges"

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

    def _ensure_challenges_directory(self) -> None:
        self.challenges_path.mkdir(parents=True, exist_ok=True)

    def _append_jsonl(self, path: Path, value: JsonValue) -> None:
        self._ensure_directory()
        with path.open("ab") as handle:
            handle.write(canonical_json(value))
            handle.write(b"\n")

    def _challenge_path(self, challenge_id: UUID) -> Path:
        return self.challenges_path / f"{challenge_id}.json"

    def list_events(self) -> tuple[RegistryEvent, ...]:
        """Load every persisted event in order."""

        if not self.events_path.exists():
            return ()
        result: list[RegistryEvent] = []
        for line in self.events_path.read_bytes().splitlines():
            if not line:
                continue
            parsed = _parse_stored_json_object(line, "registry event log")
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
            parsed = _parse_stored_json_object(line, "registry batch log")
            result.append(RegistryBatch.from_dict(parsed))
        return tuple(result)

    def latest_sequence(self) -> int:
        """Return the highest persisted registry event sequence."""

        events = self.list_events()
        if not events:
            return 0
        return events[-1].sequence

    def append(
        self,
        event_type: RegistryEventType,
        actor_key_id: str | None,
        data: dict[str, object],
    ) -> RegistryEvent:
        """Append one event and one disclosure batch."""

        next_sequence = len(self.list_events()) + 1
        event, batch = _new_event_and_batch(
            sequence=next_sequence,
            event_type=event_type,
            actor_key_id=actor_key_id,
            data=data,
        )
        self._append_jsonl(
            self.events_path,
            event.to_dict(),
        )
        self._append_jsonl(
            self.batches_path,
            batch.to_dict(),
        )
        return event

    def save_challenge(
        self,
        *,
        challenge_id: UUID,
        expires_at: datetime,
        challenge: dict[str, object],
    ) -> None:
        """Persist a short-lived, one-use mutation challenge."""

        self._ensure_challenges_directory()
        path = self._challenge_path(challenge_id)
        temporary_path = path.with_name(f"{path.name}.{uuid4()}.tmp")
        temporary_path.write_bytes(canonical_json(cast(JsonValue, challenge)))
        temporary_path.replace(path)

    def take_challenge(
        self,
        challenge_id: UUID,
    ) -> dict[str, object] | None:
        """Atomically load and consume a mutation challenge."""

        path = self._challenge_path(challenge_id)
        claimed_path = path.with_name(f"{path.name}.{uuid4()}.claimed")
        try:
            path.rename(claimed_path)
        except FileNotFoundError:
            return None

        try:
            return _parse_stored_json_object(
                claimed_path.read_bytes(),
                "file registry challenge",
            )
        finally:
            claimed_path.unlink(missing_ok=True)

    def purge_expired_challenges(self, now: datetime) -> int:
        """Remove expired unconsumed mutation challenges."""

        if not self.challenges_path.exists():
            return 0

        removed = 0
        for path in self.challenges_path.glob("*.json"):
            try:
                challenge = _parse_stored_json_object(
                    path.read_bytes(),
                    "file registry challenge",
                )
                expires_at = _parse_datetime(
                    challenge.get("expires_at"),
                    "expires_at",
                )
            except (FileNotFoundError, RegistryStoreError):
                continue
            if expires_at < now:
                try:
                    path.unlink()
                except FileNotFoundError:
                    continue
                removed += 1
        return removed


class SqliteRegistryStore:
    """SQLite-backed registry persistence for monolith deployments."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self.database = str(database)
        self._lock = threading.Lock()
        self.connection = sqlite3.connect(
            self.database,
            check_same_thread=False,
        )
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS registry_events (
                sequence INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_batches (
                batch_id TEXT PRIMARY KEY,
                first_sequence INTEGER NOT NULL,
                last_sequence INTEGER NOT NULL,
                batch_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_challenges (
                challenge_id TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                challenge_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_registry_challenges_expires_at
                ON registry_challenges(expires_at);
            """
        )
        self.connection.commit()

    def _load_json_rows(
        self,
        query: str,
    ) -> list[dict[str, object]]:
        rows = self.connection.execute(query).fetchall()
        result: list[dict[str, object]] = []
        for (payload,) in rows:
            result.append(
                _parse_stored_json_object(payload, "SQLite registry")
            )
        return result

    def list_events(self) -> tuple[RegistryEvent, ...]:
        """Load every persisted event in order."""

        return tuple(
            RegistryEvent.from_dict(item)
            for item in self._load_json_rows(
                "SELECT event_json FROM registry_events ORDER BY sequence"
            )
        )

    def list_batches(self) -> tuple[RegistryBatch, ...]:
        """Load every persisted batch in order."""

        return tuple(
            RegistryBatch.from_dict(item)
            for item in self._load_json_rows(
                "SELECT batch_json FROM registry_batches ORDER BY first_sequence"
            )
        )

    def latest_sequence(self) -> int:
        """Return the highest persisted registry event sequence."""

        row = self.connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM registry_events"
        ).fetchone()
        return int(row[0])

    def append(
        self,
        event_type: RegistryEventType,
        actor_key_id: str | None,
        data: dict[str, object],
    ) -> RegistryEvent:
        """Append one event and one disclosure batch."""

        with self._lock:
            row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM registry_events"
            ).fetchone()
            next_sequence = int(row[0])
            event, batch = _new_event_and_batch(
                sequence=next_sequence,
                event_type=event_type,
                actor_key_id=actor_key_id,
                data=data,
            )
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO registry_events(sequence, event_id, event_json)
                    VALUES (?, ?, ?)
                    """,
                    (
                        event.sequence,
                        str(event.event_id),
                        canonical_json(event.to_dict()).decode("utf-8"),
                    ),
                )
                self.connection.execute(
                    """
                    INSERT INTO registry_batches(
                        batch_id,
                        first_sequence,
                        last_sequence,
                        batch_json
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(batch.batch_id),
                        batch.first_sequence,
                        batch.last_sequence,
                        canonical_json(batch.to_dict()).decode("utf-8"),
                    ),
                )
            return event

    def save_challenge(
        self,
        *,
        challenge_id: UUID,
        expires_at: datetime,
        challenge: dict[str, object],
    ) -> None:
        """Persist a short-lived, one-use mutation challenge."""

        with self.connection:
            self.connection.execute(
                """
                INSERT OR REPLACE INTO registry_challenges(
                    challenge_id,
                    expires_at,
                    challenge_json
                )
                VALUES (?, ?, ?)
                """,
                (
                    str(challenge_id),
                    _isoformat(expires_at),
                    canonical_json(cast(JsonValue, challenge)).decode("utf-8"),
                ),
            )

    def take_challenge(
        self,
        challenge_id: UUID,
    ) -> dict[str, object] | None:
        """Atomically load and consume a mutation challenge."""

        row = self.connection.execute(
            """
            DELETE FROM registry_challenges
            WHERE challenge_id = ?
            RETURNING challenge_json
            """,
            (str(challenge_id),),
        ).fetchone()
        self.connection.commit()

        if row is None:
            return None

        return _parse_stored_json_object(row[0], "SQLite registry challenge")

    def purge_expired_challenges(self, now: datetime) -> int:
        """Remove expired unconsumed mutation challenges."""

        with self.connection:
            cursor = self.connection.execute(
                "DELETE FROM registry_challenges WHERE expires_at < ?",
                (_isoformat(now),),
            )

        return cursor.rowcount


class PostgresRegistryStore:
    """Postgres-backed registry persistence for serverless deployments."""

    def __init__(self, dsn: str) -> None:
        try:
            psycopg = importlib.import_module("psycopg")
        except ImportError as error:
            raise RegistryStoreError(
                "Postgres storage requires the pact[aws] optional dependencies"
            ) from error
        self._psycopg = cast(Any, psycopg)
        self.connection = psycopg.connect(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.connection.execute(
            "CREATE SEQUENCE IF NOT EXISTS registry_event_sequence"
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS registry_events (
                sequence BIGINT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS registry_batches (
                batch_id TEXT PRIMARY KEY,
                first_sequence BIGINT NOT NULL,
                last_sequence BIGINT NOT NULL,
                batch_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS registry_challenges (
                challenge_id TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                challenge_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_registry_challenges_expires_at
                ON registry_challenges(expires_at)
            """
        )
        self.connection.execute(
            """
            SELECT setval(
                'registry_event_sequence',
                GREATEST(
                    COALESCE((SELECT MAX(sequence) FROM registry_events), 0)
                    + 1,
                    1
                ),
                false
            )
            """
        )
        self.connection.commit()

    def _load_json_rows(self, query: str) -> list[dict[str, object]]:
        rows = self.connection.execute(query).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            result.append(
                _parse_stored_json_object(row[0], "Postgres registry")
            )
        return result

    def list_events(self) -> tuple[RegistryEvent, ...]:
        """Load every persisted event in order."""

        return tuple(
            RegistryEvent.from_dict(item)
            for item in self._load_json_rows(
                "SELECT event_json FROM registry_events ORDER BY sequence"
            )
        )

    def list_batches(self) -> tuple[RegistryBatch, ...]:
        """Load every persisted batch in order."""

        return tuple(
            RegistryBatch.from_dict(item)
            for item in self._load_json_rows(
                "SELECT batch_json FROM registry_batches ORDER BY first_sequence"
            )
        )

    def latest_sequence(self) -> int:
        """Return the highest persisted registry event sequence."""

        row = self.connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM registry_events"
        ).fetchone()
        return int(row[0])

    def append(
        self,
        event_type: RegistryEventType,
        actor_key_id: str | None,
        data: dict[str, object],
    ) -> RegistryEvent:
        """Append one event and one disclosure batch."""

        row = self.connection.execute(
            "SELECT nextval('registry_event_sequence')"
        ).fetchone()
        if row is None:
            raise RegistryStoreError(
                "Postgres sequence query returned no rows"
            )
        next_sequence = int(row[0])
        event, batch = _new_event_and_batch(
            sequence=next_sequence,
            event_type=event_type,
            actor_key_id=actor_key_id,
            data=data,
        )
        try:
            self.connection.execute(
                """
                INSERT INTO registry_events(sequence, event_id, event_json)
                VALUES (%s, %s, %s)
                """,
                (
                    event.sequence,
                    str(event.event_id),
                    canonical_json(event.to_dict()).decode("utf-8"),
                ),
            )
            self.connection.execute(
                """
                INSERT INTO registry_batches(
                    batch_id,
                    first_sequence,
                    last_sequence,
                    batch_json
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    str(batch.batch_id),
                    batch.first_sequence,
                    batch.last_sequence,
                    canonical_json(batch.to_dict()).decode("utf-8"),
                ),
            )
        except Exception:
            self.connection.rollback()
            raise
        self.connection.commit()
        return event

    def save_challenge(
        self,
        *,
        challenge_id: UUID,
        expires_at: datetime,
        challenge: dict[str, object],
    ) -> None:
        """Persist a short-lived, one-use mutation challenge."""

        try:
            self.connection.execute(
                """
                INSERT INTO registry_challenges(
                    challenge_id,
                    expires_at,
                    challenge_json
                )
                VALUES (%s, %s, %s)
                ON CONFLICT (challenge_id) DO UPDATE SET
                    expires_at = EXCLUDED.expires_at,
                    challenge_json = EXCLUDED.challenge_json
                """,
                (
                    str(challenge_id),
                    _isoformat(expires_at),
                    canonical_json(cast(JsonValue, challenge)).decode("utf-8"),
                ),
            )
        except Exception:
            self.connection.rollback()
            raise
        self.connection.commit()

    def take_challenge(
        self,
        challenge_id: UUID,
    ) -> dict[str, object] | None:
        """Atomically load and consume a mutation challenge."""

        try:
            row = self.connection.execute(
                """
                DELETE FROM registry_challenges
                WHERE challenge_id = %s
                RETURNING challenge_json
                """,
                (str(challenge_id),),
            ).fetchone()
        except Exception:
            self.connection.rollback()
            raise
        self.connection.commit()

        if row is None:
            return None

        return _parse_stored_json_object(row[0], "Postgres registry challenge")

    def purge_expired_challenges(self, now: datetime) -> int:
        """Remove expired unconsumed mutation challenges."""

        try:
            cursor = self.connection.execute(
                "DELETE FROM registry_challenges WHERE expires_at < %s",
                (_isoformat(now),),
            )
        except Exception:
            self.connection.rollback()
            raise
        self.connection.commit()
        return int(cursor.rowcount)
