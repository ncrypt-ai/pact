"""Machine-readable permissions for PACT manifests."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit


class PolicyError(ValueError):
    """Raised when a policy is invalid."""


class PermissionValue(StrEnum):
    """A claimant's permission for a specific use."""

    ALLOWED = "allowed"
    NOT_ALLOWED = "not_allowed"
    CONSTRAINED = "constrained"

    @property
    def cawg_value(self) -> str:
        """CAWG wire spelling for this permission value."""

        if self is PermissionValue.NOT_ALLOWED:
            return "notAllowed"
        return self.value


class Permission(StrEnum):
    """Standard CAWG permissions and PACT-specific extensions."""

    DATA_MINING = "cawg.data_mining"
    AI_INFERENCE = "cawg.ai_inference"
    GENERATIVE_TRAINING = "cawg.ai_generative_training"
    NON_GENERATIVE_TRAINING = "cawg.ai_training"
    COMMERCIAL_TRAINING = "pact.commercial_training"
    NO_COMMERCIAL_TRAINING = "pact.no_commercial_training"
    NONCOMMERCIAL_TRAINING = "pact.noncommercial_training"
    FINE_TUNING = "pact.fine_tuning"
    EMBEDDING = "pact.embedding"
    MODEL_EVALUATION = "pact.model_evaluation"
    SYNTHETIC_DATA = "pact.synthetic_data"
    SEARCH_INDEXING = "pact.search_indexing"
    REDISTRIBUTION = "pact.redistribution"


def _validate_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PolicyError("licensing_url must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise PolicyError("licensing_url must not contain credentials")
    return value


@dataclass(frozen=True, slots=True)
class PolicyEntry:
    """A permission decision and its optional conditions."""

    permission: Permission
    value: PermissionValue
    explanation: str | None = None
    licensing_url: str | None = None

    def __post_init__(self) -> None:
        if self.value is PermissionValue.CONSTRAINED and not self.explanation:
            raise PolicyError("constrained permissions require an explanation")
        if self.explanation is not None and not self.explanation.strip():
            raise PolicyError("explanation must not be blank")
        if self.licensing_url is not None:
            _validate_url(self.licensing_url)

    def to_dict(self) -> dict[str, str]:
        """Serialize one CAWG-compatible permission entry."""

        result = {"use": self.value.cawg_value}
        if self.explanation is not None:
            result["constraint_info"] = self.explanation
        if self.licensing_url is not None:
            result["licensing_url"] = self.licensing_url
        return result

    @classmethod
    def from_dict(
        cls,
        permission: Permission,
        value: Mapping[str, object],
    ) -> "PolicyEntry":
        """Load one permission entry from manifest data."""

        unexpected = set(value) - {"use", "constraint_info", "licensing_url"}
        if unexpected:
            raise PolicyError(
                f"unsupported policy entry fields: {sorted(unexpected)}"
            )
        use = value.get("use")
        if use == "notAllowed":
            use = PermissionValue.NOT_ALLOWED.value
        try:
            permission_value = PermissionValue(use)
        except (TypeError, ValueError) as error:
            raise PolicyError(
                "policy entry has an invalid use value"
            ) from error

        explanation = value.get("constraint_info")
        licensing_url = value.get("licensing_url")
        if explanation is not None and not isinstance(explanation, str):
            raise PolicyError("constraint_info must be a string")
        if licensing_url is not None and not isinstance(licensing_url, str):
            raise PolicyError("licensing_url must be a string")
        return cls(permission, permission_value, explanation, licensing_url)


@dataclass(frozen=True, slots=True)
class Policy:
    """A nonempty collection containing one entry per permission."""

    entries: tuple[PolicyEntry, ...]

    def __post_init__(self) -> None:
        if not self.entries:
            raise PolicyError("a policy must contain at least one entry")
        permissions = [entry.permission for entry in self.entries]
        if len(set(permissions)) != len(permissions):
            raise PolicyError("a policy cannot repeat a permission")

    def to_dict(self) -> dict[str, dict[str, str]]:
        """Serialize the CAWG training-mining entries map."""

        return {
            entry.permission.value: entry.to_dict() for entry in self.entries
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "Policy":
        """Load and validate manifest policy entries."""

        entries: list[PolicyEntry] = []
        for raw_permission, raw_entry in value.items():
            try:
                permission = Permission(raw_permission)
            except ValueError as error:
                raise PolicyError(
                    f"unsupported permission: {raw_permission}"
                ) from error
            if not isinstance(raw_entry, Mapping):
                raise PolicyError("policy entries must be objects")
            entry_value = cast(Mapping[str, object], raw_entry)
            entries.append(PolicyEntry.from_dict(permission, entry_value))
        return cls(tuple(entries))
