from collections.abc import Callable

import pytest

from pact.policy import (
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    PolicyError,
)


def test_policy_round_trip_uses_cawg_wire_values() -> None:
    policy = Policy(
        (
            PolicyEntry(Permission.DATA_MINING, PermissionValue.ALLOWED),
            PolicyEntry(
                Permission.GENERATIVE_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
            PolicyEntry(
                Permission.COMMERCIAL_TRAINING,
                PermissionValue.CONSTRAINED,
                "Contact the claimant for a license.",
                "https://example.com/license",
            ),
            PolicyEntry(
                Permission.NO_COMMERCIAL_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
        )
    )

    wire_value = policy.to_dict()

    assert wire_value["cawg.ai_generative_training"] == {"use": "notAllowed"}
    assert wire_value["pact.no_commercial_training"] == {"use": "notAllowed"}
    assert Policy.from_dict(wire_value) == policy


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (
            lambda: PolicyEntry(
                Permission.FINE_TUNING,
                PermissionValue.CONSTRAINED,
            ),
            "require an explanation",
        ),
        (
            lambda: PolicyEntry(
                Permission.FINE_TUNING,
                PermissionValue.ALLOWED,
                "  ",
            ),
            "must not be blank",
        ),
        (
            lambda: PolicyEntry(
                Permission.FINE_TUNING,
                PermissionValue.ALLOWED,
                licensing_url="mailto:test@example.com",
            ),
            "absolute HTTP",
        ),
        (
            lambda: PolicyEntry(
                Permission.FINE_TUNING,
                PermissionValue.ALLOWED,
                licensing_url="https://user:pass@example.com/license",
            ),
            "must not contain credentials",
        ),
    ],
)
def test_invalid_policy_entries_are_rejected(
    entry: Callable[[], PolicyEntry],
    message: str,
) -> None:
    with pytest.raises(PolicyError, match=message):
        entry()


def test_policy_must_be_nonempty_and_unique() -> None:
    with pytest.raises(PolicyError, match="at least one"):
        Policy(())

    entry = PolicyEntry(Permission.DATA_MINING, PermissionValue.ALLOWED)
    with pytest.raises(PolicyError, match="repeat"):
        Policy((entry, entry))


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"unknown": {"use": "allowed"}}, "unsupported permission"),
        ({Permission.DATA_MINING.value: "allowed"}, "must be objects"),
        ({Permission.DATA_MINING.value: {"use": "sometimes"}}, "use value"),
        (
            {
                Permission.DATA_MINING.value: {
                    "use": "allowed",
                    "unknown": True,
                }
            },
            "unsupported policy entry fields",
        ),
        (
            {
                Permission.DATA_MINING.value: {
                    "use": "allowed",
                    "constraint_info": 1,
                }
            },
            "constraint_info",
        ),
        (
            {
                Permission.DATA_MINING.value: {
                    "use": "allowed",
                    "licensing_url": 1,
                }
            },
            "licensing_url",
        ),
    ],
)
def test_invalid_policy_wire_values_are_rejected(
    value: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(PolicyError, match=message):
        Policy.from_dict(value)
