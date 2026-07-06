"""Local statistical analysis for probe responses."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from pact.detection.probes import ProbeKind, ProbeResponse, ProbeSet

_TOKEN = re.compile(r"[A-Za-z0-9']+")


class ProbeConclusion(StrEnum):
    """Allowed local probe-analysis conclusions."""

    WATERMARK_SIGNAL_DETECTED = "watermark_signal_detected"
    STATISTICALLY_CONSISTENT = "statistically_consistent"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    """Confidence interval for one estimated rate or effect."""

    lower: float
    upper: float
    confidence_level: float = 0.95

    def to_dict(self) -> dict[str, float]:
        """Serialize the interval bounds."""

        return {
            "lower": self.lower,
            "upper": self.upper,
            "confidence_level": self.confidence_level,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ConfidenceInterval:
        """Load interval bounds from exported data."""

        return cls(
            lower=_required_float(value, "lower"),
            upper=_required_float(value, "upper"),
            confidence_level=_required_float(value, "confidence_level"),
        )


@dataclass(frozen=True, slots=True)
class HypothesisTest:
    """One hypothesis test and its corrected p-value."""

    name: str
    p_value: float | None
    adjusted_p_value: float | None

    def to_dict(self) -> dict[str, object]:
        """Serialize the hypothesis-test result."""

        return {
            "name": self.name,
            "p_value": self.p_value,
            "adjusted_p_value": self.adjusted_p_value,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> HypothesisTest:
        """Load a hypothesis-test result."""

        return cls(
            name=_required_string(value, "name"),
            p_value=_optional_float(value, "p_value"),
            adjusted_p_value=_optional_float(value, "adjusted_p_value"),
        )


@dataclass(frozen=True, slots=True)
class ProbeMeasurement:
    """One response scored against a probe's withheld continuation."""

    probe_id: str
    kind: ProbeKind
    matched: bool
    score: float
    longest_run: int
    exact_match: bool

    def to_dict(self) -> dict[str, object]:
        """Serialize one scored response."""

        return {
            "probe_id": self.probe_id,
            "kind": self.kind.value,
            "matched": self.matched,
            "score": self.score,
            "longest_run": self.longest_run,
            "exact_match": self.exact_match,
        }


@dataclass(frozen=True, slots=True)
class ProbeAnalysisReport:
    """Aggregate local statistics for protected and comparison probes."""

    treatment_count: int
    control_count: int
    treatment_matches: int
    control_matches: int
    treatment_rate: float
    control_rate: float
    effect_size: float
    z_score: float | None
    p_value: float | None
    adjusted_p_value: float | None
    correction_method: str
    treatment_rate_interval: ConfidenceInterval
    control_rate_interval: ConfidenceInterval
    effect_size_interval: ConfidenceInterval
    hypothesis_tests: tuple[HypothesisTest, ...]
    conclusion: ProbeConclusion
    measurements: tuple[ProbeMeasurement, ...]
    false_positive_threshold: float = 0.05

    def to_dict(self) -> dict[str, object]:
        """Serialize the aggregate probe analysis."""

        return {
            "treatment_count": self.treatment_count,
            "control_count": self.control_count,
            "treatment_matches": self.treatment_matches,
            "control_matches": self.control_matches,
            "treatment_rate": self.treatment_rate,
            "control_rate": self.control_rate,
            "effect_size": self.effect_size,
            "z_score": self.z_score,
            "p_value": self.p_value,
            "adjusted_p_value": self.adjusted_p_value,
            "correction_method": self.correction_method,
            "treatment_rate_interval": self.treatment_rate_interval.to_dict(),
            "control_rate_interval": self.control_rate_interval.to_dict(),
            "effect_size_interval": self.effect_size_interval.to_dict(),
            "hypothesis_tests": [
                item.to_dict() for item in self.hypothesis_tests
            ],
            "false_positive_threshold": self.false_positive_threshold,
            "conclusion": self.conclusion.value,
            "measurements": [item.to_dict() for item in self.measurements],
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> ProbeAnalysisReport:
        """Load aggregate probe analysis from exported data."""

        measurements_value = value.get("measurements")
        hypothesis_tests_value = value.get("hypothesis_tests")
        if not isinstance(measurements_value, list):
            raise ValueError("measurements must be an array")
        if not isinstance(hypothesis_tests_value, list):
            raise ValueError("hypothesis_tests must be an array")
        return cls(
            treatment_count=_required_int(value, "treatment_count"),
            control_count=_required_int(value, "control_count"),
            treatment_matches=_required_int(value, "treatment_matches"),
            control_matches=_required_int(value, "control_matches"),
            treatment_rate=_required_float(value, "treatment_rate"),
            control_rate=_required_float(value, "control_rate"),
            effect_size=_required_float(value, "effect_size"),
            z_score=_optional_float(value, "z_score"),
            p_value=_optional_float(value, "p_value"),
            adjusted_p_value=_optional_float(value, "adjusted_p_value"),
            correction_method=_required_string(value, "correction_method"),
            treatment_rate_interval=ConfidenceInterval.from_dict(
                _required_object(
                    value.get("treatment_rate_interval"),
                    "treatment_rate_interval",
                )
            ),
            control_rate_interval=ConfidenceInterval.from_dict(
                _required_object(
                    value.get("control_rate_interval"),
                    "control_rate_interval",
                )
            ),
            effect_size_interval=ConfidenceInterval.from_dict(
                _required_object(
                    value.get("effect_size_interval"),
                    "effect_size_interval",
                )
            ),
            hypothesis_tests=tuple(
                HypothesisTest.from_dict(
                    _required_object(item, "hypothesis_test")
                )
                for item in hypothesis_tests_value
            ),
            false_positive_threshold=_required_float(
                value,
                "false_positive_threshold",
            ),
            conclusion=ProbeConclusion(_required_string(value, "conclusion")),
            measurements=tuple(
                _measurement_from_dict(_required_object(item, "measurement"))
                for item in measurements_value
            ),
        )


def analyze_probe_responses(
    probe_set: ProbeSet,
    responses: tuple[ProbeResponse, ...],
    *,
    false_positive_threshold: float = 0.05,
) -> ProbeAnalysisReport:
    """Analyze imported responses against a committed probe set."""

    if not 0.0 < false_positive_threshold < 1.0:
        raise ValueError("false_positive_threshold must be between 0 and 1")
    response_by_probe = {response.probe_id: response for response in responses}
    measurements = tuple(
        _measure_response(
            probe_id=probe.probe_id,
            kind=probe.kind,
            expected=probe.expected_continuation,
            response=response_by_probe.get(probe.probe_id),
        )
        for probe in probe_set.probes
    )
    treatment = [
        item for item in measurements if item.kind is ProbeKind.TREATMENT
    ]
    control = [item for item in measurements if item.kind is ProbeKind.CONTROL]
    treatment_matches = sum(item.matched for item in treatment)
    control_matches = sum(item.matched for item in control)
    treatment_exact_matches = sum(item.exact_match for item in treatment)
    control_exact_matches = sum(item.exact_match for item in control)
    treatment_rate = treatment_matches / len(treatment) if treatment else 0.0
    control_rate = control_matches / len(control) if control else 0.0
    z_score, p_value = _two_proportion_z_test(
        treatment_matches,
        len(treatment),
        control_matches,
        len(control),
    )
    _exact_z_score, exact_p_value = _two_proportion_z_test(
        treatment_exact_matches,
        len(treatment),
        control_exact_matches,
        len(control),
    )
    hypothesis_tests = _holm_adjust(
        (
            HypothesisTest("aggregate_match_enrichment", p_value, None),
            HypothesisTest(
                "exact_reproduction_enrichment", exact_p_value, None
            ),
        )
    )
    adjusted_p_value = next(
        test.adjusted_p_value
        for test in hypothesis_tests
        if test.name == "aggregate_match_enrichment"
    )
    treatment_interval = _wilson_interval(
        treatment_matches,
        len(treatment),
    )
    control_interval = _wilson_interval(control_matches, len(control))
    effect_interval = ConfidenceInterval(
        lower=max(-1.0, treatment_interval.lower - control_interval.upper),
        upper=min(1.0, treatment_interval.upper - control_interval.lower),
    )
    effect_size = treatment_rate - control_rate
    if treatment_matches == 0:
        conclusion = ProbeConclusion.INCONCLUSIVE
    elif (
        adjusted_p_value is not None
        and adjusted_p_value <= false_positive_threshold
        and effect_size > 0
    ):
        conclusion = ProbeConclusion.STATISTICALLY_CONSISTENT
    elif (
        any(item.exact_match for item in treatment)
        and treatment_rate > control_rate
    ):
        conclusion = ProbeConclusion.WATERMARK_SIGNAL_DETECTED
    else:
        conclusion = ProbeConclusion.INCONCLUSIVE
    return ProbeAnalysisReport(
        treatment_count=len(treatment),
        control_count=len(control),
        treatment_matches=treatment_matches,
        control_matches=control_matches,
        treatment_rate=treatment_rate,
        control_rate=control_rate,
        effect_size=effect_size,
        z_score=z_score,
        p_value=p_value,
        adjusted_p_value=adjusted_p_value,
        correction_method="holm",
        treatment_rate_interval=treatment_interval,
        control_rate_interval=control_interval,
        effect_size_interval=effect_interval,
        hypothesis_tests=hypothesis_tests,
        false_positive_threshold=false_positive_threshold,
        conclusion=conclusion,
        measurements=measurements,
    )


def _measure_response(
    *,
    probe_id: str,
    kind: ProbeKind,
    expected: str,
    response: ProbeResponse | None,
) -> ProbeMeasurement:
    if response is None:
        return ProbeMeasurement(probe_id, kind, False, 0.0, 0, False)
    expected_text = _normalize(expected)
    response_text = _normalize(response.response)
    expected_tokens = _tokens(expected_text)
    response_tokens = _tokens(response_text)
    exact_match = bool(expected_text and expected_text in response_text)
    overlap = 0.0
    if expected_tokens:
        response_token_set = set(response_tokens)
        overlap = sum(
            token in response_token_set for token in expected_tokens
        ) / len(expected_tokens)
    longest_run = _longest_common_run(expected_tokens, response_tokens)
    matched = exact_match or overlap >= 0.45 or longest_run >= 8
    return ProbeMeasurement(
        probe_id=probe_id,
        kind=kind,
        matched=matched,
        score=overlap,
        longest_run=longest_run,
        exact_match=exact_match,
    )


def _two_proportion_z_test(
    treatment_matches: int,
    treatment_count: int,
    control_matches: int,
    control_count: int,
) -> tuple[float | None, float | None]:
    if treatment_count == 0 or control_count == 0:
        return None, None
    pooled = (treatment_matches + control_matches) / (
        treatment_count + control_count
    )
    if pooled in {0.0, 1.0}:
        return None, None
    treatment_rate = treatment_matches / treatment_count
    control_rate = control_matches / control_count
    standard_error = math.sqrt(
        pooled * (1 - pooled) * (1 / treatment_count + 1 / control_count)
    )
    if standard_error == 0:
        return None, None
    z_score = (treatment_rate - control_rate) / standard_error
    p_value = 0.5 * math.erfc(z_score / math.sqrt(2))
    return z_score, p_value


def _holm_adjust(
    tests: tuple[HypothesisTest, ...],
) -> tuple[HypothesisTest, ...]:
    observed = [
        (index, test)
        for index, test in enumerate(tests)
        if test.p_value is not None
    ]
    adjusted: dict[int, float | None] = {
        index: None for index, _test in enumerate(tests)
    }
    running_max = 0.0
    total = len(observed)
    for rank, (index, test) in enumerate(
        sorted(observed, key=lambda item: item[1].p_value or 1.0),
        start=1,
    ):
        assert test.p_value is not None
        value = min((total - rank + 1) * test.p_value, 1.0)
        running_max = max(running_max, value)
        adjusted[index] = running_max
    return tuple(
        HypothesisTest(test.name, test.p_value, adjusted[index])
        for index, test in enumerate(tests)
    )


def _wilson_interval(
    matches: int,
    count: int,
    *,
    confidence_level: float = 0.95,
) -> ConfidenceInterval:
    if count == 0:
        return ConfidenceInterval(0.0, 1.0, confidence_level)
    z_score = 1.959963984540054
    proportion = matches / count
    denominator = 1 + z_score**2 / count
    center = (proportion + z_score**2 / (2 * count)) / denominator
    spread = (
        z_score
        * math.sqrt(
            (proportion * (1 - proportion) + z_score**2 / (4 * count)) / count
        )
        / denominator
    )
    return ConfidenceInterval(
        lower=max(0.0, center - spread),
        upper=min(1.0, center + spread),
        confidence_level=confidence_level,
    )


def _longest_common_run(left: list[str], right: list[str]) -> int:
    previous = [0] * (len(right) + 1)
    best = 0
    for left_token in left:
        current = [0]
        for index, right_token in enumerate(right):
            value = previous[index] + 1 if left_token == right_token else 0
            current.append(value)
            best = max(best, value)
        previous = current
    return best


def _normalize(value: str) -> str:
    return " ".join(value.lower().split())


def _tokens(value: str) -> list[str]:
    return _TOKEN.findall(value.lower())


def _measurement_from_dict(value: dict[str, object]) -> ProbeMeasurement:
    return ProbeMeasurement(
        probe_id=_required_string(value, "probe_id"),
        kind=ProbeKind(_required_string(value, "kind")),
        matched=_required_bool(value, "matched"),
        score=_required_float(value, "score"),
        longest_run=_required_int(value, "longest_run"),
        exact_match=_required_bool(value, "exact_match"),
    )


def _required_string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a nonempty string")
    return item


def _required_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _required_int(value: dict[str, object], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int):
        raise ValueError(f"{key} must be an integer")
    return item


def _required_float(value: dict[str, object], key: str) -> float:
    item = value.get(key)
    if not isinstance(item, int | float):
        raise ValueError(f"{key} must be a number")
    return float(item)


def _optional_float(value: dict[str, object], key: str) -> float | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, int | float):
        raise ValueError(f"{key} must be a number")
    return float(item)


def _required_bool(value: dict[str, object], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ValueError(f"{key} must be a boolean")
    return item
