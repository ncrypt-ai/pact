"""Combined evidence reports for possible training use."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pact.detection.evidence import ProbeEvidencePackage
from pact.detection.statistics import ProbeAnalysisReport, ProbeConclusion
from pact.registry.app import ClaimVerificationReport, VerificationLabel
from pact.watermarks import (
    ImagePerceptualMatch,
    ImageSoftBindingVerification,
    TextWatermarkDetection,
)


class TrainingUseRiskLevel(StrEnum):
    """Risk labels for a combined evidence report."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    """One signal used in a combined training-use report."""

    kind: str
    label: str
    present: bool
    weight: float
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Serialize one evidence signal."""

        return {
            "kind": self.kind,
            "label": self.label,
            "present": self.present,
            "weight": self.weight,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class TrainingUseRiskReport:
    """Combined evidence report for possible training use."""

    risk_level: TrainingUseRiskLevel
    score: float
    summary: str
    signals: tuple[EvidenceSignal, ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize the combined risk report."""

        return {
            "risk_level": self.risk_level.value,
            "score": self.score,
            "summary": self.summary,
            "signals": [signal.to_dict() for signal in self.signals],
            "warnings": list(self.warnings),
        }


def create_training_use_risk_report(
    *,
    probe_analysis: ProbeAnalysisReport | None = None,
    probe_package: ProbeEvidencePackage | None = None,
    text_watermark_detections: tuple[TextWatermarkDetection, ...] = (),
    image_watermark_verification: ImageSoftBindingVerification | None = None,
    image_perceptual_match: ImagePerceptualMatch | None = None,
    registry_verification: ClaimVerificationReport | None = None,
) -> TrainingUseRiskReport:
    """Combine probe, watermark, matching, and registry evidence."""

    analysis = probe_analysis or (
        None if probe_package is None else probe_package.analysis
    )
    signals: list[EvidenceSignal] = []
    warnings = [
        "This report is evidence, not proof of infringement, breach, or training.",
        "Provider responses must be collected by the user and interpreted with controls.",
    ]
    if analysis is not None:
        signals.append(_probe_signal(analysis))
    signals.extend(
        _text_watermark_signal(item) for item in text_watermark_detections
    )
    if image_watermark_verification is not None:
        signals.append(_image_watermark_signal(image_watermark_verification))
    if image_perceptual_match is not None:
        signals.append(_image_perceptual_signal(image_perceptual_match))
    if registry_verification is not None:
        signals.append(_registry_signal(registry_verification))
        if registry_verification.label in {
            VerificationLabel.DISPUTED,
            VerificationLabel.REVOKED,
            VerificationLabel.INVALID_CLAIM_SIGNATURE,
            VerificationLabel.CONTENT_MISMATCH,
        }:
            warnings.append(
                "Registry verification has dispute, revocation, or trust limitations."
            )
    score = min(
        1.0,
        sum(signal.weight for signal in signals if signal.present),
    )
    risk_level = _risk_level(score, signals)
    return TrainingUseRiskReport(
        risk_level=risk_level,
        score=score,
        summary=_summary(risk_level, signals),
        signals=tuple(signals),
        warnings=tuple(warnings),
    )


def _probe_signal(analysis: ProbeAnalysisReport) -> EvidenceSignal:
    weight = 0.0
    present = analysis.conclusion is not ProbeConclusion.INCONCLUSIVE
    if analysis.conclusion is ProbeConclusion.WATERMARK_SIGNAL_DETECTED:
        weight = 0.45
    elif analysis.conclusion is ProbeConclusion.STATISTICALLY_CONSISTENT:
        weight = 0.35
    if analysis.adjusted_p_value is not None:
        if analysis.adjusted_p_value <= 0.01:
            weight += 0.1
        elif analysis.adjusted_p_value <= analysis.false_positive_threshold:
            weight += 0.05
    weight += min(max(analysis.effect_size, 0.0) * 0.25, 0.15)
    return EvidenceSignal(
        kind="probe",
        label=analysis.conclusion.value,
        present=present,
        weight=round(min(weight, 0.7), 4) if present else 0.0,
        details={
            "treatment_matches": analysis.treatment_matches,
            "control_matches": analysis.control_matches,
            "effect_size": analysis.effect_size,
            "effect_size_interval": analysis.effect_size_interval.to_dict(),
            "p_value": analysis.p_value,
            "adjusted_p_value": analysis.adjusted_p_value,
            "correction_method": analysis.correction_method,
        },
    )


def _text_watermark_signal(
    detection: TextWatermarkDetection,
) -> EvidenceSignal:
    is_canary = "canary" in detection.method_id
    weight = 0.35 if is_canary else min(0.25, max(detection.score, 0.0) * 0.25)
    return EvidenceSignal(
        kind="text_watermark",
        label=detection.method_id,
        present=detection.detected,
        weight=round(weight, 4) if detection.detected else 0.0,
        details=detection.to_dict(),
    )


def _image_watermark_signal(
    verification: ImageSoftBindingVerification,
) -> EvidenceSignal:
    present = verification.registry_match or verification.detected
    weight = 0.25 if verification.registry_match else 0.1
    return EvidenceSignal(
        kind="image_watermark",
        label="registry_match" if verification.registry_match else "detected",
        present=present,
        weight=weight if present else 0.0,
        details=verification.to_dict(),
    )


def _image_perceptual_signal(match: ImagePerceptualMatch) -> EvidenceSignal:
    return EvidenceSignal(
        kind="image_perceptual_match",
        label="matched" if match.matched else "not_matched",
        present=match.matched,
        weight=round(min(max(match.score, 0.0), 1.0) * 0.15, 4)
        if match.matched
        else 0.0,
        details=match.to_dict(),
    )


def _registry_signal(report: ClaimVerificationReport) -> EvidenceSignal:
    present = report.label is VerificationLabel.CONTENT_CLAIM_VERIFIED
    return EvidenceSignal(
        kind="registry",
        label=report.label.value,
        present=present,
        weight=0.15 if present else 0.0,
        details=report.to_dict(),
    )


def _risk_level(
    score: float,
    signals: list[EvidenceSignal],
) -> TrainingUseRiskLevel:
    if not any(signal.present for signal in signals):
        return TrainingUseRiskLevel.INCONCLUSIVE
    if score >= 0.7:
        return TrainingUseRiskLevel.HIGH
    if score >= 0.35:
        return TrainingUseRiskLevel.MODERATE
    return TrainingUseRiskLevel.LOW


def _summary(
    risk_level: TrainingUseRiskLevel,
    signals: list[EvidenceSignal],
) -> str:
    present = [signal.kind for signal in signals if signal.present]
    if risk_level is TrainingUseRiskLevel.INCONCLUSIVE:
        return "No reliable signal was detected."
    return (
        f"{risk_level.value} evidence signal based on "
        + ", ".join(_dedupe(present))
        + "."
    )


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
