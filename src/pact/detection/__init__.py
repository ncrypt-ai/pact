"""Local probe generation and statistical evidence exports."""

# ruff: noqa: F401

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pact.detection.evidence import (
        ProbeEvidencePackage,
        ProbeEvidenceSignature,
    )
    from pact.detection.probes import (
        Probe,
        ProbeKind,
        ProbeResponse,
        ProbeSet,
        create_probe_set,
        responses_from_jsonl,
    )
    from pact.detection.risk import (
        EvidenceSignal,
        TrainingUseRiskLevel,
        TrainingUseRiskReport,
        create_training_use_risk_report,
    )
    from pact.detection.statistics import (
        ConfidenceInterval,
        HypothesisTest,
        ProbeAnalysisReport,
        ProbeConclusion,
        ProbeMeasurement,
        analyze_probe_responses,
    )

_EXPORTS = {
    "Probe": "pact.detection.probes",
    "ProbeKind": "pact.detection.probes",
    "ProbeResponse": "pact.detection.probes",
    "ProbeSet": "pact.detection.probes",
    "create_probe_set": "pact.detection.probes",
    "responses_from_jsonl": "pact.detection.probes",
    "ProbeEvidencePackage": "pact.detection.evidence",
    "ProbeEvidenceSignature": "pact.detection.evidence",
    "ConfidenceInterval": "pact.detection.statistics",
    "HypothesisTest": "pact.detection.statistics",
    "ProbeAnalysisReport": "pact.detection.statistics",
    "ProbeConclusion": "pact.detection.statistics",
    "ProbeMeasurement": "pact.detection.statistics",
    "analyze_probe_responses": "pact.detection.statistics",
    "EvidenceSignal": "pact.detection.risk",
    "TrainingUseRiskLevel": "pact.detection.risk",
    "TrainingUseRiskReport": "pact.detection.risk",
    "create_training_use_risk_report": "pact.detection.risk",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> object:
    """Load detection exports on demand."""

    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
