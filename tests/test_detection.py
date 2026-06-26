import json
from datetime import UTC, datetime

from pact import (
    ClaimantIdentity,
    ProbeConclusion,
    ProbeEvidencePackage,
    ProbeKind,
    ProbeResponse,
    ProbeSet,
    TextWatermarkDetection,
    TrainingUseRiskLevel,
    analyze_probe_responses,
    create_probe_set,
    create_training_use_risk_report,
    responses_from_jsonl,
)

PROTECTED = (
    "The silver orchard opened under the blue evening sky. "
    "Every branch carried a glass bell that chimed when the river fog arrived. "
    "Mara wrote the sound into her notebook before the lighthouse went dark."
)
CONTROL = (
    "The public garden opened after the spring rain ended. "
    "Every path carried small signs that explained where visitors should walk. "
    "The caretaker closed the gate before the town clock sounded."
)


def test_probe_set_commitment_round_trip() -> None:
    probe_set = create_probe_set(
        protected_texts=(PROTECTED,),
        control_texts=(CONTROL,),
        target_model="model-a",
        claim_id="018f7f79-7b42-7c00-8000-000000000001",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    parsed = ProbeSet.from_dict(probe_set.to_dict())

    assert parsed == probe_set
    assert parsed.commitment == parsed.compute_commitment()
    assert {probe.kind for probe in parsed.probes} == {
        ProbeKind.TREATMENT,
        ProbeKind.CONTROL,
    }


def test_probe_analysis_detects_treatment_enrichment() -> None:
    probe_set = create_probe_set(
        protected_texts=(PROTECTED,),
        control_texts=(CONTROL,),
        target_model="model-a",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    treatment = next(
        probe
        for probe in probe_set.probes
        if probe.kind is ProbeKind.TREATMENT
    )
    control = next(
        probe for probe in probe_set.probes if probe.kind is ProbeKind.CONTROL
    )
    responses = (
        ProbeResponse(
            treatment.probe_id,
            f"The next sentence is: {treatment.expected_continuation}",
        ),
        ProbeResponse(control.probe_id, "I do not know."),
    )

    report = analyze_probe_responses(probe_set, responses)

    assert report.treatment_matches == 1
    assert report.control_matches == 0
    assert report.conclusion is ProbeConclusion.WATERMARK_SIGNAL_DETECTED
    assert report.adjusted_p_value is not None
    assert report.effect_size_interval.lower <= report.effect_size
    assert report.effect_size <= report.effect_size_interval.upper
    assert {test.name for test in report.hypothesis_tests} == {
        "aggregate_match_enrichment",
        "exact_reproduction_enrichment",
    }


def test_training_use_risk_report_combines_probe_and_canary_evidence() -> None:
    probe_set = create_probe_set(
        protected_texts=(PROTECTED,),
        control_texts=(CONTROL,),
        target_model="model-a",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    treatment = next(
        probe
        for probe in probe_set.probes
        if probe.kind is ProbeKind.TREATMENT
    )
    control = next(
        probe for probe in probe_set.probes if probe.kind is ProbeKind.CONTROL
    )
    analysis = analyze_probe_responses(
        probe_set,
        (
            ProbeResponse(treatment.probe_id, treatment.expected_continuation),
            ProbeResponse(control.probe_id, "I do not know."),
        ),
    )
    canary = TextWatermarkDetection(
        method_id="pact.text.canary.v1",
        detected=True,
        score=1.0,
        inspected=1,
        matches=1,
        details={"phrase": "approved canary"},
    )

    report = create_training_use_risk_report(
        probe_analysis=analysis,
        text_watermark_detections=(canary,),
    )

    assert report.risk_level is TrainingUseRiskLevel.HIGH
    assert report.score >= 0.7
    assert {signal.kind for signal in report.signals if signal.present} == {
        "probe",
        "text_watermark",
    }


def test_probe_evidence_package_digest_and_signature_round_trip() -> None:
    identity = ClaimantIdentity.generate("https://registry.example")
    probe_set = create_probe_set(
        protected_texts=(PROTECTED,),
        control_texts=(CONTROL,),
        target_model="model-a",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    responses = tuple(
        ProbeResponse(probe.probe_id, "I do not know.")
        for probe in probe_set.probes
    )
    report = analyze_probe_responses(probe_set, responses)
    package = ProbeEvidencePackage.create(
        probe_set=probe_set,
        responses=responses,
        analysis=report,
        signer=identity,
        exported_at=datetime(2026, 1, 2, tzinfo=UTC),
    )

    parsed = ProbeEvidencePackage.from_dict(package.to_dict())

    assert parsed.package_digest == package.compute_digest()
    assert parsed.signature is not None
    assert parsed.signature.key_id == identity.key_id


def test_responses_from_jsonl() -> None:
    parsed = responses_from_jsonl(
        json.dumps({"probe_id": "p1", "response": "answer"}) + "\n"
    )

    assert parsed == (ProbeResponse("p1", "answer"),)
