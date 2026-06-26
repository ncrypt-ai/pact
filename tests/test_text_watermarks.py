from uuid import UUID

import pytest

from pact import (
    CanonicalizationProfile,
    ClaimantIdentity,
    Manifest,
    Permission,
    PermissionValue,
    Policy,
    PolicyEntry,
    TextWatermarkParameters,
    embed_text_carrier,
    sign_manifest,
)
from pact.carriers import CarrierMode, extract_text_carrier
from pact.watermarks import (
    CanaryPhrasePlugin,
    InvisibleFramePlugin,
    LexicalSubstitutionPlugin,
    SemanticParaphrasePlugin,
    StatisticalSentencePatternPlugin,
    SyntacticVariationPlugin,
    WatermarkError,
    assess_text_watermark_eligibility,
)

ROOT_FINGERPRINT = "A" * 43
NONCE = b"\x02" * 32
CLAIM_ID = UUID("018f7f79-7b42-7c00-8000-000000000456")
TEXT = (
    "We help new users start quickly because clear setup steps matter. "
    "If the guide is simple, then more people finish the task."
)


def make_policy() -> Policy:
    return Policy(
        (
            PolicyEntry(
                Permission.GENERATIVE_TRAINING,
                PermissionValue.NOT_ALLOWED,
            ),
        )
    )


def make_signed_manifest():
    identity = ClaimantIdentity.generate("https://registry.example")
    manifest = Manifest.create(
        identity=identity,
        registry_root_fingerprint=ROOT_FINGERPRINT,
        content=TEXT.encode("utf-8"),
        mime_type="text/plain",
        canonicalization=CanonicalizationProfile.TEXT_V1,
        policy=make_policy(),
        claim_id=CLAIM_ID,
        nonce=NONCE,
    )
    return sign_manifest(manifest, identity)


def test_text_watermark_eligibility_blocks_code_and_requires_confirmation() -> None:
    eligibility = assess_text_watermark_eligibility("def main():\n    return 1\n")
    assert eligibility.allowed is False
    plugin = LexicalSubstitutionPlugin()
    with pytest.raises(WatermarkError, match="requires user confirmation"):
        plugin.embed(TEXT, "secret", TextWatermarkParameters())


def test_invisible_text_watermark_detects() -> None:
    plugin = InvisibleFramePlugin()
    embedding = plugin.embed(
        TEXT,
        "secret",
        TextWatermarkParameters(user_confirmation=True),
    )
    detection = plugin.detect(embedding.transformed_content, "secret", embedding.record)
    assert detection.detected is True


def test_lexical_and_syntactic_watermarks_transform_text() -> None:
    lexical = LexicalSubstitutionPlugin()
    lexical_embedding = lexical.embed(
        TEXT,
        "secret",
        TextWatermarkParameters(user_confirmation=True, max_changes=4),
    )
    assert lexical_embedding.transformed_content != TEXT

    syntactic = SyntacticVariationPlugin()
    syntactic_embedding = syntactic.embed(
        TEXT,
        "secret",
        TextWatermarkParameters(user_confirmation=True, selection_stride=1),
    )
    assert "Because clear setup steps matter" in syntactic_embedding.transformed_content


def test_semantic_and_canary_methods_require_explicit_opt_in() -> None:
    semantic = SemanticParaphrasePlugin()
    with pytest.raises(WatermarkError, match="disabled by default"):
        semantic.embed(
            "We act due to the fact that the plan is simple.",
            "secret",
            TextWatermarkParameters(user_confirmation=True),
        )

    canary = CanaryPhrasePlugin()
    embedding = canary.embed(
        TEXT,
        "secret",
        TextWatermarkParameters(
            user_confirmation=True,
            allow_semantic_methods=True,
            approved_canary_phrase="This line is an approved canary.",
        ),
    )
    assert embedding.transformed_content.endswith("This line is an approved canary.\n")


def test_statistical_sentence_pattern_reports_enrichment() -> None:
    plugin = StatisticalSentencePatternPlugin()
    embedding = plugin.embed(
        TEXT,
        "secret",
        TextWatermarkParameters(
            user_confirmation=True,
            allow_semantic_methods=True,
            approved_canary_phrase="marker",
            selection_stride=1,
        ),
    )
    detection = plugin.detect(embedding.transformed_content, "secret", embedding.record)
    assert detection.detected is True
    assert detection.score >= 0.0


def test_experimental_text_carrier_mode_uses_plugins() -> None:
    signed = make_signed_manifest()
    embedded = embed_text_carrier(
        TEXT,
        signed,
        nonce=NONCE,
        mode=CarrierMode.EXPERIMENTAL,
        secret="secret",
        plugins=(LexicalSubstitutionPlugin(),),
        plugin_parameters=TextWatermarkParameters(user_confirmation=True),
    )
    extraction = extract_text_carrier(embedded)
    assert extraction.signed_manifest == signed
    assert extraction.content != TEXT.encode("utf-8")
