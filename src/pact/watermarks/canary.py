"""User-approved canary phrase plugin."""

from __future__ import annotations

from pact.watermarks.base import (
    TextWatermarkDetection,
    TextWatermarkEmbedding,
    TextWatermarkParameters,
    TextWatermarkPlugin,
    TextWatermarkRecord,
    WatermarkError,
    build_quality_report,
    require_text_watermark_safety,
    secret_digest,
)


class CanaryPhrasePlugin(TextWatermarkPlugin):
    """Append a user-approved canary phrase as a footer paragraph."""

    method_id = "pact.text.canary.v1"
    semantic = True

    def embed(
        self,
        content: str,
        secret: bytes | str,
        parameters: TextWatermarkParameters,
    ) -> TextWatermarkEmbedding:
        require_text_watermark_safety(
            content,
            parameters,
            semantic=self.semantic,
        )
        phrase = parameters.approved_canary_phrase
        if not phrase:
            raise WatermarkError("canary watermarking requires an approved canary phrase")
        transformed = content.rstrip() + f"\n\n{phrase}\n"
        record = TextWatermarkRecord(
            method_id=self.method_id,
            secret_digest=secret_digest(secret),
            metadata={"phrase": phrase, "placement": "footer"},
        )
        return TextWatermarkEmbedding(
            transformed_content=transformed,
            record=record,
            quality_report=self.assess(content, transformed),
        )

    def detect(
        self,
        content_or_outputs: str,
        secret: bytes | str,
        record: TextWatermarkRecord,
    ) -> TextWatermarkDetection:
        del secret
        phrase = record.metadata.get("phrase")
        if not isinstance(phrase, str):
            return TextWatermarkDetection(
                method_id=self.method_id,
                detected=False,
                score=0.0,
                inspected=0,
                matches=0,
                details={},
            )
        matches = content_or_outputs.count(phrase)
        return TextWatermarkDetection(
            method_id=self.method_id,
            detected=matches > 0,
            score=float(matches > 0),
            inspected=1,
            matches=min(matches, 1),
            details={"phrase": phrase, "occurrences": matches},
        )

    def assess(self, original: str, transformed: str):
        return build_quality_report(
            self.method_id,
            original,
            transformed,
            warnings=("canary phrase inserted",),
        )
