"""Very local semantic paraphrase plugin with explicit opt-in."""

from __future__ import annotations

from pact.watermarks.base import (
    TextWatermarkDetection,
    TextWatermarkEmbedding,
    TextWatermarkParameters,
    TextWatermarkPlugin,
    TextWatermarkRecord,
    build_quality_report,
    require_text_watermark_safety,
    secret_digest,
)

_PHRASE_MAP = (
    ("due to the fact that", "because"),
    ("in order to", "to"),
    ("at this point in time", "now"),
    ("a large number of", "many"),
    ("in the event that", "if"),
    ("for the purpose of", "for"),
)


def _replacement_text(item: object) -> str | None:
    if not isinstance(item, dict):
        return None
    replacement = item.get("replacement")
    return replacement if isinstance(replacement, str) else None


class SemanticParaphrasePlugin(TextWatermarkPlugin):
    """Apply a small explicit phrase map for local paraphrases."""

    method_id = "pact.text.semantic.v1"
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
        transformed = content
        replacements: list[dict[str, object]] = []
        for original, replacement in _PHRASE_MAP:
            if len(replacements) >= parameters.max_changes:
                break
            if original not in transformed:
                continue
            transformed = transformed.replace(original, replacement, 1)
            replacements.append(
                {"original": original, "replacement": replacement}
            )
        record = TextWatermarkRecord(
            method_id=self.method_id,
            secret_digest=secret_digest(secret),
            metadata={"replacements": replacements},
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
        replacements = record.metadata.get("replacements", [])
        items = replacements if isinstance(replacements, list) else []
        matches = sum(
            1
            for item in items
            if (_replacement := _replacement_text(item)) is not None
            and _replacement in content_or_outputs
        )
        inspected = len(items)
        score = 0.0 if inspected == 0 else matches / inspected
        return TextWatermarkDetection(
            method_id=self.method_id,
            detected=matches > 0,
            score=score,
            inspected=inspected,
            matches=matches,
            details={"replacements": items},
        )

    def assess(self, original: str, transformed: str):
        return build_quality_report(
            self.method_id,
            original,
            transformed,
            warnings=("semantic method used",),
        )
