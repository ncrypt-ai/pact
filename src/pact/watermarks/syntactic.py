"""Keyed syntactic variation plugin."""

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
    sentence_selected,
    split_sentences,
)


def _lower_initial(value: str) -> str:
    return value[:1].lower() + value[1:] if value else value


def _replacement_text(item: object) -> str | None:
    if not isinstance(item, dict):
        return None
    replacement = item.get("replacement")
    return replacement if isinstance(replacement, str) else None


class SyntacticVariationPlugin(TextWatermarkPlugin):
    """Reorder a small set of safe sentence templates."""

    method_id = "pact.text.syntactic.v1"
    semantic = False

    def _rewrite(self, sentence: str) -> str | None:
        if " because " in sentence and sentence.endswith("."):
            main, reason = sentence[:-1].split(" because ", 1)
            if main and reason:
                return f"Because {reason}, {_lower_initial(main)}."
        prefix = "If "
        marker = ", then "
        if (
            sentence.startswith(prefix)
            and sentence.endswith(".")
            and marker in sentence
        ):
            condition, result = sentence[3:-1].split(marker, 1)
            return f"{result} if {condition}."
        return None

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
        sentences = split_sentences(content)
        transformed_sentences: list[str] = []
        rewrites: list[dict[str, object]] = []
        for index, sentence in enumerate(sentences):
            replacement = self._rewrite(sentence)
            if (
                replacement is None
                or not sentence_selected(
                    secret, index, parameters.selection_stride
                )
                or len(rewrites) >= parameters.max_changes
            ):
                transformed_sentences.append(sentence)
                continue
            transformed_sentences.append(replacement)
            rewrites.append(
                {
                    "sentence_index": index,
                    "original": sentence,
                    "replacement": replacement,
                }
            )
        transformed = " ".join(transformed_sentences)
        record = TextWatermarkRecord(
            method_id=self.method_id,
            secret_digest=secret_digest(secret),
            metadata={"rewrites": rewrites},
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
        rewrites = record.metadata.get("rewrites", [])
        items = rewrites if isinstance(rewrites, list) else []
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
            details={"rewrites": items},
        )

    def assess(self, original: str, transformed: str):
        return build_quality_report(self.method_id, original, transformed)
