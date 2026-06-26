"""Sentence-selection watermarking with measurable enrichment."""

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
    sentence_selected,
    split_sentences,
)


class StatisticalSentencePatternPlugin(TextWatermarkPlugin):
    """Insert an approved marker on a keyed subset of sentences."""

    method_id = "pact.text.statistical.v1"
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
        marker = parameters.approved_canary_phrase
        if not marker:
            raise WatermarkError("statistical watermarking requires an approved marker phrase")
        sentences = split_sentences(content)
        transformed_sentences: list[str] = []
        selected_indexes: list[int] = []
        for index, sentence in enumerate(sentences):
            if (
                sentence_selected(secret, index, parameters.selection_stride)
                and len(selected_indexes) < parameters.max_changes
            ):
                selected_indexes.append(index)
                if sentence.endswith((".", "!", "?")):
                    transformed_sentences.append(
                        sentence[:-1] + f" — {marker}" + sentence[-1]
                    )
                else:
                    transformed_sentences.append(sentence + f" — {marker}")
            else:
                transformed_sentences.append(sentence)
        transformed = " ".join(transformed_sentences)
        record = TextWatermarkRecord(
            method_id=self.method_id,
            secret_digest=secret_digest(secret),
            metadata={
                "marker": marker,
                "selected_indexes": selected_indexes,
                "selection_stride": parameters.selection_stride,
            },
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
        marker = record.metadata.get("marker")
        selected_indexes = record.metadata.get("selected_indexes")
        if not isinstance(marker, str) or not isinstance(selected_indexes, list):
            return TextWatermarkDetection(
                method_id=self.method_id,
                detected=False,
                score=0.0,
                inspected=0,
                matches=0,
                details={},
            )
        sentences = split_sentences(content_or_outputs)
        selected_hits = 0
        control_hits = 0
        for index, sentence in enumerate(sentences):
            has_marker = marker in sentence
            if index in selected_indexes:
                selected_hits += int(has_marker)
            else:
                control_hits += int(has_marker)
        inspected = len(selected_indexes)
        selected_rate = 0.0 if inspected == 0 else selected_hits / inspected
        control_denominator = max(len(sentences) - inspected, 1)
        control_rate = control_hits / control_denominator
        score = max(selected_rate - control_rate, 0.0)
        return TextWatermarkDetection(
            method_id=self.method_id,
            detected=selected_hits > 0 and selected_rate >= control_rate,
            score=score,
            inspected=inspected,
            matches=selected_hits,
            details={
                "marker": marker,
                "selected_hits": selected_hits,
                "control_hits": control_hits,
                "selected_rate": selected_rate,
                "control_rate": control_rate,
            },
        )

    def assess(self, original: str, transformed: str):
        return build_quality_report(
            self.method_id,
            original,
            transformed,
            warnings=("statistical marker inserted",),
        )
