"""Context-limited lexical substitution plugin."""

from __future__ import annotations

import hashlib
import re

from pact.watermarks.base import (
    TextWatermarkDetection,
    TextWatermarkEmbedding,
    TextWatermarkParameters,
    TextWatermarkPlugin,
    TextWatermarkRecord,
    build_quality_report,
    index_is_locked,
    require_text_watermark_safety,
    secret_bytes,
    secret_digest,
)

_TOKEN_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z'-]*\b")
_LEXICAL_MAP = {
    "help": "assist",
    "show": "display",
    "start": "begin",
    "end": "finish",
    "keep": "retain",
    "check": "verify",
    "build": "create",
    "need": "require",
}


def _apply_case(source: str, replacement: str) -> str:
    if source.isupper():
        return replacement.upper()
    if source[:1].isupper():
        return replacement.capitalize()
    return replacement


def _replacement_text(item: object) -> str | None:
    if not isinstance(item, dict):
        return None
    replacement = item.get("replacement")
    return replacement if isinstance(replacement, str) else None


class LexicalSubstitutionPlugin(TextWatermarkPlugin):
    """Use deterministic synonym swaps outside locked spans."""

    method_id = "pact.text.lexical.v1"
    semantic = False

    def embed(
        self,
        content: str,
        secret: bytes | str,
        parameters: TextWatermarkParameters,
    ) -> TextWatermarkEmbedding:
        eligibility = require_text_watermark_safety(
            content,
            parameters,
            semantic=self.semantic,
        )
        replacements: list[dict[str, object]] = []
        pieces: list[str] = []
        cursor = 0
        changes = 0
        secret_raw = secret_bytes(secret)
        for index, match in enumerate(_TOKEN_PATTERN.finditer(content)):
            start, end = match.span()
            token = match.group(0)
            lower = token.lower()
            if (
                lower not in _LEXICAL_MAP
                or index_is_locked(start, eligibility.locked_spans)
                or changes >= parameters.max_changes
            ):
                continue
            gate = hashlib.sha256(secret_raw + index.to_bytes(4, "big")).digest()[0]
            if gate % 2 == 0:
                continue
            pieces.append(content[cursor:start])
            replacement = _apply_case(token, _LEXICAL_MAP[lower])
            pieces.append(replacement)
            cursor = end
            changes += 1
            replacements.append(
                {
                    "index": index,
                    "start": start,
                    "end": end,
                    "original": token,
                    "replacement": replacement,
                }
            )
        pieces.append(content[cursor:])
        transformed = "".join(pieces) if replacements else content
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
        return build_quality_report(self.method_id, original, transformed)
