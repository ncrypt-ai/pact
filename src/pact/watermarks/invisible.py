"""Invisible framing plugin for prose-only experimental text watermarking."""

from __future__ import annotations

import hashlib
import json
import re

from pact.canonical import canonical_json
from pact.watermarks.base import (
    TextWatermarkDetection,
    TextWatermarkEmbedding,
    TextWatermarkParameters,
    TextWatermarkPlugin,
    TextWatermarkRecord,
    build_quality_report,
    require_text_watermark_safety,
    secret_bytes,
    secret_digest,
)

_FRAME_START = "\u2060\u2062\u2060"
_FRAME_END = "\u2060\u2063\u2060"
_BIT_ZERO = "\u200b"
_BIT_ONE = "\u200c"
_FRAME_PATTERN = re.compile(
    re.escape(_FRAME_START) + r"(?P<bits>[\u200b\u200c]+)" + re.escape(_FRAME_END)
)


class InvisibleFramePlugin(TextWatermarkPlugin):
    """Append a zero-width experimental watermark frame to prose."""

    method_id = "pact.text.invisible.v1"
    semantic = False

    def _payload(self, content: str, secret: bytes | str) -> dict[str, object]:
        digest = hashlib.sha256(
            secret_bytes(secret) + canonical_json(content)
        ).digest()[:12]
        return {"version": 1, "tag": digest.hex()}

    def _frame(self, payload: dict[str, object]) -> str:
        bits = "".join(
            f"{byte:08b}" for byte in canonical_json(payload)
        ).replace("0", _BIT_ZERO).replace("1", _BIT_ONE)
        return f"{_FRAME_START}{bits}{_FRAME_END}"

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
        payload = self._payload(content, secret)
        transformed = content + self._frame(payload)
        record = TextWatermarkRecord(
            method_id=self.method_id,
            secret_digest=secret_digest(secret),
            metadata={"payload": payload},
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
        match = _FRAME_PATTERN.search(content_or_outputs)
        if match is None:
            return TextWatermarkDetection(
                method_id=self.method_id,
                detected=False,
                score=0.0,
                inspected=1,
                matches=0,
                details={},
            )
        bits = (
            match.group("bits").replace(_BIT_ZERO, "0").replace(_BIT_ONE, "1")
        )
        payload = bytes(
            int(bits[index : index + 8], 2)
            for index in range(0, len(bits), 8)
        )
        parsed = json.loads(payload)
        expected = record.metadata.get("payload")
        detected = parsed == expected
        return TextWatermarkDetection(
            method_id=self.method_id,
            detected=detected,
            score=1.0 if detected else 0.0,
            inspected=1,
            matches=1 if detected else 0,
            details={"payload": parsed},
        )

    def assess(self, original: str, transformed: str):
        return build_quality_report(self.method_id, original, transformed)
