"""Composition helpers for experimental text watermark plugins."""

from __future__ import annotations

from dataclasses import dataclass

from pact.carriers.text import CarrierMode, embed_text_carrier
from pact.manifest import SignedManifest
from pact.watermarks.base import (
    TextWatermarkEmbedding,
    TextWatermarkParameters,
    TextWatermarkPlugin,
    WatermarkError,
)


@dataclass(frozen=True, slots=True)
class TextWatermarkPipelineResult:
    """Sequential plugin output for one prose document."""

    transformed_content: str
    embeddings: tuple[TextWatermarkEmbedding, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible pipeline summary."""

        return {
            "transformed_content": self.transformed_content,
            "embeddings": [embedding.to_dict() for embedding in self.embeddings],
        }


def apply_text_watermark_plugins(
    content: str,
    secret: bytes | str,
    plugins: tuple[TextWatermarkPlugin, ...],
    parameters: TextWatermarkParameters,
) -> TextWatermarkPipelineResult:
    """Apply a sequence of experimental text watermark plugins."""

    transformed = content
    embeddings: list[TextWatermarkEmbedding] = []
    for plugin in plugins:
        embedding = plugin.embed(transformed, secret, parameters)
        transformed = embedding.transformed_content
        embeddings.append(embedding)
    return TextWatermarkPipelineResult(
        transformed_content=transformed,
        embeddings=tuple(embeddings),
    )


def embed_experimental_text_carrier(
    content: str,
    signed: SignedManifest,
    *,
    nonce: bytes,
    secret: bytes | str,
    plugins: tuple[TextWatermarkPlugin, ...],
    parameters: TextWatermarkParameters,
) -> tuple[bytes, TextWatermarkPipelineResult]:
    """Apply plugins to prose, then embed the standard text carrier."""

    if not plugins:
        raise WatermarkError("experimental text carrier mode requires at least one plugin")
    pipeline = apply_text_watermark_plugins(content, secret, plugins, parameters)
    return (
        embed_text_carrier(
            pipeline.transformed_content,
            signed,
            nonce=nonce,
            mode=CarrierMode.BOTH,
        ),
        pipeline,
    )
