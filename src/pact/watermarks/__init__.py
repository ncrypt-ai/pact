"""Public watermark exports."""

from pact.watermarks.base import (
    TRUSTMARK_WATERMARK_ID,
    DecodedImageWatermark,
    ImageWatermark,
    ImageWatermarkBackend,
    TextWatermarkDetection,
    TextWatermarkEligibility,
    TextWatermarkEmbedding,
    TextWatermarkParameters,
    TextWatermarkPlugin,
    TextWatermarkQualityReport,
    TextWatermarkRecord,
    TrustMarkLocator,
    WatermarkError,
    assess_text_watermark_eligibility,
)
from pact.watermarks.canary import CanaryPhrasePlugin
from pact.watermarks.image import (
    ImageSoftBindingVerification,
    ImageWatermarkDependencyError,
    TrustMarkBackend,
    decode_image_soft_binding,
    embed_image_soft_binding,
    trustmark_supported_image_mime_types,
    verify_image_soft_binding,
    watermark_id_for_image_soft_binding,
)
from pact.watermarks.invisible import InvisibleFramePlugin
from pact.watermarks.lexical import LexicalSubstitutionPlugin
from pact.watermarks.semantic import SemanticParaphrasePlugin
from pact.watermarks.statistical import StatisticalSentencePatternPlugin
from pact.watermarks.syntactic import SyntacticVariationPlugin
from pact.watermarks.textual import (
    TextWatermarkPipelineResult,
    apply_text_watermark_plugins,
    embed_experimental_text_carrier,
)

__all__ = [
    "DecodedImageWatermark",
    "ImageSoftBindingVerification",
    "ImageWatermark",
    "ImageWatermarkBackend",
    "ImageWatermarkDependencyError",
    "CanaryPhrasePlugin",
    "InvisibleFramePlugin",
    "LexicalSubstitutionPlugin",
    "SemanticParaphrasePlugin",
    "StatisticalSentencePatternPlugin",
    "TRUSTMARK_WATERMARK_ID",
    "SyntacticVariationPlugin",
    "TextWatermarkDetection",
    "TextWatermarkEligibility",
    "TextWatermarkEmbedding",
    "TextWatermarkParameters",
    "TextWatermarkPipelineResult",
    "TextWatermarkPlugin",
    "TextWatermarkQualityReport",
    "TextWatermarkRecord",
    "TrustMarkBackend",
    "TrustMarkLocator",
    "WatermarkError",
    "apply_text_watermark_plugins",
    "assess_text_watermark_eligibility",
    "decode_image_soft_binding",
    "embed_image_soft_binding",
    "embed_experimental_text_carrier",
    "trustmark_supported_image_mime_types",
    "verify_image_soft_binding",
    "watermark_id_for_image_soft_binding",
]
