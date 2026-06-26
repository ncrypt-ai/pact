"""Public watermark exports."""

from pact.watermarks.base import (
    TRUSTMARK_WATERMARK_ID,
    DecodedImageWatermark,
    ImageWatermark,
    ImageWatermarkBackend,
    TrustMarkLocator,
    WatermarkError,
)
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

__all__ = [
    "DecodedImageWatermark",
    "ImageSoftBindingVerification",
    "ImageWatermark",
    "ImageWatermarkBackend",
    "ImageWatermarkDependencyError",
    "TRUSTMARK_WATERMARK_ID",
    "TrustMarkBackend",
    "TrustMarkLocator",
    "WatermarkError",
    "decode_image_soft_binding",
    "embed_image_soft_binding",
    "trustmark_supported_image_mime_types",
    "verify_image_soft_binding",
    "watermark_id_for_image_soft_binding",
]
