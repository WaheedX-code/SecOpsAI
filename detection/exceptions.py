"""
SecOpsAI Detection Exceptions
Domain-specific exceptions for the detection engine.
"""
from _future_ import annotations

class DetectionError(Exception):
    """Base class for all detection-related errors."""


class ModelNotLoadedError(DetectionError):
    """Raised when inference is attempted before the model is loaded."""


class FeatureValidationError(DetectionError):
    """Raised when the supplied feature vector is invalid."""


class PredictionError(DetectionError):
    """Raised when model inference fails."""
