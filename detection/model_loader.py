"""
SecOpsAI — Model Artifact Loader.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib

from detection.exceptions import DetectionError

logger = logging.getLogger("secopsai.model_loader")

_DEFAULT_MODEL_FILENAME = "xgboost_hardened.pkl"
_DEFAULT_SCALER_FILENAME = "scaler.pkl"
_DEFAULT_LABEL_ENCODER_FILENAME = "label_encoder.pkl"
_DEFAULT_ABLATION_FILENAME = "ablation_results.json"


class ModelLoader:
 
    def __init__(
        self,
        model_dir: str | Path = "detection/models",
        ablation_path: str | Path = "detection/ablation_results.json",
        *,
        model_filename: str = _DEFAULT_MODEL_FILENAME,
        scaler_filename: str = _DEFAULT_SCALER_FILENAME,
        label_encoder_filename: str = _DEFAULT_LABEL_ENCODER_FILENAME,
        model_version: str | None = None,
    ) -> None:
        self._model_dir = Path(model_dir)
        self._ablation_path = Path(ablation_path)
        self._model_filename = model_filename
        self._scaler_filename = scaler_filename
        self._label_encoder_filename = label_encoder_filename
        self._model_version = model_version or Path(model_filename).stem

        self._model: Any | None = None
        self._scaler: Any | None = None
        self._label_encoder: Any | None = None
        self._features: list[str] | None = None
        self._loaded: bool = False

    @property
    def is_loaded(self) -> bool:
        """Whether all artifacts have been successfully loaded."""
        return self._loaded

    def load(self) -> None:
        """Load the model, scaler, label encoder, and feature order from disk.
        Raises:
            DetectionError: If any artifact is missing or fails to load.
        """
        try:
            model_path = self._model_dir / self._model_filename
            scaler_path = self._model_dir / self._scaler_filename
            label_encoder_path = self._model_dir / self._label_encoder_filename

            logger.info("Loading model artifacts from %s", self._model_dir)

            self._model = joblib.load(model_path)
            self._scaler = joblib.load(scaler_path)
            self._label_encoder = joblib.load(label_encoder_path)
            self._features = self._load_feature_order(self._ablation_path)

            self._loaded = True
            logger.info(
                "Model artifacts loaded successfully (%d features)",
                len(self._features),
            )
        except DetectionError:
            self._loaded = False
            raise
        except Exception as exc:  # noqa: BLE001 - normalize to DetectionError
            self._loaded = False
            logger.error("Failed to load model artifacts: %s", exc)
            raise DetectionError(f"Failed to load model artifacts: {exc}") from exc

    @staticmethod
    def _load_feature_order(ablation_path: Path) -> list[str]:
        """Extract the canonical, ordered feature list from ablation results.
        Raises:
            DetectionError: If the file is missing, malformed, or empty.
        """
        try:
            with open(ablation_path) as f:
                ablation = json.load(f)
            features = [item["feature"] for item in ablation]
        except Exception as exc:  # noqa: BLE001 - normalize to DetectionError
            raise DetectionError(
                f"Failed to load feature order from {ablation_path}: {exc}"
            ) from exc

        if not features:
            raise DetectionError(f"No features found in {ablation_path}")
        return features

    def get_model(self) -> Any:
        """Return the loaded model instance.
        Raises:
            DetectionError: If artifacts have not been loaded.
        """
        self._ensure_loaded()
        return self._model

    def get_scaler(self) -> Any:
        """Return the loaded scaler instance.
        Raises:
            DetectionError: If artifacts have not been loaded.
        """
        self._ensure_loaded()
        return self._scaler

    def get_label_encoder(self) -> Any:
        """Return the loaded label encoder instance.
        Raises:
            DetectionError: If artifacts have not been loaded.
        """
        self._ensure_loaded()
        return self._label_encoder

    def get_features(self) -> list[str]:
        """Return the canonical, ordered list of feature names.
        Raises:
            DetectionError: If artifacts have not been loaded.
        """
        self._ensure_loaded()
        assert self._features is not None
        return self._features

    def get_model_version(self) -> str:
        """Return the version identifier for the currently loaded model.
         """
        return self._model_version

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            raise DetectionError(
                "Model artifacts have not been loaded; call load() first."
            )
