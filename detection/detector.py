from __future__ import annotations

import logging
import time
from typing import Any, Final, Mapping, Sequence

import numpy as np

from detection.exceptions import (
    FeatureValidationError,
    ModelNotLoadedError,
    PredictionError,
)
from detection.metrics_sink import MetricsSink, NullMetricsSink
from detection.model_loader import ModelLoader
from detection.models import DetectionResult, PredictionContext

logger = logging.getLogger("secopsai.detector")

_NORMAL_TRAFFIC_LABEL: Final[str] = "Normal Traffic"

_DEFAULT_MAX_MISSING_RATIO: Final[float] = 0.5


class DetectionService:
    def __init__(
        self,
        loader: ModelLoader,
        metrics: MetricsSink | None = None,
        *,
        max_missing_ratio: float = _DEFAULT_MAX_MISSING_RATIO,
    ) -> None:
        if not 0.0 <= max_missing_ratio <= 1.0:
            raise ValueError("max_missing_ratio must be in [0.0, 1.0]")

        self._loader = loader
        self._metrics = metrics if metrics is not None else NullMetricsSink()
        self._max_missing_ratio = max_missing_ratio
        self._start_time = time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(
        self,
        features: Mapping[str, float],
        context: PredictionContext | None = None,
    ) -> DetectionResult:
        self._validate_loader()
        ctx = context if context is not None else PredictionContext()

        try:
            started = time.perf_counter()
            vector = self._prepare_single_features(features, source=ctx.source)
            scaled = self._scale(vector)
            pred_classes, pred_probas = self._predict_internal(scaled)
            result = self._build_detection_result(
                pred_classes[0], pred_probas[0], ctx
            )
            latency_ms = self._measure_latency(started)
        except FeatureValidationError:
            self._metrics.record_error(
                error_type="FeatureValidationError", source=ctx.source
            )
            raise
        except PredictionError:
            self._metrics.record_error(
                error_type="PredictionError", source=ctx.source
            )
            raise

        self._log_prediction(result, latency_ms, ctx, feature_count=vector.shape[1])
        self._metrics.record_prediction(
            prediction=result.prediction,
            is_malicious=result.is_malicious,
            latency_ms=latency_ms,
            source=ctx.source,
        )
        return result

    def predict_batch(
        self,
        rows: Sequence[Mapping[str, float]],
        context: PredictionContext | None = None,
    ) -> list[DetectionResult]:
        self._validate_loader()
        ctx = context if context is not None else PredictionContext()

        try:
            started = time.perf_counter()
            matrix = self._prepare_batch_features(rows, source=ctx.source)
            scaled = self._scale(matrix)
            pred_classes, pred_probas = self._predict_internal(scaled)
            results = [
                self._build_detection_result(pred_classes[i], pred_probas[i], ctx)
                for i in range(len(pred_classes))
            ]
            latency_ms = self._measure_latency(started)
        except FeatureValidationError:
            self._metrics.record_error(
                error_type="FeatureValidationError", source=ctx.source
            )
            raise
        except PredictionError:
            self._metrics.record_error(
                error_type="PredictionError", source=ctx.source
            )
            raise

        malicious_count = sum(r.is_malicious for r in results)
        logger.info(
            "batch_prediction request_id=%s pipeline_id=%s source=%s "
            "rows=%d feature_count=%d latency_ms=%.2f malicious_count=%d "
            "model_version=%s",
            ctx.request_id,
            ctx.pipeline_id,
            ctx.source,
            len(results),
            matrix.shape[1],
            latency_ms,
            malicious_count,
            self._loader.get_model_version(),
        )
        self._metrics.record_batch(
            size=len(results),
            malicious_count=malicious_count,
            latency_ms=latency_ms,
            source=ctx.source,
        )
        return results

    def predict_batch_raw(
        self, matrix: np.ndarray, feature_names: Sequence[str]
    ) -> tuple[np.ndarray, np.ndarray]:
        self._validate_loader()

        expected = self._loader.get_features()
        if list(feature_names) != expected:
            raise FeatureValidationError(
                "feature_names must exactly match the model's expected "
                "feature order for predict_batch_raw; use predict_batch "
                "for automatic reindexing."
            )
        if matrix.ndim != 2:
            raise FeatureValidationError(
                f"Expected a 2D matrix, got array with ndim={matrix.ndim}"
            )
        if matrix.shape[0] == 0:
            raise FeatureValidationError("Batch matrix is empty")
        if matrix.shape[1] != len(expected):
            raise FeatureValidationError(
                f"Expected {len(expected)} columns, got {matrix.shape[1]}"
            )

        numeric = self._convert_numeric(matrix)
        cleaned = self._replace_nan_inf(numeric)
        scaled = self._scale(cleaned)
        return self._predict_internal(scaled)

    def warmup(self) -> float:
        self._validate_loader()

        feature_order = self._loader.get_features()
        dummy = np.zeros((1, len(feature_order)), dtype=np.float64)

        started = time.perf_counter()
        scaled = self._scale(dummy)
        self._predict_internal(scaled)
        latency_ms = self._measure_latency(started)

        logger.info("warmup_complete latency_ms=%.2f", latency_ms)
        return latency_ms

    def health(self) -> dict[str, Any]:
        loaded = self._loader.is_loaded
        feature_count = 0
        num_classes = 0
        model_version = self._loader.get_model_version()

        if loaded:
            try:
                feature_count = len(self._loader.get_features())
                num_classes = len(self._loader.get_label_encoder().classes_)
            except Exception as exc:  # noqa: BLE001 - health must not raise
                logger.warning("health_check_degraded error=%s", exc)
                loaded = False

        return {
            "status": "healthy" if loaded else "degraded",
            "ready": loaded,
            "model_loaded": loaded,
            "model_version": model_version,
            "feature_count": feature_count,
            "num_classes": num_classes,
            "normal_label": _NORMAL_TRAFFIC_LABEL,
            "started_at": self._started_at_iso(),
            "uptime_seconds": round(time.monotonic() - self._start_time, 2),
        }

    def model_info(self) -> dict[str, Any]:
        self._validate_loader()

        model = self._loader.get_model()
        scaler = self._loader.get_scaler()
        label_encoder = self._loader.get_label_encoder()
        features = self._loader.get_features()

        return {
            "model_type": type(model).__name__,
            "model_library": type(model).__module__.split(".")[0],
            "model_version": self._loader.get_model_version(),
            "classes": list(label_encoder.classes_),
            "normal_class": _NORMAL_TRAFFIC_LABEL,
            "training_features": list(features),
            "feature_count": len(features),
            "artifact_names": {
                "model": type(model).__name__,
                "scaler": type(scaler).__name__,
                "label_encoder": type(label_encoder).__name__,
            },
        }

    # ------------------------------------------------------------------
    # Feature preparation
    # ------------------------------------------------------------------

    def _prepare_single_features(
        self, features: Mapping[str, float], *, source: str
    ) -> np.ndarray:
        if not isinstance(features, Mapping):
            raise FeatureValidationError(
                f"Expected a mapping of features, got {type(features).__name__}"
            )

        feature_order = self._loader.get_features()
        self._detect_unknown_features(set(features.keys()), set(feature_order), source)
        self._validate_missing_ratio(set(features.keys()), feature_order)
        filled = self._fill_missing_features(features, feature_order)

        raw_row = np.array(
            [[filled[name] for name in feature_order]], dtype=object
        )
        row = self._convert_numeric(raw_row)
        return self._replace_nan_inf(row)

    def _prepare_batch_features(
        self, rows: Sequence[Mapping[str, float]], *, source: str
    ) -> np.ndarray:
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            raise FeatureValidationError(
                f"Expected a sequence of feature mappings, got {type(rows).__name__}"
            )
        if len(rows) == 0:
            raise FeatureValidationError("Batch is empty")
        if not all(isinstance(row, Mapping) for row in rows):
            raise FeatureValidationError(
                "Every row in the batch must be a mapping of feature name to value"
            )

        feature_order = self._loader.get_features()
        all_keys: set[str] = set()
        for row in rows:
            all_keys.update(row.keys())
            self._validate_missing_ratio(set(row.keys()), feature_order)
        self._detect_unknown_features(all_keys, set(feature_order), source)

        raw_matrix = np.array(
            [[row.get(name, 0.0) for name in feature_order] for row in rows],
            dtype=object,
        )
        matrix = self._convert_numeric(raw_matrix)
        return self._replace_nan_inf(matrix)

    def _validate_missing_ratio(
        self, provided: set[str], feature_order: list[str]
    ) -> None:
        missing = set(feature_order) - provided
        missing_ratio = len(missing) / len(feature_order)
        if missing_ratio > self._max_missing_ratio:
            raise FeatureValidationError(
                f"Input is missing {len(missing)}/{len(feature_order)} "
                f"expected features (missing_ratio={missing_ratio:.2f}), "
                f"which exceeds max_missing_ratio="
                f"{self._max_missing_ratio:.2f}"
            )

    @staticmethod
    def _fill_missing_features(
        features: Mapping[str, float], feature_order: list[str]
    ) -> dict[str, float]:
        """Fill any feature names absent from ``features`` with ``0.0``."""
        return {name: features.get(name, 0.0) for name in feature_order}

    def _detect_unknown_features(
        self, provided: set[str], expected: set[str], source: str
    ) -> None:
        unknown = provided - expected
        if unknown:
            logger.warning("unknown_features_ignored count=%d source=%s", len(unknown), source)
            self._metrics.record_unknown_features(count=len(unknown), source=source)

    @staticmethod
    def _convert_numeric(array: np.ndarray) -> np.ndarray:
        try:
            return array.astype(np.float64)
        except (TypeError, ValueError) as exc:
            raise FeatureValidationError(
                f"Feature values could not be converted to numeric type: {exc}"
            ) from exc

    @staticmethod
    def _replace_nan_inf(array: np.ndarray) -> np.ndarray:
        return np.nan_to_num(array, nan=0.0, posinf=0.0, neginf=0.0)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def _scale(self, matrix: np.ndarray) -> np.ndarray:
        try:
            return self._loader.get_scaler().transform(matrix)
        except Exception as exc:  # noqa: BLE001 - normalize to PredictionError
            raise PredictionError(f"Feature scaling failed: {exc}") from exc

    def _predict_internal(
        self, scaled: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray]:
        try:
            model = self._loader.get_model()
            pred_classes = model.predict(scaled)
            pred_probas = model.predict_proba(scaled)
            return pred_classes, pred_probas
        except Exception as exc:  # noqa: BLE001 - normalize to PredictionError
            raise PredictionError(f"Model inference failed: {exc}") from exc

    def _build_detection_result(
        self, pred_class: Any, pred_proba: np.ndarray, context: PredictionContext
    ) -> DetectionResult:
        try:
            label_encoder = self._loader.get_label_encoder()
            label = str(label_encoder.inverse_transform([pred_class])[0])
        except Exception as exc:  # noqa: BLE001 - normalize to PredictionError
            raise PredictionError(f"Label decoding failed: {exc}") from exc

        confidence = float(np.max(pred_proba))
        is_malicious = label != _NORMAL_TRAFFIC_LABEL
        threat_score = self._compute_threat_score(
            label, confidence, pred_proba, label_encoder
        )

        return DetectionResult(
            prediction=label,
            confidence=confidence,
            threat_score=threat_score,
            is_malicious=is_malicious,
            request_id=context.request_id,
            model_version=self._loader.get_model_version(),
        )

    @staticmethod
    def _compute_threat_score(
        label: str,
        confidence: float,
        pred_proba: np.ndarray,
        label_encoder: Any,
    ) -> float:
        classes = list(label_encoder.classes_)
        if _NORMAL_TRAFFIC_LABEL in classes:
            normal_index = classes.index(_NORMAL_TRAFFIC_LABEL)
            return 1.0 - float(pred_proba[normal_index])
        return confidence

    # ------------------------------------------------------------------
    # Cross-cutting concerns
    # ------------------------------------------------------------------

    def _validate_loader(self) -> None:
        if not self._loader.is_loaded:
            raise ModelNotLoadedError(
                "DetectionService cannot run inference: model artifacts "
                "have not been loaded. Call loader.load() before predicting."
            )

    @staticmethod
    def _measure_latency(started_at: float) -> float:
        return (time.perf_counter() - started_at) * 1000.0

    def _started_at_iso(self) -> str:
        elapsed = time.monotonic() - self._start_time
        wall_clock_start = time.time() - elapsed
        return time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall_clock_start)
        )

    @staticmethod
    def _log_prediction(
        result: DetectionResult,
        latency_ms: float,
        context: PredictionContext,
        *,
        feature_count: int,
    ) -> None:
        logger.info(
            "prediction=%s confidence=%.4f malicious=%s latency_ms=%.2f "
            "feature_count=%d request_id=%s pipeline_id=%s source=%s "
            "model_version=%s",
            result.prediction,
            result.confidence,
            result.is_malicious,
            latency_ms,
            feature_count,
            context.request_id,
            context.pipeline_id,
            context.source,
            result.model_version,
        )
