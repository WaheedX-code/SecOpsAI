"""
SecOpsAI — Pipeline Unit Tests
"""

import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path


def test_baseline_metrics_exist():
    """Baseline metrics file must exist."""
    assert Path("detection/baseline_metrics.json").exists()


def test_ml_metrics_exist():
    """ML metrics file must exist."""
    assert Path("detection/ml_metrics.json").exists()


def test_ml_beats_baseline():
    """ML model must beat baseline by at least 15% F1."""
    with open("detection/baseline_metrics.json") as f:
        baseline = json.load(f)
    with open("detection/ml_metrics.json") as f:
        ml = json.load(f)

    improvement = ml["f1_macro"] - baseline["f1_macro"]
    assert improvement >= 0.15, (
        f"ML F1 {ml['f1_macro']} must beat baseline "
        f"{baseline['f1_macro']} by 0.15. Got: {improvement:.4f}"
    )


def test_model_files_exist():
    """Trained model artifacts must exist."""
    assert Path("detection/models/xgboost_detector.pkl").exists()
    assert Path("detection/models/scaler.pkl").exists()
    assert Path("detection/models/label_encoder.pkl").exists()


def test_ablation_results_exist():
    """Ablation study results must exist."""
    path = Path("detection/ablation_results.json")
    assert path.exists()
    with open(path) as f:
        results = json.load(f)
    assert len(results) > 0
    assert "feature" in results[0]
    assert "importance" in results[0]


def test_hash_chain():
    """Hash chain validation must work."""
    from ingestion.pipeline import HashChain
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmp_path = f.name

    try:
        chain = HashChain(chain_file=tmp_path)
        chain.append({"test": "record1"})
        chain.append({"test": "record2"})
        chain.append({"test": "record3"})
        assert chain.verify() is True
    finally:
        os.unlink(tmp_path)


def test_schema_validation():
    """Schema validator must reject out-of-bounds records."""
    from ingestion.pipeline import validate_record

    valid = {
        "duration": 10,
        "packet_count": 100,
        "byte_count": 5000,
        "flow_bytes_per_sec": 500,
        "flow_packets_per_sec": 10,
        "entropy": 3.5
    }
    is_valid, violations = validate_record(valid)
    assert is_valid is True
    assert len(violations) == 0

    invalid = {
        "duration": 10,
        "packet_count": -1,
        "byte_count": 5000,
        "flow_bytes_per_sec": 500,
        "flow_packets_per_sec": 10,
        "entropy": 99.9
    }
    is_valid, violations = validate_record(invalid)
    assert is_valid is False
    assert len(violations) > 0


def test_adversarial_injection_rejected():
    """Adversarial injection test must reject all malformed records."""
    from ingestion.pipeline import validate_record

    adversarial_samples = [
        {"duration": 10, "packet_count": 100, "byte_count": 5000,
         "flow_bytes_per_sec": 500, "flow_packets_per_sec": 10, "entropy": 99.9},
        {"duration": 5, "packet_count": -1, "byte_count": 100,
         "flow_bytes_per_sec": 20, "flow_packets_per_sec": -1, "entropy": 3.2},
        {"duration": 1, "packet_count": 999999999, "byte_count": 999999999999,
         "flow_bytes_per_sec": 999999999999, "flow_packets_per_sec": 999999999,
         "entropy": 7.9},
    ]

    for sample in adversarial_samples:
        is_valid, _ = validate_record(sample)
        assert is_valid is False, f"Should have rejected: {sample}"
