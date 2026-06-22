"""
SecOpsAI — Rule-Based Baseline Detector
Mimics Suricata/Snort threshold logic using feature thresholds.
This is the benchmark the ML model must beat by 15% F1.
"""

import logging
import pandas as pd
import numpy as np
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.baseline")


# ─── Rule Definitions ─────────────────────────────────────────────────────────
# Each rule mimics a Suricata threshold rule.
# These are intentionally simple — that's the point.
# The ML model will learn patterns these rules miss entirely.

def rule_dos(row) -> bool:
    """
    Rule: Flag as DoS if flow generates extremely high packet rate
    Suricata equivalent: threshold type both, track by_src, count 1000, seconds 1
    """
    return (
        row.get('Flow Packets/s', 0) > 10000 or
        row.get('Flow Bytes/s', 0) > 1_000_000
    )


def rule_ddos(row) -> bool:
    """
    Rule: Flag as DDoS if very short flows with high packet counts
    Suricata equivalent: detection_filter track by_dst, count 500, seconds 1
    """
    return (
        row.get('Flow Duration', 999) < 100 and
        row.get('Total Fwd Packets', 0) > 100
    )


def rule_port_scan(row) -> bool:
    """
    Rule: Flag as Port Scan if small packets sent rapidly with no response
    Suricata equivalent: threshold type threshold, track by_src, count 100, seconds 10
    """
    return (
        row.get('Fwd Packet Length Mean', 999) < 10 and
        row.get('Bwd Packet Length Mean', 999) < 10 and
        row.get('Flow Packets/s', 0) > 100
    )


def rule_brute_force(row) -> bool:
    """
    Rule: Flag as Brute Force if many small forward packets, few backward
    Suricata equivalent: threshold type both, track by_src, count 20, seconds 60
    """
    fwd = row.get('Total Fwd Packets', 0)
    bwd = row.get('Total Backward Packets', 0)
    return (
        fwd > 20 and
        bwd < 5 and
        row.get('Fwd Packet Length Mean', 999) < 50
    )


def rule_web_attack(row) -> bool:
    """
    Rule: Flag as Web Attack if long packets with abnormal flag patterns
    Suricata equivalent: content match on PSH+ACK with large payload
    """
    return (
        row.get('Fwd Packet Length Max', 0) > 1000 and
        row.get('PSH Flag Count', 0) > 5 and
        row.get('ACK Flag Count', 0) > 5
    )


def rule_bot(row) -> bool:
    """
    Rule: Flag as Bot/C2 if periodic low-volume traffic with consistent timing
    Suricata equivalent: threshold type both, track by_src, count 5, seconds 300
    This is intentionally weak — bots vary timing to evade exactly this rule.
    """
    return (
        row.get('Flow IAT Mean', 0) > 1000 and
        row.get('Flow IAT Std', 999) < 500 and
        row.get('Total Fwd Packets', 999) < 20
    )


# ─── Rule Engine ──────────────────────────────────────────────────────────────

RULES = {
    'DoS':           rule_dos,
    'DDoS':          rule_ddos,
    'Port Scanning': rule_port_scan,
    'Brute Force':   rule_brute_force,
    'Web Attacks':   rule_web_attack,
    'Bots':          rule_bot,
}


def apply_rules(df: pd.DataFrame) -> pd.Series:
    """
    Apply all rules to dataframe.
    Returns predicted labels — first matching rule wins.
    If no rule fires, classify as Normal Traffic.
    """
    predictions = pd.Series(['Normal Traffic'] * len(df), index=df.index)

    for label, rule_fn in RULES.items():
        mask = df.apply(rule_fn, axis=1)
        predictions[mask] = label
        logger.info(f"Rule '{label}' fired on {mask.sum():,} records")

    return predictions


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_baseline(df: pd.DataFrame):
    """
    Evaluate rule-based baseline against ground truth labels.
    Logs full classification report and saves metrics.
    """
    logger.info("Applying rule-based detection...")

    # Clean column names
    df.columns = df.columns.str.strip()

    # Sample for speed — 200k records is enough for baseline eval
    if len(df) > 200_000:
        df = df.sample(n=200_000, random_state=42)
        logger.info("Sampled 200,000 records for baseline evaluation")

    y_true = df['Attack Type'].str.strip()
    y_pred = apply_rules(df)

    # Overall metrics
    f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    precision = precision_score(y_true, y_pred, average='macro', zero_division=0)
    recall = recall_score(y_true, y_pred, average='macro', zero_division=0)

    logger.info("=" * 60)
    logger.info("BASELINE RESULTS")
    logger.info("=" * 60)
    logger.info(f"F1 Score (macro):    {f1_macro:.4f}")
    logger.info(f"F1 Score (weighted): {f1_weighted:.4f}")
    logger.info(f"Precision (macro):   {precision:.4f}")
    logger.info(f"Recall (macro):      {recall:.4f}")
    logger.info("=" * 60)

    # Per-class report
    report = classification_report(
        y_true, y_pred, zero_division=0
    )
    logger.info(f"\n{report}")

    # Confusion matrix
    labels = sorted(y_true.unique())
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    logger.info("Confusion Matrix:")
    logger.info(f"Labels: {labels}")
    logger.info(f"\n{cm}")

    # Save metrics for comparison with ML model
    metrics = {
        'model': 'rule_baseline',
        'f1_macro': round(f1_macro, 4),
        'f1_weighted': round(f1_weighted, 4),
        'precision_macro': round(precision, 4),
        'recall_macro': round(recall, 4),
    }

    import json
    with open('detection/baseline_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)

    logger.info("Metrics saved to detection/baseline_metrics.json")
    logger.info(f"ML model must beat F1 macro of: {f1_macro + 0.15:.4f}")

    return metrics


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Loading dataset...")
    df = pd.read_csv(
        'data/raw/cicids2017/cicids2017_cleaned.csv',
        low_memory=False
    )
    logger.info(f"Loaded {len(df):,} records")
    metrics = evaluate_baseline(df)
