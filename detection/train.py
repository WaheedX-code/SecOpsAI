"""
SecOpsAI — ML Detection Model
XGBoost classifier trained on CICIDS 2017 features.
Target: Beat rule baseline F1 macro of 0.1305 by 15% (must reach 0.2805+)
"""

import json
import logging
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score
)
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb
import joblib
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.training")


# ─── Feature Selection ────────────────────────────────────────────────────────
# These features are selected based on domain knowledge of network attacks.
# Ablation study will confirm which ones matter most.

FEATURES = [
    # Flow volume features
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',

    # Packet size features
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',

    # Timing features — critical for C2 beaconing detection
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Bwd IAT Mean',

    # Flag features — critical for port scan and brute force
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',

    # Header features
    'Fwd Header Length',
    'Bwd Header Length',

    # Subflow features
    'Subflow Fwd Packets',
    'Subflow Fwd Bytes',
    'Subflow Bwd Packets',
    'Subflow Bwd Bytes',

    # Active/idle timing
    'Active Mean',
    'Active Std',
    'Idle Mean',
    'Idle Std',
]

LABEL_COL = 'Attack Type'


# ─── Data Loading & Preprocessing ────────────────────────────────────────────

def load_and_preprocess(path: str, sample_size: int = 500_000):
    logger.info(f"Loading dataset from {path}...")
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    logger.info(f"Loaded {len(df):,} records")

    # Keep only columns we need
    available_features = [f for f in FEATURES if f in df.columns]
    missing = set(FEATURES) - set(available_features)
    if missing:
        logger.warning(f"Missing features: {missing}")

    df.columns = df.columns.str.strip()
    df[LABEL_COL] = df[LABEL_COL].str.strip()
    df = df[available_features + [LABEL_COL]].copy()

    # Drop nulls and infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    logger.info(f"Dropped {before - len(df):,} rows with nulls/infs")

    # Sample for training speed — stratified to keep class distribution
    if len(df) > sample_size:
        classes = df[LABEL_COL].unique()
        samples = []
        for cls in classes:
            cls_df = df[df[LABEL_COL] == cls]
            n = max(1, int(sample_size * len(cls_df) / len(df)))
            samples.append(cls_df.sample(min(len(cls_df), n), random_state=42))
        df = pd.concat(samples, ignore_index=True)
        logger.info(f"Stratified sample: {len(df):,} records")

    logger.info(f"Class distribution:\n{df[LABEL_COL].value_counts()}")


    # Strip again after groupby — pandas can reintroduce whitespace
    df.columns = df.columns.str.strip()
    df[LABEL_COL] = df[LABEL_COL].str.strip()
    
    logger.info(f"Class distribution:\n{df[LABEL_COL].value_counts()}")
    return df, available_features

def encode_labels(df, label_col):
    le = LabelEncoder()
    y = le.fit_transform(df[label_col])
    logger.info(f"Classes: {list(le.classes_)}")
    return y, le


# ─── Model Training ───────────────────────────────────────────────────────────

def train_xgboost(X_train, y_train, num_classes):
    logger.info("Training XGBoost classifier...")

    # Handle class imbalance with sample weights
    sample_weights = compute_sample_weight('balanced', y_train)

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric='mlogloss',
        num_class=num_classes,
        objective='multi:softprob',
        random_state=42,
        n_jobs=-1,
        tree_method='hist',  # Fast CPU training
    )

    model.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_train, y_train)],
        verbose=100
    )

    return model


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, le, model_name="xgboost"):
    logger.info(f"Evaluating {model_name}...")
    y_pred = model.predict(X_test)

    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    precision = precision_score(y_test, y_pred, average='macro', zero_division=0)
    recall = recall_score(y_test, y_pred, average='macro', zero_division=0)

    logger.info("=" * 60)
    logger.info(f"MODEL RESULTS — {model_name.upper()}")
    logger.info("=" * 60)
    logger.info(f"F1 Score (macro):    {f1_macro:.4f}")
    logger.info(f"F1 Score (weighted): {f1_weighted:.4f}")
    logger.info(f"Precision (macro):   {precision:.4f}")
    logger.info(f"Recall (macro):      {recall:.4f}")
    logger.info("=" * 60)

    report = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        zero_division=0
    )
    logger.info(f"\n{report}")

    return {
        'model': model_name,
        'f1_macro': round(f1_macro, 4),
        'f1_weighted': round(f1_weighted, 4),
        'precision_macro': round(precision, 4),
        'recall_macro': round(recall, 4),
    }


# ─── Ablation Study ───────────────────────────────────────────────────────────

def ablation_study(model, X_test, y_test, feature_names):
    """
    Feature importance analysis — which features matter most?
    Uses XGBoost's built-in feature importance scores.
    """
    logger.info("Running ablation study...")

    importances = model.feature_importances_
    feature_importance = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True
    )

    logger.info("Top 15 most important features:")
    logger.info(f"{'Feature':<35} {'Importance':>10}")
    logger.info("-" * 47)
    for feat, imp in feature_importance[:15]:
        logger.info(f"{feat:<35} {imp:>10.4f}")

    # Save ablation results
    ablation_results = [
        {'feature': f, 'importance': round(float(i), 6)}
        for f, i in feature_importance
    ]
    with open('detection/ablation_results.json', 'w') as f:
        json.dump(ablation_results, f, indent=2)

    logger.info("Ablation results saved to detection/ablation_results.json")
    return feature_importance


# ─── Compare vs Baseline ──────────────────────────────────────────────────────

def compare_with_baseline(ml_metrics):
    try:
        with open('detection/baseline_metrics.json') as f:
            baseline = json.load(f)

        baseline_f1 = baseline['f1_macro']
        ml_f1 = ml_metrics['f1_macro']
        improvement = ml_f1 - baseline_f1
        target = baseline_f1 + 0.15
        passed = ml_f1 >= target

        logger.info("=" * 60)
        logger.info("COMPARISON VS RULE BASELINE")
        logger.info("=" * 60)
        logger.info(f"Baseline F1 macro:  {baseline_f1:.4f}")
        logger.info(f"ML F1 macro:        {ml_f1:.4f}")
        logger.info(f"Improvement:        +{improvement:.4f}")
        logger.info(f"Target (baseline+15%): {target:.4f}")
        logger.info(f"PASSED: {passed}")
        logger.info("=" * 60)

        return passed, improvement

    except FileNotFoundError:
        logger.warning("baseline_metrics.json not found — run baseline.py first")
        return None, None


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs('detection/models', exist_ok=True)

    # Load and preprocess
    df, features = load_and_preprocess(
        'data/raw/cicids2017/cicids2017_cleaned.csv',
        sample_size=500_000
    )

    # Encode labels
    y, le = encode_labels(df, LABEL_COL)
    X = df[features].values

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split — stratified
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    logger.info(f"Train: {len(X_train):,} | Test: {len(X_test):,}")

    # Train XGBoost
    model = train_xgboost(X_train, y_train, num_classes=len(le.classes_))

    # Evaluate
    metrics = evaluate_model(model, X_test, y_test, le, "xgboost")

    # Ablation study
    ablation_study(model, X_test, y_test, features)

    # Compare vs baseline
    passed, improvement = compare_with_baseline(metrics)

    # Save model and artifacts
    joblib.dump(model, 'detection/models/xgboost_detector.pkl')
    joblib.dump(scaler, 'detection/models/scaler.pkl')
    joblib.dump(le, 'detection/models/label_encoder.pkl')

    with open('detection/ml_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)

    logger.info("Model saved to detection/models/")
    logger.info("Training complete.")
