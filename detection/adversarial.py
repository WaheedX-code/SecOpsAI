"""
SecOpsAI — Adversarial Robustness Testing
"""

import json
import logging
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import f1_score
from sklearn.preprocessing import LabelEncoder

from art.estimators.classification import SklearnClassifier
from art.attacks.evasion import (
    HopSkipJump,
    ZooAttack,
    BoundaryAttack,
    DecisionTreeAttack,
    SquareAttack,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.adversarial")


# ─── Load Model & Data ────────────────────────────────────────────────────────

def load_artifacts():
    logger.info("Loading model artifacts...")
    model = joblib.load('detection/models/xgboost_detector.pkl')
    scaler = joblib.load('detection/models/scaler.pkl')
    le = joblib.load('detection/models/label_encoder.pkl')
    return model, scaler, le


def load_test_data(scaler, le, n_samples=500):
    """Load a small test set for adversarial attacks — attacks are slow."""
    logger.info(f"Loading {n_samples} test samples...")
    df = pd.read_csv(
        'data/raw/cicids2017/cicids2017_cleaned.csv',
        low_memory=False
    )
    df.columns = df.columns.str.strip()
    df['Attack Type'] = df['Attack Type'].str.strip()

    # Load feature list from ablation results
    with open('detection/ablation_results.json') as f:
        ablation = json.load(f)
    features = [item['feature'] for item in ablation]
    available = [f for f in features if f in df.columns]

    # Sample balanced across classes
    samples = []
    for cls in df['Attack Type'].unique():
        cls_df = df[df['Attack Type'] == cls]
        n = min(len(cls_df), max(1, n_samples // len(df['Attack Type'].unique())))
        samples.append(cls_df.sample(n, random_state=42))
    df_sample = pd.concat(samples, ignore_index=True)

    # Handle known label encoder classes only
    known_classes = list(le.classes_)
    df_sample = df_sample[df_sample['Attack Type'].isin(known_classes)]

    X = df_sample[available].values.astype(np.float32)
    y = le.transform(df_sample['Attack Type'])

    # Replace inf/nan
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X).astype(np.float32)

    logger.info(f"Test set: {len(X_scaled)} samples, {X_scaled.shape[1]} features")
    return X_scaled, y, available


# ─── ART Classifier Wrapper ───────────────────────────────────────────────────

def build_art_classifier(model, X_sample):
    """Wrap XGBoost in ART using XGBoostClassifier wrapper."""
    from art.estimators.classification import XGBoostClassifier
    import xgboost as xgb

    # Convert to Booster format which ART accepts
    booster = model.get_booster()
    
    classifier = XGBoostClassifier(
        model=booster,
        nb_features=X_sample.shape[1],
        nb_classes=model.n_classes_,
        clip_values=(float(X_sample.min()), float(X_sample.max()))
    )
    return classifier


# ─── Attack Suite ─────────────────────────────────────────────────────────────

def run_hopskipjump(classifier, X, y):
    """
    HopSkipJump — black-box boundary attack.
    Finds minimal perturbation to cross decision boundary.
    Most realistic attack — assumes no model internals.
    """
    logger.info("Running HopSkipJump attack...")
    attack = HopSkipJump(
        classifier=classifier,
        targeted=False,
        max_iter=20,
        max_eval=100,
        init_eval=10,
        verbose=False
    )
    # Attack subset — HopSkipJump is slow
    X_subset = X[:50]
    y_subset = y[:50]
    X_adv = attack.generate(x=X_subset)
    return X_adv, y_subset


def run_zoo(classifier, X, y):
    """
    ZOO — Zeroth Order Optimization attack.
    Estimates gradients via finite differences.
    No model access needed.
    """
    logger.info("Running ZOO attack...")
    attack = ZooAttack(
        classifier=classifier,
        confidence=0.0,
        targeted=False,
        learning_rate=1e-1,
        max_iter=20,
        binary_search_steps=5,
        initial_const=1e-3,
        abort_early=True,
        use_resize=False,
        nb_parallel=1,
        variable_h=0.2,
        verbose=False
    )
    X_subset = X[:30]
    y_subset = y[:30]
    X_adv = attack.generate(x=X_subset)
    return X_adv, y_subset


def run_boundary(classifier, X, y):
    """
    Boundary Attack — decision-based black-box attack.
    Starts from a misclassified point and moves toward original.
    """
    logger.info("Running Boundary Attack...")
    attack = BoundaryAttack(
        estimator=classifier,
        targeted=False,
        delta=0.01,
        epsilon=0.01,
        step_adapt=0.667,
        max_iter=200,
        num_trial=25,
        sample_size=20,
        init_size=100,
        verbose=False
    )
    X_subset = X[:30]
    y_subset = y[:30]
    X_adv = attack.generate(x=X_subset)
    return X_adv, y_subset


def run_decision_tree(classifier, X, y):
    """
    Decision Tree Attack — white-box attack specific to tree models.
    Exploits the tree structure directly to find adversarial paths.
    Most dangerous for XGBoost.
    """
    logger.info("Running Decision Tree Attack...")
    attack = DecisionTreeAttack(
        classifier=classifier,
        verbose=False
    )
    X_subset = X[:100]
    y_subset = y[:100]
    X_adv = attack.generate(x=X_subset)
    return X_adv, y_subset


def run_square_attack(classifier, X, y):
    """
    Square Attack --- score based black-box attack.
    Uses random square-shaped perturbations.
    Highly query-efficient, no gradient needed.
    """
    logger.info("Running Square Attack...")
    attack = SquareAttack(
        estimator=classifier,
        norm=np.inf,
        max_iter=100,
        eps=0.3,
        p_init=0.8,
        nb_restarts=1,
        verbose=False
    )
    X_subset = X[:50]
    y_subset = y[:50]
    X_adv = attack.generate(x=X_subset)
    return X_adv, y_subset


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_attack(model, X_clean, X_adv, y_true, attack_name):
    """Compare model performance on clean vs adversarial examples."""
    y_pred_clean = model.predict(X_clean)
    y_pred_adv = model.predict(X_adv)

    f1_clean = f1_score(y_true, y_pred_clean, average='macro', zero_division=0)
    f1_adv = f1_score(y_true, y_pred_adv, average='macro', zero_division=0)
    degradation = f1_clean - f1_adv

    logger.info(f"\n{'='*50}")
    logger.info(f"Attack: {attack_name}")
    logger.info(f"F1 clean:        {f1_clean:.4f}")
    logger.info(f"F1 adversarial:  {f1_adv:.4f}")
    logger.info(f"Degradation:     -{degradation:.4f}")
    logger.info(f"{'='*50}")

    return {
        'attack': attack_name,
        'f1_clean': round(f1_clean, 4),
        'f1_adversarial': round(f1_adv, 4),
        'degradation': round(degradation, 4)
    }


# ─── Adversarial Retraining ───────────────────────────────────────────────────

def adversarial_retrain(model, scaler, le, X_adv_all, y_adv_all):
    """
    Retrain model with adversarial examples mixed into training data.
    This is the hardening step.
    """
    logger.info("Starting adversarial retraining...")

    # Load original training data
    df = pd.read_csv(
        'data/raw/cicids2017/cicids2017_cleaned.csv',
        low_memory=False
    )
    df.columns = df.columns.str.strip()
    df['Attack Type'] = df['Attack Type'].str.strip()

    with open('detection/ablation_results.json') as f:
        ablation = json.load(f)
    features = [item['feature'] for item in ablation
                if item['feature'] in df.columns]

    # Sample clean training data
    known_classes = list(le.classes_)
    df = df[df['Attack Type'].isin(known_classes)]

    samples = []
    for cls in df['Attack Type'].unique():
        cls_df = df[df['Attack Type'] == cls]
        samples.append(cls_df.sample(min(len(cls_df), 5000), random_state=42))
    df_train = pd.concat(samples, ignore_index=True)

    X_clean = scaler.transform(
        np.nan_to_num(df_train[features].values.astype(np.float32))
    )
    y_clean = le.transform(df_train['Attack Type'])

    # Mix adversarial examples into training set
    X_combined = np.vstack([X_clean, X_adv_all])
    y_combined = np.concatenate([y_clean, y_adv_all])

    logger.info(f"Combined training set: {len(X_combined):,} samples")
    logger.info(f"  Clean: {len(X_clean):,} | Adversarial: {len(X_adv_all):,}")

    # Retrain
    import xgboost as xgb
    from sklearn.utils.class_weight import compute_sample_weight

    sample_weights = compute_sample_weight('balanced', y_combined)
    hardened_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='mlogloss',
        objective='multi:softprob',
        num_class=len(le.classes_),
        random_state=42,
        n_jobs=-1,
        tree_method='hist',
    )
    hardened_model.fit(X_combined, y_combined, sample_weight=sample_weights)

    # Save hardened model
    joblib.dump(hardened_model, 'detection/models/xgboost_hardened.pkl')
    logger.info("Hardened model saved to detection/models/xgboost_hardened.pkl")
    return hardened_model


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Load artifacts
    model, scaler, le = load_artifacts()
    X_test, y_test, features = load_test_data(scaler, le, n_samples=500)

    # Build ART classifier
    classifier = build_art_classifier(model, X_test)

    # Run all 5 attacks
    results = []
    all_adv_X = []
    all_adv_y = []

    attacks = [
        ('HopSkipJump', run_hopskipjump),
        ('ZOO',         run_zoo),
        ('Boundary',    run_boundary),
        ('DecisionTree',run_decision_tree),
        ('SquareAttack',run_square_attack),
    ]

    for attack_name, attack_fn in attacks:
        try:
            X_adv, y_adv = attack_fn(classifier, X_test, y_test)
            result = evaluate_attack(model, X_test[:len(X_adv)], X_adv, y_adv, attack_name)
            results.append(result)
            all_adv_X.append(X_adv)
            all_adv_y.append(y_adv)
        except Exception as e:
            logger.error(f"Attack {attack_name} failed: {e}")
            results.append({
                'attack': attack_name,
                'f1_clean': None,
                'f1_adversarial': None,
                'degradation': None,
                'error': str(e)
            })

    # Save pre-hardening results
    with open('detection/adversarial_results_pre.json', 'w') as f:
        json.dump(results, f, indent=2)
    logger.info("Pre-hardening results saved")

    # Adversarial retraining
    if all_adv_X:
        X_adv_all = np.vstack(all_adv_X)
        y_adv_all = np.concatenate(all_adv_y)
        hardened_model = adversarial_retrain(model, scaler, le, X_adv_all, y_adv_all)

        # Evaluate hardened model on same adversarial examples
        hardened_results = []
        adv_idx = 0
        for i, (attack_name, _) in enumerate(attacks):
            if i < len(all_adv_X):
                X_adv = all_adv_X[i]
                y_adv = all_adv_y[i]
                result = evaluate_attack(
                    hardened_model,
                    X_test[:len(X_adv)],
                    X_adv, y_adv,
                    f"{attack_name}_hardened"
                )
                hardened_results.append(result)

        with open('detection/adversarial_results_post.json', 'w') as f:
            json.dump(hardened_results, f, indent=2)
        logger.info("Post-hardening results saved")

    logger.info("Adversarial robustness testing complete.")

