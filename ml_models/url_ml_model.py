from __future__ import annotations

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Project root / imports
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# Allows this file to work when run directly:
# python ml_models/url_ml_model.py
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd

from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from models.utils.Features import analyze_url


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_PATH = BASE_DIR / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

FEATURE_CACHE = MODELS_DIR / "url_features.npy"
META_PATH = MODELS_DIR / "url_features_meta.json"


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def registered_group(url: str) -> str:
    """Return the registered domain used for group-aware splitting."""
    try:
        domain = analyze_url(url).get("registered_domain")
        return str(domain).strip().lower() if domain else str(url).strip().lower()
    except Exception:
        return str(url).strip().lower()


def extract_matrix(urls: list[str]) -> np.ndarray:
    """Extract URL features using the project's analyze_url() function."""
    rows: list[np.ndarray] = []
    expected_features: int | None = None

    for i, url in enumerate(urls, start=1):
        try:
            result = analyze_url(url)
            features = np.asarray(result["features"], dtype=float).reshape(-1)

            if expected_features is None:
                expected_features = len(features)

            if len(features) != expected_features:
                raise ValueError(
                    f"Feature count mismatch for URL '{url}': "
                    f"expected {expected_features}, got {len(features)}"
                )

            rows.append(features)

        except Exception as exc:
            # Once the feature count is known, preserve the matrix shape.
            if expected_features is None:
                # The project currently expects 36 URL features.
                expected_features = 36

            rows.append(np.zeros(expected_features, dtype=float))

            if i <= 10:
                print(f"Warning: feature extraction failed for URL {i}: {exc}")

        if i % 10000 == 0:
            print(f"Extracted {i:,} URLs...")

    if not rows:
        raise ValueError("No URLs were available for feature extraction.")

    X = np.vstack(rows)

    print(f"Feature matrix shape: {X.shape}")
    return X


# ---------------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------------
def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found:\n{DATA_PATH}\n\n"
            "Make sure PhiUSIIL_Phishing_URL_Dataset.csv is inside datasets/."
        )

    print(f"Dataset: {DATA_PATH}")

    # Read only the columns required by this training script.
    df = pd.read_csv(
        DATA_PATH,
        usecols=["URL", "label"],
    ).dropna(subset=["URL", "label"])

    df["URL"] = df["URL"].astype(str).str.strip()
    df = (
        df[df["URL"] != ""]
        .drop_duplicates("URL")
        .reset_index(drop=True)
    )

    if df.empty:
        raise ValueError("The URL dataset contains no usable rows.")

    # PhiUSIIL convention:
    # raw label 1 = legitimate
    # raw label 0 = phishing
    #
    # Project convention:
    # 0 = legitimate
    # 1 = phishing
    raw_labels = pd.to_numeric(df["label"], errors="coerce")

    if raw_labels.isna().any():
        raise ValueError("The dataset contains non-numeric values in 'label'.")

    unique_labels = set(raw_labels.astype(int).unique())
    if not unique_labels.issubset({0, 1}):
        raise ValueError(
            f"Unexpected URL labels found: {sorted(unique_labels)}. "
            "Expected only 0 and 1."
        )

    y = (1 - raw_labels.astype(int)).to_numpy()
    urls = df["URL"].tolist()

    print(f"Usable URLs: {len(urls):,}")
    print(f"Legitimate: {int(np.sum(y == 0)):,}")
    print(f"Phishing:   {int(np.sum(y == 1)):,}")

    # -----------------------------------------------------------------------
    # Feature extraction / cache
    # -----------------------------------------------------------------------
    cache_ok = False

    if FEATURE_CACHE.exists() and META_PATH.exists():
        try:
            meta = json.loads(META_PATH.read_text(encoding="utf-8"))

            cache_ok = (
                meta.get("row_count") == len(urls)
                and meta.get("feature_count") == 36
                and meta.get("source") == DATA_PATH.name
            )

            if cache_ok:
                X = np.load(FEATURE_CACHE)

                if X.shape != (len(urls), int(meta["feature_count"])):
                    cache_ok = False

        except Exception:
            cache_ok = False

    if cache_ok:
        print(f"Using cached URL features: {FEATURE_CACHE}")
    else:
        print("Extracting URL features...")
        X = extract_matrix(urls)

        if X.ndim != 2:
            raise ValueError(f"Expected 2D feature matrix, got shape {X.shape}")

        np.save(FEATURE_CACHE, X)

        META_PATH.write_text(
            json.dumps(
                {
                    "row_count": int(len(urls)),
                    "feature_count": int(X.shape[1]),
                    "source": DATA_PATH.name,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        print(f"Saved feature cache: {FEATURE_CACHE}")

    # -----------------------------------------------------------------------
    # Hard negatives
    # -----------------------------------------------------------------------
    # Generate benign URLs on legitimate registered domains.
    # These examples teach the model that deep paths/query strings are not
    # automatically phishing.
    legit_domains: list[str] = []
    seen_domains: set[str] = set()

    for url, label in zip(urls, y):
        if label != 0:
            continue

        domain = registered_group(url)

        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            legit_domains.append(domain)

        if len(legit_domains) >= 250:
            break

    hard_urls: list[str] = []

    for domain in legit_domains:
        hard_urls.extend(
            [
                f"https://{domain}/account/settings/profile",
                f"https://{domain}/help/security/login",
                f"https://{domain}/user/profile?id=12345&view=details",
                f"https://{domain}/support/article/2026/update",
            ]
        )

    if hard_urls:
        print(f"Generating {len(hard_urls):,} hard-negative URLs...")

        hard_X = extract_matrix(hard_urls)

        if hard_X.shape[1] != X.shape[1]:
            raise ValueError(
                f"Feature count mismatch: dataset={X.shape[1]}, "
                f"hard_negatives={hard_X.shape[1]}"
            )

        X = np.vstack([X, hard_X])
        y = np.concatenate(
            [
                y,
                np.zeros(len(hard_urls), dtype=int),
            ]
        )

        groups = [
            registered_group(url) for url in urls
        ] + [
            registered_group(url) for url in hard_urls
        ]
    else:
        print("No legitimate domains available for hard-negative generation.")
        groups = [registered_group(url) for url in urls]

    groups = np.asarray(groups)

    # -----------------------------------------------------------------------
    # Group-aware train/test split
    # -----------------------------------------------------------------------
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42,
    )

    train_idx, test_idx = next(
        splitter.split(X, y, groups=groups)
    )

    print(f"Training rows: {len(train_idx):,}")
    print(f"Testing rows:  {len(test_idx):,}")

    # Safety check: both classes must exist in training data.
    train_classes = np.unique(y[train_idx])

    if len(train_classes) < 2:
        raise ValueError(
            f"Training split contains only class(es): {train_classes.tolist()}"
        )

    # -----------------------------------------------------------------------
    # Random Forest + probability calibration
    # -----------------------------------------------------------------------
    clf = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    model = CalibratedClassifierCV(
        estimator=clf,
        method="isotonic",
        cv=3,
        n_jobs=-1,
    )

    print("Training URL model...")
    model.fit(X[train_idx], y[train_idx])

    pred = model.predict(X[test_idx])

    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError(
            f"Phishing class (1) is missing from trained model classes: {classes}"
        )

    phishing_idx = classes.index(1)
    prob = model.predict_proba(X[test_idx])[:, phishing_idx]

    # -----------------------------------------------------------------------
    # Evaluation
    # -----------------------------------------------------------------------
    print("\n=== URL MODEL EVALUATION ===")

    print(
        classification_report(
            y[test_idx],
            pred,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            digits=4,
            zero_division=0,
        )
    )

    print(
        "ROC-AUC:",
        round(roc_auc_score(y[test_idx], prob), 4),
    )

    print(
        "PR-AUC :",
        round(average_precision_score(y[test_idx], prob), 4),
    )

    print(
        "Confusion matrix:\n",
        confusion_matrix(y[test_idx], pred, labels=[0, 1]),
    )

    # -----------------------------------------------------------------------
    # Save model
    # -----------------------------------------------------------------------
    model_path = MODELS_DIR / "url_model.pkl"
    joblib.dump(model, model_path)

    print(f"\nSaved: {model_path}")
    print(f"Feature cache: {FEATURE_CACHE}")
    print(f"Metadata: {META_PATH}")
    print("Classes:", model.classes_)


if __name__ == "__main__":
    main()
