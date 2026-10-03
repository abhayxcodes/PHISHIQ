"""Train the email phishing model as one TF-IDF + LogisticRegression Pipeline."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "datasets" / "CEAS_08.csv"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH, usecols=["subject", "body", "label"]).fillna("")
    text = (df["subject"].astype(str) + "\n" + df["body"].astype(str)).str.strip()
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        text, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=50000,
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=3,
            strip_accents="unicode",
        )),
        ("clf", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            C=4.0,
        )),
    ])

    pipeline.fit(X_train, y_train)
    pred = pipeline.predict(X_test)
    prob = pipeline.predict_proba(X_test)[:, list(pipeline.classes_).index(1)]

    print("\n=== EMAIL MODEL EVALUATION ===")
    print(classification_report(y_test, pred, target_names=["legitimate", "phishing"], digits=4))
    print("ROC-AUC:", round(roc_auc_score(y_test, prob), 4))

    out = MODELS_DIR / "email_model.pkl"
    joblib.dump(pipeline, out)
    print(f"Saved: {out}")
    print("Classes:", pipeline.classes_)
    print("\nNote: CEAS-08 is a 2008 corpus; modern phishing may differ substantially.")
    print("An additional CSV with subject/body/label can be concatenated before training if available.")

if __name__ == "__main__":
    main()
