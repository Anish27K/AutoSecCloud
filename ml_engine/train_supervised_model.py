from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer


# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "ml_engine"
    / "synthetic_security_dataset.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_engine"
    / "threat_detection_classifier.pkl"
)


# ==========================================
# LOAD DATASET
# ==========================================

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET_PATH}"
    )

df = pd.read_csv(DATASET_PATH)

FEATURE_COLUMNS = [
    "failed_attempts",
    "request_count",
    "distinct_usernames",
    "request_rate"
]

TARGET_COLUMN = "expected_label"

required_columns = FEATURE_COLUMNS + [TARGET_COLUMN]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Dataset is missing columns: {missing_columns}"
    )

df = df.dropna(
    subset=[TARGET_COLUMN]
).copy()

X = df[FEATURE_COLUMNS]

y = df[TARGET_COLUMN]

if y.nunique() < 2:
    raise ValueError(
        "The dataset must contain at least two classes."
    )


# ==========================================
# SPLIT TRAINING AND TEST DATA
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# BUILD CLASSIFIER
# ==========================================

model = Pipeline([
    (
        "imputer",
        SimpleImputer(strategy="median")
    ),
    (
        "classifier",
        RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced"
        )
    )
])


# ==========================================
# TRAIN MODEL
# ==========================================

model.fit(
    X_train,
    y_train
)


# ==========================================
# EVALUATE ON HELD-OUT DATA
# ==========================================

predictions = model.predict(X_test)

print("\n========== SUPERVISED MODEL EVALUATION ==========")

print(f"Total records: {len(df)}")
print(f"Training records: {len(X_train)}")
print(f"Test records: {len(X_test)}")

print("\nClassification report:")

print(
    classification_report(
        y_test,
        predictions,
        labels=["NORMAL", "SUSPICIOUS"],
        zero_division=0
    )
)

print("\nConfusion matrix:")

print(
    confusion_matrix(
        y_test,
        predictions,
        labels=["NORMAL", "SUSPICIOUS"]
    )
)

# Positive class: SUSPICIOUS
probabilities = model.predict_proba(X_test)

classes = list(
    model.named_steps["classifier"].classes_
)

suspicious_index = classes.index("SUSPICIOUS")

suspicious_probabilities = probabilities[
    :,
    suspicious_index
]

binary_test_labels = (
    y_test == "SUSPICIOUS"
).astype(int)

print(
    "\nROC-AUC:",
    round(
        roc_auc_score(
            binary_test_labels,
            suspicious_probabilities
        ),
        4
    )
)


# ==========================================
# SAVE CANDIDATE MODEL
# ==========================================

joblib.dump(
    model,
    MODEL_PATH
)

print("\nCandidate model saved successfully.")
print(f"Model path: {MODEL_PATH}")

print(
    "\nIMPORTANT: Evaluation uses synthetic data. "
    "These metrics do not establish real-world "
    "attack-detection performance."
)