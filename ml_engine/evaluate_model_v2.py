from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    classification_report,
    confusion_matrix
)


# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_engine"
    / "threat_detection_model_v2.pkl"
)


# ==========================================
# LOAD EXPERIMENTAL MODEL
# ==========================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)


# ==========================================
# CONTROLLED TEST SCENARIOS
# ==========================================

test_cases = pd.DataFrame([
    # Normal scenarios
    {
        "scenario": "Single failed login",
        "failed_attempts": 1,
        "request_count": 1,
        "expected": "NORMAL"
    },
    {
        "scenario": "Occasional failed logins",
        "failed_attempts": 2,
        "request_count": 1,
        "expected": "NORMAL"
    },
    {
        "scenario": "Normal successful login",
        "failed_attempts": 0,
        "request_count": 1,
        "expected": "NORMAL"
    },

    # Simulated suspicious scenarios
    {
        "scenario": "Repeated failed logins",
        "failed_attempts": 5,
        "request_count": 5,
        "expected": "SUSPICIOUS"
    },
    {
        "scenario": "High request volume",
        "failed_attempts": 2,
        "request_count": 10,
        "expected": "SUSPICIOUS"
    },
    {
        "scenario": "High failed attempts and request volume",
        "failed_attempts": 10,
        "request_count": 10,
        "expected": "SUSPICIOUS"
    }
])


# ==========================================
# RUN MODEL PREDICTIONS
# ==========================================

features = test_cases[
    ["failed_attempts", "request_count"]
]

predictions = model.predict(features)

test_cases["predicted"] = [
    "NORMAL" if prediction == 1 else "SUSPICIOUS"
    for prediction in predictions
]


# ==========================================
# DISPLAY RESULTS
# ==========================================

print("\n========== ML MODEL EVALUATION ==========\n")

print(
    test_cases[
        [
            "scenario",
            "failed_attempts",
            "request_count",
            "expected",
            "predicted"
        ]
    ].to_string(index=False)
)


# ==========================================
# CALCULATE BASIC COUNTS
# ==========================================

correct = (
    test_cases["expected"]
    == test_cases["predicted"]
).sum()

total = len(test_cases)

print("\n========== SUMMARY ==========")

print(f"Test scenarios: {total}")
print(f"Matching classifications: {correct}")
print(f"Non-matching classifications: {total - correct}")

print(
    "\nIMPORTANT: These are synthetic scenarios, "
    "not independently verified real-world attacks."
)