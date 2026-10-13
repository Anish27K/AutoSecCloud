from pathlib import Path

import joblib
import pandas as pd


# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_engine"
    / "threat_detection_classifier.pkl"
)


# ==========================================
# LOAD MODEL
# ==========================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)


# ==========================================
# UNSEEN TEST SCENARIOS
# ==========================================

test_cases = pd.DataFrame([
    {
        "scenario": "Occasional login mistakes",
        "failed_attempts": 3,
        "request_count": 4,
        "distinct_usernames": 1,
        "request_rate": 0.4,
        "expected": "NORMAL"
    },
    {
        "scenario": "Repeated failed logins",
        "failed_attempts": 12,
        "request_count": 12,
        "distinct_usernames": 1,
        "request_rate": 1.2,
        "expected": "SUSPICIOUS"
    },
    {
        "scenario": "High request volume",
        "failed_attempts": 1,
        "request_count": 40,
        "distinct_usernames": 2,
        "request_rate": 4.0,
        "expected": "SUSPICIOUS"
    },
    {
        "scenario": "Combined suspicious activity",
        "failed_attempts": 20,
        "request_count": 60,
        "distinct_usernames": 8,
        "request_rate": 6.0,
        "expected": "SUSPICIOUS"
    },
    {
        "scenario": "High volume of legitimate requests",
        "failed_attempts": 1,
        "request_count": 50,
        "distinct_usernames": 1,
        "request_rate": 5.0,
        "expected": "NORMAL"
    },
    {
        "scenario": "Moderate failures and traffic",
        "failed_attempts": 4,
        "request_count": 8,
        "distinct_usernames": 2,
        "request_rate": 0.8,
        "expected": "REVIEW"
    }
])


# ==========================================
# MODEL INPUT
# ==========================================

FEATURE_COLUMNS = [
    "failed_attempts",
    "request_count",
    "distinct_usernames",
    "request_rate"
]

features = test_cases[FEATURE_COLUMNS]


# ==========================================
# PREDICTIONS
# ==========================================

predictions = model.predict(features)

probabilities = model.predict_proba(features)

classifier = model.named_steps["classifier"]

classes = list(classifier.classes_)

suspicious_index = classes.index("SUSPICIOUS")

test_cases["predicted"] = predictions

test_cases["suspicious_probability"] = (
    probabilities[:, suspicious_index]
)


# ==========================================
# DISPLAY RESULTS
# ==========================================

print("\n========== GENERALIZATION TEST ==========\n")

print(
    test_cases[
        [
            "scenario",
            "failed_attempts",
            "request_count",
            "distinct_usernames",
            "expected",
            "predicted",
            "suspicious_probability"
        ]
    ].to_string(
        index=False,
        formatters={
            "suspicious_probability": "{:.3f}".format
        }
    )
)


# ==========================================
# SUMMARY
# ==========================================

print("\n========== SUMMARY ==========")

for expected_label in ["NORMAL", "SUSPICIOUS", "REVIEW"]:

    count = (
        test_cases["expected"] == expected_label
    ).sum()

    print(f"{expected_label} scenarios: {count}")

print(
    "\nNOTE: These are manually designed scenarios, "
    "not real-world attack observations."
)

print(
    "The probabilities are model scores based on "
    "synthetic training data, not calibrated probabilities "
    "of a real attack."
)
# ==========================================
# FEATURE SENSITIVITY TEST
# ==========================================

print("\n========== FEATURE SENSITIVITY TEST ==========\n")

sensitivity_cases = pd.DataFrame([
    {
        "case": "Baseline",
        "failed_attempts": 1,
        "request_count": 10,
        "distinct_usernames": 1,
        "request_rate": 1.0
    },
    {
        "case": "More failed logins",
        "failed_attempts": 10,
        "request_count": 10,
        "distinct_usernames": 1,
        "request_rate": 1.0
    },
    {
        "case": "More requests",
        "failed_attempts": 1,
        "request_count": 40,
        "distinct_usernames": 1,
        "request_rate": 4.0
    },
    {
        "case": "More distinct usernames",
        "failed_attempts": 1,
        "request_count": 10,
        "distinct_usernames": 8,
        "request_rate": 1.0
    },
    {
        "case": "More failures and requests",
        "failed_attempts": 10,
        "request_count": 40,
        "distinct_usernames": 8,
        "request_rate": 4.0
    }
])

sensitivity_features = sensitivity_cases[FEATURE_COLUMNS]

sensitivity_cases["predicted"] = model.predict(
    sensitivity_features
)

sensitivity_probabilities = model.predict_proba(
    sensitivity_features
)

sensitivity_cases["suspicious_probability"] = (
    sensitivity_probabilities[:, suspicious_index]
)

print(
    sensitivity_cases[
        [
            "case",
            "failed_attempts",
            "request_count",
            "distinct_usernames",
            "predicted",
            "suspicious_probability"
        ]
    ].to_string(
        index=False,
        formatters={
            "suspicious_probability": "{:.3f}".format
        }
    )
)