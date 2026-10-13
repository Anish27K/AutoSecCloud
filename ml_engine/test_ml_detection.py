from pathlib import Path

import joblib
import pandas as pd


# ==========================================
# LOAD TRAINED MODEL
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_engine"
    / "threat_detection_classifier.pkl"
)

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = [
    "failed_attempts",
    "request_count",
    "distinct_usernames",
    "request_rate",
]

classifier = model.named_steps["classifier"]

classes = list(classifier.classes_)

suspicious_index = classes.index("SUSPICIOUS")


# ==========================================
# DEFINE TEST SCENARIOS
# ==========================================

test_cases = [
    {
        "scenario": "Normal activity",
        "failed_attempts": 1,
        "request_count": 5,
        "distinct_usernames": 1,
        "request_rate": 0.5,
        "expected": "NORMAL",
    },
    {
        "scenario": "Repeated failed logins",
        "failed_attempts": 12,
        "request_count": 12,
        "distinct_usernames": 1,
        "request_rate": 1.2,
        "expected": "SUSPICIOUS",
    },
    {
        "scenario": "High request volume with failed logins",
        "failed_attempts": 2,
        "request_count": 40,
        "distinct_usernames": 2,
        "request_rate": 4.0,
        "expected": "SUSPICIOUS",
    },
    {
        "scenario": "Legitimate high traffic",
        "failed_attempts": 1,
        "request_count": 50,
        "distinct_usernames": 1,
        "request_rate": 5.0,
        "expected": "NORMAL",
    },
    {
        "scenario": "Combined suspicious activity",
        "failed_attempts": 20,
        "request_count": 60,
        "distinct_usernames": 8,
        "request_rate": 6.0,
        "expected": "SUSPICIOUS",
    },
]


# ==========================================
# RUN PREDICTIONS
# ==========================================

features = pd.DataFrame(test_cases)[FEATURE_COLUMNS]

predictions = model.predict(features)
probabilities = model.predict_proba(features)

results = []

for index, case in enumerate(test_cases):

    prediction = str(predictions[index])

    suspicious_probability = float(
        probabilities[index][suspicious_index]
    )

    # Mirrors the ML blocking threshold in security_service.py.
    would_block = (
        prediction == "SUSPICIOUS"
        and suspicious_probability >= 0.90
    )

    passed = prediction == case["expected"]

    results.append({
        "scenario": case["scenario"],
        "expected": case["expected"],
        "predicted": prediction,
        "suspicious_score": round(
            suspicious_probability, 3
        ),
        "would_block": would_block,
        "test_passed": passed,
    })


# ==========================================
# DISPLAY RESULTS
# ==========================================

results_df = pd.DataFrame(results)

print("\n========== AUTOMATED ML DETECTION TEST ==========\n")
print(results_df.to_string(index=False))

total = len(results_df)
correct = int(results_df["test_passed"].sum())
incorrect = total - correct

print("\n========== SUMMARY ==========")

print(f"Total scenarios: {total}")
print(f"Correct predictions: {correct}")
print(f"Incorrect predictions: {incorrect}")
print(
    "Scenarios that would trigger ML blocking: "
    f"{int(results_df['would_block'].sum())}"
)

print(
    "\nNOTE: This test evaluates model predictions and "
    "simulates the ML blocking decision. It does not send "
    "API requests or modify live IP-blocking state."
)

if incorrect == 0:
    print("\nAll test scenarios passed.")
else:
    print("\nSome scenarios failed. Review their predictions.")