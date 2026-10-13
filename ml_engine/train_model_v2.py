import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

LOG_FILE = PROJECT_ROOT / "logs" / "security_logs.log"

MODEL_FILE = (
    PROJECT_ROOT
    / "ml_engine"
    / "threat_detection_model_v2.pkl"
)


# ==========================================
# LOAD SECURITY LOGS
# ==========================================

if not LOG_FILE.exists():
    raise FileNotFoundError(
        f"Security log file not found: {LOG_FILE}"
    )

logs = []

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):

        if not line.strip():
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON at line {line_number}"
            ) from exc

        if not isinstance(record, dict):
            raise ValueError(
                f"Expected a JSON object at line {line_number}"
            )

        logs.append(record)


if len(logs) < 10:
    raise ValueError(
        "Not enough log records for this experiment. "
        "Collect more data before training."
    )


# ==========================================
# PREPARE FEATURES
# ==========================================

df = pd.DataFrame(logs)

FEATURE_COLUMNS = [
    "failed_attempts",
    "request_count",
]

for column in FEATURE_COLUMNS:

    if column not in df.columns:
        df[column] = pd.NA

    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    )


# Drop records that contain no usable feature data.
features = df[FEATURE_COLUMNS].dropna(
    how="all"
).copy()


if len(features) < 10:
    raise ValueError(
        "Not enough records with usable feature data."
    )


# ==========================================
# BUILD ANOMALY DETECTOR
# ==========================================

pipeline = Pipeline([
    (
        "imputer",
        SimpleImputer(
            strategy="median",
            add_indicator=True
        )
    ),
    (
        "detector",
        IsolationForest(
            contamination=0.2,
            random_state=42
        )
    )
])


pipeline.fit(features)


# ==========================================
# SAVE CANDIDATE MODEL
# ==========================================

joblib.dump(pipeline, MODEL_FILE)


# ==========================================
# REPORT
# ==========================================

predictions = pipeline.predict(features)

normal_count = int((predictions == 1).sum())
anomaly_count = int((predictions == -1).sum())

print("\nExperimental ML model trained successfully.")
print(f"Log records loaded: {len(logs)}")
print(f"Records used: {len(features)}")
print(f"Features: {FEATURE_COLUMNS}")
print(f"Normal observations: {normal_count}")
print(f"Anomalies flagged: {anomaly_count}")
print(f"Candidate model saved to: {MODEL_FILE}")

print(
    "\nNOTE: These are training-set results, "
    "not accuracy or proof of attack detection."
)