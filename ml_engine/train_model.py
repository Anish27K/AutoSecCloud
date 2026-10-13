import pandas as pd
import json
import joblib

from sklearn.ensemble import IsolationForest

# LOAD LOGS
logs = []

with open("../logs/security_logs.log", "r") as file:

    for line in file:
        logs.append(json.loads(line))

# CREATE DATAFRAME
df = pd.DataFrame(logs)

# FEATURE ENGINEERING

df["failed_attempts"] = df["failed_attempts"].fillna(0)

features = df[["failed_attempts"]]

# TRAIN MODEL

model = IsolationForest(
    contamination=0.2,
    random_state=42
)

model.fit(features)

# SAVE MODEL

joblib.dump(model, "threat_detection_model.pkl")

print("\nModel trained and saved successfully.")