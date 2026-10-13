import argparse
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

OUTPUT_FILE = (
    PROJECT_ROOT
    / "ml_engine"
    / "synthetic_security_dataset.csv"
)


FEATURE_COLUMNS = [
    "failed_attempts",
    "request_count",
    "distinct_usernames",
    "request_rate",
]


def generate_dataset(total_records=5000, random_seed=42):

    if total_records < 100:
        raise ValueError("Generate at least 100 records.")

    rng = np.random.default_rng(random_seed)

    scenarios = [
        "normal",
        "legitimate_high_traffic",
        "brute_force_simulation",
        "high_request_rate_simulation",
        "combined_suspicious_activity",
        "low_volume_suspicious_activity",
        "targeted_boundary_cases",
    ]

    probabilities = [
        0.30,
        0.18,
        0.15,
        0.12,
        0.10,
        0.08,
        0.07,
    ]

    selected_scenarios = rng.choice(
        scenarios,
        size=total_records,
        p=probabilities,
    )

    records = []

    for scenario in selected_scenarios:

        # ------------------------------------------
        # 1. NORMAL ACTIVITY
        # ------------------------------------------
        if scenario == "normal":

            failed_attempts = int(rng.integers(0, 4))
            request_count = int(rng.integers(1, 16))
            distinct_usernames = int(rng.integers(1, 4))

            expected_label = "NORMAL"

        # ------------------------------------------
        # 2. LEGITIMATE HIGH TRAFFIC
        # ------------------------------------------
        elif scenario == "legitimate_high_traffic":

            failed_attempts = int(rng.integers(0, 4))
            request_count = int(rng.integers(15, 101))
            distinct_usernames = int(rng.integers(1, 6))

            # High traffic alone does not prove an attack.
            expected_label = "NORMAL"

        # ------------------------------------------
        # 3. BRUTE-FORCE SIMULATION
        # ------------------------------------------
        elif scenario == "brute_force_simulation":

            failed_attempts = int(rng.integers(5, 31))
            request_count = int(rng.integers(5, 41))
            distinct_usernames = int(rng.integers(1, 6))

            expected_label = "SUSPICIOUS"

        # ------------------------------------------
        # 4. HIGH REQUEST-RATE SIMULATION
        # ------------------------------------------
        elif scenario == "high_request_rate_simulation":

            failed_attempts = int(rng.integers(0, 5))
            request_count = int(rng.integers(15, 101))
            distinct_usernames = int(rng.integers(1, 8))

            suspicious_activity = (
                (
                    request_count >= 40
                    and failed_attempts >= 2
                )
                or (
                    request_count >= 40
                    and distinct_usernames >= 5
                )
                or (
                    request_count >= 70
                    and distinct_usernames >= 3
                )
            )

            expected_label = (
                "SUSPICIOUS"
                if suspicious_activity
                else "NORMAL"
            )

        # ------------------------------------------
        # 5. COMBINED SUSPICIOUS ACTIVITY
        # ------------------------------------------
        elif scenario == "combined_suspicious_activity":

            failed_attempts = int(rng.integers(5, 31))
            request_count = int(rng.integers(15, 101))
            distinct_usernames = int(rng.integers(3, 16))

            expected_label = "SUSPICIOUS"

        # ------------------------------------------
        # 6. LOW-VOLUME SUSPICIOUS ACTIVITY
        # ------------------------------------------
        elif scenario == "low_volume_suspicious_activity":

            failed_attempts = int(rng.integers(3, 11))
            request_count = int(rng.integers(3, 16))
            distinct_usernames = int(rng.integers(2, 9))

            expected_label = "SUSPICIOUS"

        # ------------------------------------------
        # 7. TARGETED BOUNDARY CASES
        # ------------------------------------------
        else:

            boundary_type = int(rng.integers(0, 4))

            if boundary_type == 0:
                # High traffic with multiple failed logins.
                failed_attempts = int(rng.integers(2, 5))
                request_count = int(rng.integers(40, 61))
                distinct_usernames = int(rng.integers(1, 4))

                expected_label = "SUSPICIOUS"

            elif boundary_type == 1:
                # High traffic involving many usernames.
                failed_attempts = int(rng.integers(0, 4))
                request_count = int(rng.integers(40, 61))
                distinct_usernames = int(rng.integers(5, 9))

                expected_label = "SUSPICIOUS"

            elif boundary_type == 2:
                # Extremely high traffic with several usernames.
                failed_attempts = int(rng.integers(0, 2))
                request_count = int(rng.integers(70, 101))
                distinct_usernames = int(rng.integers(3, 6))

                expected_label = "SUSPICIOUS"

            else:
                # Legitimate high traffic without repeated failures
                # or a large number of distinct usernames.
                failed_attempts = int(rng.integers(0, 2))
                request_count = int(rng.integers(40, 81))
                distinct_usernames = int(rng.integers(1, 3))

                expected_label = "NORMAL"

        # ------------------------------------------
        # CALCULATE REQUEST RATE
        # ------------------------------------------
        time_window_seconds = 10

        request_rate = (
            request_count / time_window_seconds
        )

        records.append({
            "scenario": scenario,
            "failed_attempts": failed_attempts,
            "request_count": request_count,
            "distinct_usernames": distinct_usernames,
            "time_window_seconds": time_window_seconds,
            "request_rate": round(request_rate, 3),
            "expected_label": expected_label,
        })

    return pd.DataFrame(records)


def main():

    parser = argparse.ArgumentParser(
        description="Generate synthetic AutoSecCloud security data."
    )

    parser.add_argument(
        "--records",
        type=int,
        default=5000,
        help="Number of synthetic records to generate.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible results.",
    )

    args = parser.parse_args()

    df = generate_dataset(
        total_records=args.records,
        random_seed=args.seed,
    )

    # ------------------------------------------
    # VALIDATE DATASET
    # ------------------------------------------
    if df[FEATURE_COLUMNS].isnull().any().any():
        raise ValueError(
            "Generated features contain missing values."
        )

    valid_labels = {"NORMAL", "SUSPICIOUS"}

    if not set(df["expected_label"].unique()).issubset(
        valid_labels
    ):
        raise ValueError(
            "Dataset contains an unknown label."
        )

    # ------------------------------------------
    # SAVE DATASET
    # ------------------------------------------
    df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print("\n========== DATASET GENERATION ==========")

    print("\nSynthetic dataset generated successfully.")
    print(f"Total records: {len(df)}")
    print(f"Output file: {OUTPUT_FILE}")

    print("\n========== SCENARIO DISTRIBUTION ==========")

    print(
        df["scenario"]
        .value_counts()
        .to_string()
    )

    print("\n========== EXPECTED LABELS ==========")

    print(
        df["expected_label"]
        .value_counts()
        .to_string()
    )

    print("\n========== LABELS PER SCENARIO ==========")

    print(
        pd.crosstab(
            df["scenario"],
            df["expected_label"],
        ).to_string()
    )

    print("\n========== FEATURE SUMMARY ==========")

    print(
        df[FEATURE_COLUMNS]
        .describe()
        .round(2)
        .to_string()
    )

    print(
        "\nNOTE: Labels are based on synthetic assumptions, "
        "not verified real-world attack records."
    )

    print(
        "High request volume alone does not establish "
        "malicious activity."
    )

    print(
        "Evaluate the trained model against held-out data "
        "and independently designed test scenarios."
    )


if __name__ == "__main__":
    main()