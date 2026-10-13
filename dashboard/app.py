import streamlit as st
import pandas as pd
import json
import time
from pathlib import Path

# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title="AutoSecCloud Dashboard",
    layout="wide"
)

# =========================
# TITLE
# =========================

st.title("🛡️ AutoSecCloud Security Dashboard")

st.markdown("""
Real-Time AI Powered Intrusion Detection &
Threat Monitoring System
""")

# =========================
# LOG FILE
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
log_file = BASE_DIR / "logs" / "security_logs.log"

placeholder = st.empty()

# =========================
# LIVE DASHBOARD LOOP
# =========================

while True:

    logs = []

    try:

        with open(log_file, "r") as file:

            for line in file:

                try:
                    logs.append(json.loads(line))

                except:
                    pass

        df = pd.DataFrame(logs)

        with placeholder.container():

            if not df.empty:

                # =========================
                # GLOBAL THREAT LEVEL
                # =========================

                latest_severity = "LOW"

                if "severity" in df.columns:

                    severity_priority = {
                        "LOW": 1,
                        "MEDIUM": 2,
                        "HIGH": 3,
                        "CRITICAL": 4
                    }

                    highest = max(
                        df["severity"],
                        key=lambda x:
                        severity_priority.get(x, 0)
                    )

                    latest_severity = highest

                # =========================
                # THREAT LEVEL BANNER
                # =========================

                if latest_severity == "LOW":

                    st.success(
                        "🟢 SYSTEM STATUS: LOW THREAT"
                    )

                elif latest_severity == "MEDIUM":

                    st.warning(
                        "🟡 SYSTEM STATUS: MEDIUM THREAT"
                    )

                elif latest_severity == "HIGH":

                    st.warning(
                        "🟠 SYSTEM STATUS: HIGH THREAT"
                    )

                elif latest_severity == "CRITICAL":

                    st.error(
                        "🔴 SYSTEM STATUS: CRITICAL THREAT"
                    )

                # =========================
                # METRICS
                # =========================

                total_events = len(df)

                failed_logins = len(
                    df[df["event"] == "failed_login"]
                )

                blocked_attempts = len(
                    df[df["event"] == "blocked_ip_access_attempt"]
                )

                ml_anomalies = len(
                    df[df["event"] == "ml_anomaly_detected"]
                )

                critical_threats = len(
                    df[df["event"] == "critical_threat_detected"]
                )

                suspicious_users = len(
                    df[df["event"] == "suspicious_username_detected"]
                )

                successful_logins = len(
                    df[df["event"] == "successful_login"]
                )

                # =========================
                # TOP METRICS
                # =========================

                st.subheader("📊 Security Metrics")

                col1, col2, col3 = st.columns(3)

                col1.metric(
                    "Total Events",
                    total_events
                )

                col2.metric(
                    "Failed Logins",
                    failed_logins
                )

                col3.metric(
                    "Blocked Attempts",
                    blocked_attempts
                )

                col4, col5, col6 = st.columns(3)

                col4.metric(
                    "ML Anomalies",
                    ml_anomalies
                )

                col5.metric(
                    "Critical Threats",
                    critical_threats
                )

                col6.metric(
                    "Suspicious Usernames",
                    suspicious_users
                )

                # =========================
                # EVENT DISTRIBUTION
                # =========================

                st.subheader("📈 Threat Event Distribution")

                event_counts = (
                    df["event"]
                    .value_counts()
                )

                st.bar_chart(event_counts)

                # =========================
                # SEVERITY ANALYSIS
                # =========================

                if "severity" in df.columns:

                    st.subheader(
                        "🚨 Threat Severity Distribution"
                    )

                    severity_counts = (
                        df["severity"]
                        .value_counts()
                    )

                    st.bar_chart(
                        severity_counts
                    )

                # =========================
                # RECENT CRITICAL ALERTS
                # =========================

                st.subheader(
                    "⚠️ Recent Critical Alerts"
                )

                critical_events = df[
                    df["event"].isin([
                        "critical_threat_detected",
                        "ml_anomaly_detected",
                        "traffic_spike_detected",
                        "blocked_ip_access_attempt"
                    ])
                ]

                st.dataframe(
                    critical_events.tail(10),
                    width="stretch"
                )

                # =========================
                # RECENT SECURITY LOGS
                # =========================

                st.subheader(
                    "📌 Live Security Logs"
                )

                st.dataframe(
                    df.tail(25),
                    width="stretch"
                )

                # =========================
                # SUCCESS VS FAILURE
                # =========================

                st.subheader(
                    "🔐 Authentication Analysis"
                )

                auth_data = pd.DataFrame({
                    "Category": [
                        "Successful",
                        "Failed"
                    ],
                    "Count": [
                        successful_logins,
                        failed_logins
                    ]
                })

                st.bar_chart(
                    auth_data.set_index(
                        "Category"
                    )
                )

            else:

                st.warning(
                    "No security logs available yet."
                )

    except FileNotFoundError:

        st.error(
            "Security log file not found."
        )

    except Exception as e:

        st.error(
            f"Dashboard Error: {e}"
        )

    time.sleep(2)