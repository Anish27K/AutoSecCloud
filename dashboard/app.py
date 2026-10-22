import os

import pandas as pd
import requests
import streamlit as st

# ==========================================
# PAGE CONFIG
# ==========================================

st.set_page_config(
    page_title="AutoSecCloud Dashboard",
    page_icon="🛡️",
    layout="wide",
)

API_BASE_URL = os.getenv(
    "AUTOSECCLOUD_API_URL",
    "https://autoseccloud-api.onrender.com",
).rstrip("/")

REQUEST_TIMEOUT = 30


# ==========================================
# API HELPERS
# ==========================================

def api_login(username, password):
    """Authenticate with the deployed AutoSecCloud API."""

    response = requests.post(
        f"{API_BASE_URL}/login",
        json={
            "username": username,
            "password": password,
        },
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code != 200:
        raise ValueError(
            "Login failed. Check your credentials and try again."
        )

    data = response.json()
    token = data.get("access_token")

    if not token:
        raise ValueError(
            "The API did not return an access token."
        )

    if data.get("role") != "admin":
        raise PermissionError(
            "The dashboard requires an admin account "
            "to access security statistics."
        )

    return token


def api_get(endpoint, token):
    """Make an authenticated GET request."""

    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        headers={
            "Authorization": f"Bearer {token}",
        },
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 401:
        raise PermissionError(
            "Your session has expired. Please log in again."
        )

    if response.status_code == 403:
        raise PermissionError(
            "Access denied. An administrator account is required."
        )

    response.raise_for_status()
    return response.json()


def load_dashboard_data(token):
    """Retrieve statistics and recent security logs."""

    stats = api_get("/stats", token)
    attacks = api_get("/attacks", token)

    logs = attacks.get("logs", [])
    df = pd.DataFrame(logs)

    expected_columns = [
        "id",
        "event",
        "ip",
        "username",
        "status",
        "reason",
        "severity",
        "timestamp",
    ]

    for column in expected_columns:
        if column not in df.columns:
            df[column] = pd.Series(dtype="object")

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce",
            utc=True,
        )

    return stats, df


# ==========================================
# TITLE
# ==========================================

st.title("🛡️ AutoSecCloud Security Dashboard")

st.markdown(
    """
    Real-Time AI-Powered Intrusion Detection & Threat Monitoring System

    Monitor authentication activity, ML predictions, suspicious activity,
    and IP-blocking events from your deployed security backend.
    """
)

st.caption(f"Connected API: {API_BASE_URL}")


# ==========================================
# LOGIN
# ==========================================

if "access_token" not in st.session_state:
    st.session_state.access_token = None

if "dashboard_username" not in st.session_state:
    st.session_state.dashboard_username = None

if not st.session_state.access_token:

    st.subheader("🔐 Administrator Login")

    with st.form("admin_login_form"):
        username = st.text_input("Username")
        password = st.text_input(
            "Password",
            type="password",
        )

        login_clicked = st.form_submit_button(
            "Login",
            type="primary",
            use_container_width=True,
        )

    if login_clicked:
        if not username or not password:
            st.warning("Enter your username and password.")
        else:
            try:
                with st.spinner(
                    "Authenticating with AutoSecCloud..."
                ):
                    token = api_login(username, password)

                st.session_state.access_token = token
                st.session_state.dashboard_username = username

                st.rerun()

            except requests.RequestException:
                st.error(
                    "Could not connect to the backend. "
                    "Check the API deployment and try again."
                )

            except PermissionError as exc:
                st.error(str(exc))

            except ValueError as exc:
                st.error(str(exc))

    st.info(
        "Sign in using your existing AutoSecCloud administrator account."
    )

    st.stop()


# ==========================================
# DASHBOARD CONTROLS
# ==========================================

header_col, refresh_col, logout_col = st.columns([5, 1, 1])

with header_col:
    st.success(
        f"Authenticated as administrator: "
        f"{st.session_state.dashboard_username}"
    )

with refresh_col:
    refresh_clicked = st.button(
        "🔄 Refresh",
        use_container_width=True,
    )

with logout_col:
    logout_clicked = st.button(
        "Log out",
        use_container_width=True,
    )

if logout_clicked:
    st.session_state.access_token = None
    st.session_state.dashboard_username = None
    st.rerun()


# ==========================================
# LOAD LIVE DATA
# ==========================================

try:
    with st.spinner("Loading live security data..."):
        stats, df = load_dashboard_data(
            st.session_state.access_token
        )

except PermissionError as exc:
    st.error(str(exc))

    st.session_state.access_token = None
    st.session_state.dashboard_username = None

    if st.button("Return to login"):
        st.rerun()

    st.stop()

except requests.RequestException as exc:
    st.error(
        "Unable to retrieve data from the AutoSecCloud backend. "
        "Check that Render is running and try refreshing."
    )

    with st.expander("Technical details"):
        st.code(str(exc))

    st.stop()

except (ValueError, KeyError) as exc:
    st.error(f"Unexpected API response: {exc}")
    st.stop()


# ==========================================
# NORMALIZE SECURITY LOGS
# ==========================================

if not df.empty:
    df["event"] = (
        df["event"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    df["status"] = (
        df["status"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    df["severity"] = (
        df["severity"]
        .fillna("LOW")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    df["ip"] = (
        df["ip"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.strip()
    )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True,
    )


# ==========================================
# SYSTEM STATUS
# ==========================================

if df.empty:
    st.success("🟢 SYSTEM STATUS: NO RECORDED THREATS")

else:
    # Examine only recorded block-state transitions.
    block_events = df[
        df["event"].isin(
            ["ip_blocked", "ip_unblocked"]
        )
    ].dropna(subset=["timestamp"]).copy()

    if block_events.empty:
        latest_block_events = block_events
    else:
        # Find each IP's latest block or unblock transition.
        latest_block_events = (
            block_events
            .sort_values("timestamp")
            .groupby("ip", dropna=False)
            .tail(1)
        )

    # A block is unresolved in the returned logs if the latest
    # transition for that IP is ip_blocked with status BLOCKED.
    active_blocks = latest_block_events[
        (latest_block_events["event"] == "ip_blocked")
        & (latest_block_events["status"] == "BLOCKED")
    ]

    if not active_blocks.empty:
        st.error(
            "🔴 SYSTEM STATUS: CRITICAL THREAT — "
            f"{len(active_blocks)} IP(s) with "
            "unresolved block events"
        )

    else:
        # An unblock event means the historical block was recorded
        # as recovered. Do not let that old block alone keep the
        # system at HIGH or CRITICAL severity.
        recovered_ips = set(
            latest_block_events.loc[
                latest_block_events["event"] == "ip_unblocked",
                "ip",
            ]
        )

        relevant_events = df[
            ~(
                df["ip"].isin(recovered_ips)
                & df["event"].isin(
                    [
                        "ip_blocked",
                        "blocked_ip_access_attempt",
                    ]
                )
            )
        ].copy()

        # Use the latest event per IP, not the highest severity
        # across every historical event.
        latest_events = (
            relevant_events
            .dropna(subset=["timestamp"])
            .sort_values("timestamp")
            .groupby("ip", dropna=False)
            .tail(1)
        )

        severity_priority = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        if latest_events.empty:
            st.success(
                "🟢 SYSTEM STATUS: NO ACTIVE BLOCKS REPORTED"
            )
        else:
            latest_severity = max(
                latest_events["severity"],
                key=lambda value: severity_priority.get(
                    value, 0
                ),
            )

            if latest_severity == "LOW":
                st.success("🟢 SYSTEM STATUS: LOW THREAT")

            elif latest_severity == "MEDIUM":
                st.warning("🟡 SYSTEM STATUS: MEDIUM THREAT")

            elif latest_severity == "HIGH":
                st.warning("🟠 SYSTEM STATUS: HIGH THREAT")

            else:
                st.error("🔴 SYSTEM STATUS: CRITICAL THREAT")


# ==========================================
# SECURITY METRICS
# ==========================================

st.subheader("📊 Security Metrics")

total_events = stats.get("total_logs", len(df))
failed_logins = stats.get("failed_logins", 0)
successful_logins = stats.get("successful_logins", 0)
blocked_attacks = stats.get("blocked_attacks", 0)

if df.empty:
    ml_predictions = 0
    suspicious_predictions = 0
    critical_threats = 0
    suspicious_users = 0
    blocked_attempts = 0

else:
    events = df["event"]
    statuses = df["status"]

    ml_mask = events.eq("ml_prediction")
    ml_predictions = int(ml_mask.sum())

    suspicious_predictions = int(
        (ml_mask & statuses.eq("SUSPICIOUS")).sum()
    )

    critical_threats = int(
        df["severity"].eq("CRITICAL").sum()
    )

    suspicious_users = int(
        events.eq("suspicious_username_detected").sum()
    )

    blocked_attempts = int(
        events.eq("blocked_ip_access_attempt").sum()
    )

    # Include recorded block events in the displayed blocked count.
    blocked_attacks = max(
        blocked_attacks,
        int(
            events.eq("ip_blocked").sum()
            + events.eq("blocked_ip_access_attempt").sum()
        ),
    )

col1, col2, col3 = st.columns(3)

col1.metric("Total Security Events", total_events)
col2.metric("Failed Logins", failed_logins)
col3.metric("Blocked Attacks", blocked_attacks)

col4, col5, col6 = st.columns(3)

col4.metric("ML Predictions", ml_predictions)
col5.metric("Suspicious ML Predictions", suspicious_predictions)
col6.metric("Critical Events", critical_threats)

st.caption(
    "Statistics are retrieved from the deployed API. "
    "ML prediction counts are based on the returned attack-log records."
)


# ==========================================
# EVENT DISTRIBUTION
# ==========================================

st.subheader("📈 Threat Event Distribution")

if not df.empty:
    event_counts = df["event"].replace(
        "", "UNKNOWN"
    ).value_counts()

    st.bar_chart(event_counts)
else:
    st.info("No security events have been recorded yet.")


# ==========================================
# SEVERITY ANALYSIS
# ==========================================

st.subheader("🚨 Threat Severity Distribution")

if not df.empty:
    severity_counts = df["severity"].replace(
        "", "UNKNOWN"
    ).value_counts()

    st.bar_chart(severity_counts)
else:
    st.info("No severity data is available yet.")


# ==========================================
# RECENT CRITICAL ALERTS
# ==========================================

st.subheader("⚠️ Recent Critical Alerts")

if not df.empty:
    alert_events = [
        "critical_threat_detected",
        "ml_anomaly_detected",
        "traffic_spike_detected",
        "blocked_ip_access_attempt",
        "ip_blocked",
    ]

    critical_events = df[
        df["event"].isin(alert_events)
        | df["severity"].isin(["HIGH", "CRITICAL"])
    ]

    if not critical_events.empty:
        st.dataframe(
            critical_events.sort_values(
                "timestamp",
                ascending=False,
                na_position="last",
            ).head(10),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success(
            "No high-severity alerts in the returned logs."
        )
else:
    st.info("No security logs available yet.")


# ==========================================
# LIVE SECURITY LOGS
# ==========================================

st.subheader("📌 Security Event Logs")

if not df.empty:
    st.dataframe(
        df.sort_values(
            "timestamp",
            ascending=False,
            na_position="last",
        ).head(25),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.warning("No security logs available yet.")


# ==========================================
# AUTHENTICATION ANALYSIS
# ==========================================

st.subheader("🔐 Authentication Analysis")

auth_data = pd.DataFrame(
    {
        "Category": ["Successful", "Failed"],
        "Count": [successful_logins, failed_logins],
    }
)

st.bar_chart(
    auth_data.set_index("Category")
)


# ==========================================
# ML PREDICTION DETAILS
# ==========================================

st.subheader("🤖 ML Threat Detection")

if not df.empty:
    ml_df = df[df["event"] == "ml_prediction"].copy()

    if not ml_df.empty:
        st.dataframe(
            ml_df.sort_values(
                "timestamp",
                ascending=False,
                na_position="last",
            ).head(10),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(
            "No ML prediction events are present in the returned logs."
        )
else:
    st.info("No ML prediction data is available.")


# ==========================================
# FOOTER / REFRESH
# ==========================================

st.divider()

st.caption(
    "AutoSecCloud | AI-Driven Self-Healing Cloud Security System"
)

if refresh_clicked:
    st.rerun()

st.caption(
    "Use Refresh to retrieve the latest statistics and security logs."
)