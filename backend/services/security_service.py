from collections import defaultdict
from datetime import datetime
from pathlib import Path
import time

import joblib
import pandas as pd

from backend.utils.logger_config import logger
from backend.services.db_logger_service import save_attack_log
from backend.services.user_service import verify_user

# ==========================================
# LOAD RANDOM FOREST CLASSIFIER
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml_engine"
    / "threat_detection_classifier.pkl"
)

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Threat detection model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = [
    "failed_attempts",
    "request_count",
    "distinct_usernames",
    "request_rate",
]

classifier = model.named_steps["classifier"]
MODEL_CLASSES = list(classifier.classes_)

if "SUSPICIOUS" not in MODEL_CLASSES:
    raise ValueError(
        "The ML classifier must contain the SUSPICIOUS class."
    )


# ==========================================
# IN-MEMORY SECURITY STATE
# ==========================================

failed_attempts = defaultdict(int)
blocked_ips = {}
request_logs = defaultdict(list)
username_logs = defaultdict(list)
threat_scores = defaultdict(int)


# ==========================================
# SECURITY CONFIGURATION
# ==========================================

RATE_LIMIT_WINDOW = 10
MAX_REQUESTS = 5
BLOCK_DURATION = 30
ML_BLOCK_THRESHOLD = 0.90


# ==========================================
# GET THREAT SEVERITY
# ==========================================

def get_severity(score):

    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"

    return "LOW"


# ==========================================
# RECORD SECURITY EVENT
# ==========================================

def log_security_event(
    event,
    ip,
    username=None,
    severity="LOW",
    **details,
):
    event_data = {
        "event": event,
        "ip": ip,
        "severity": severity,
        "timestamp": str(datetime.now()),
    }

    if username is not None:
        event_data["username"] = username

    event_data.update(details)

    if severity == "CRITICAL":
        logger.critical(event_data)
    elif severity in ("HIGH", "MEDIUM"):
        logger.warning(event_data)
    else:
        logger.info(event_data)


# ==========================================
# TRACK REQUESTS
# ==========================================

def track_request(username, client_ip, current_time):

    request_logs[client_ip] = [
        timestamp
        for timestamp in request_logs[client_ip]
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]

    username_logs[client_ip] = [
        (timestamp, username_seen)
        for timestamp, username_seen in username_logs[client_ip]
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]

    request_logs[client_ip].append(current_time)

    username_logs[client_ip].append(
        (current_time, username)
    )

    request_count = len(request_logs[client_ip])

    distinct_usernames = len({
        username_seen
        for _, username_seen in username_logs[client_ip]
    })

    request_rate = request_count / RATE_LIMIT_WINDOW

    return (
        request_count,
        distinct_usernames,
        request_rate,
    )


# ==========================================
# RUN ML PREDICTION
# ==========================================

def predict_suspicious_activity(
    client_ip,
    username,
    current_attempts,
    request_count,
    distinct_usernames,
    request_rate,
):
    features = pd.DataFrame(
        [{
            "failed_attempts": current_attempts,
            "request_count": request_count,
            "distinct_usernames": distinct_usernames,
            "request_rate": request_rate,
        }],
        columns=FEATURE_COLUMNS,
    )

    prediction = str(model.predict(features)[0])

    probabilities = model.predict_proba(features)[0]

    suspicious_index = MODEL_CLASSES.index("SUSPICIOUS")

    suspicious_probability = float(
        probabilities[suspicious_index]
    )

    log_security_event(
        event="ml_prediction",
        ip=client_ip,
        username=username,
        severity="LOW",
        failed_attempts=current_attempts,
        request_count=request_count,
        distinct_usernames=distinct_usernames,
        request_rate=request_rate,
        prediction=prediction,
        suspicious_probability=suspicious_probability,
    )

    return prediction, suspicious_probability


# ==========================================
# TEMPORARILY BLOCK AN IP
# ==========================================

def block_ip(
    client_ip,
    username,
    reason,
    message,
    current_time=None,
):
    if current_time is None:
        current_time = time.time()

    blocked_ips[client_ip] = {
        "blocked_at": current_time,
        "reason": reason,
    }

    save_attack_log(
        event="ip_blocked",
        ip=client_ip,
        username=username,
        status="BLOCKED",
        reason=reason,
        severity="CRITICAL",
    )

    log_security_event(
        event="ip_blocked",
        ip=client_ip,
        username=username,
        severity="CRITICAL",
        block_reason=reason,
        action_taken="IP_BLOCKED",
        threat_score=threat_scores[client_ip],
    )

    return {
        "status": "blocked",
        "message": message,
        "retry_after_seconds": BLOCK_DURATION,
    }


# ==========================================
# SECURITY CHECK FUNCTION
# ==========================================

def process_login(username, password, client_ip):

    current_time = time.time()

    # ======================================
    # 1. TRACK REQUESTS
    # ======================================

    (
        request_count,
        distinct_usernames,
        request_rate,
    ) = track_request(
        username,
        client_ip,
        current_time,
    )

    # ======================================
    # 2. CHECK TEMPORARY IP BLOCK
    # ======================================

    if client_ip in blocked_ips:

        block_data = blocked_ips[client_ip]

        elapsed_time = (
            current_time - block_data["blocked_at"]
        )

        if elapsed_time < BLOCK_DURATION:

            remaining_time = max(
                1,
                int(BLOCK_DURATION - elapsed_time),
            )

            save_attack_log(
                event="blocked_ip_access_attempt",
                ip=client_ip,
                username=username,
                status="BLOCKED",
                reason=block_data["reason"],
                severity="CRITICAL",
            )

            log_security_event(
                event="blocked_ip_access_attempt",
                ip=client_ip,
                username=username,
                severity="CRITICAL",
                block_reason=block_data["reason"],
                request_count=request_count,
            )

            return {
                "status": "blocked",
                "message": (
                    f"IP blocked due to {block_data['reason']}"
                ),
                "retry_after_seconds": remaining_time,
            }

        # Temporary block has expired.
        del blocked_ips[client_ip]

        failed_attempts[client_ip] = 0
        threat_scores[client_ip] = 0

        save_attack_log(
            event="ip_unblocked",
            ip=client_ip,
            username=username,
            status="RECOVERED",
            reason="BLOCK_DURATION_EXPIRED",
            severity="LOW",
        )

        log_security_event(
            event="ip_unblocked",
            ip=client_ip,
            username=username,
            severity="LOW",
            message="Temporary IP block expired.",
        )

    # ======================================
    # 3. SUSPICIOUS USERNAME CHECK
    # ======================================

    suspicious_keywords = [
        "admin",
        "root",
        "sql",
        "' OR 1=1",
        "--",
    ]

    if any(
        keyword.lower() in username.lower()
        for keyword in suspicious_keywords
    ):

        threat_scores[client_ip] += 20

        severity = get_severity(
            threat_scores[client_ip]
        )

        save_attack_log(
            event="suspicious_username_detected",
            ip=client_ip,
            username=username,
            status="WARNING",
            reason="SUSPICIOUS_USERNAME",
            severity=severity,
        )

        log_security_event(
            event="suspicious_username_detected",
            ip=client_ip,
            username=username,
            severity=severity,
            threat_score=threat_scores[client_ip],
        )

    # ======================================
    # 4. RULE-BASED RATE LIMITING
    # ======================================

    # More than five requests within ten seconds
    # triggers an independent traffic block.
    if request_count > MAX_REQUESTS:

        threat_scores[client_ip] += 40

        log_security_event(
            event="rate_limit_exceeded",
            ip=client_ip,
            username=username,
            severity="HIGH",
            request_count=request_count,
            rate_limit=MAX_REQUESTS,
            window_seconds=RATE_LIMIT_WINDOW,
        )

        return block_ip(
            client_ip=client_ip,
            username=username,
            reason="TRAFFIC_SPIKE",
            message=(
                "Traffic spike detected. "
                "IP temporarily blocked."
            ),
            current_time=current_time,
        )

    # ======================================
    # 5. ML EVALUATION
    # ======================================

    prediction, suspicious_probability = (
        predict_suspicious_activity(
            client_ip=client_ip,
            username=username,
            current_attempts=failed_attempts[client_ip],
            request_count=request_count,
            distinct_usernames=distinct_usernames,
            request_rate=request_rate,
        )
    )

    if (
        prediction == "SUSPICIOUS"
        and suspicious_probability >= ML_BLOCK_THRESHOLD
    ):

        threat_scores[client_ip] += 50

        return block_ip(
            client_ip=client_ip,
            username=username,
            reason="ML_SUSPICIOUS_ACTIVITY",
            message=(
                "ML classifier detected suspicious activity. "
                "IP temporarily blocked."
            ),
            current_time=current_time,
        )

    # ======================================
    # 6. VERIFY LOGIN CREDENTIALS
    # ======================================

    if not verify_user(username, password):

        failed_attempts[client_ip] += 1

        current_attempts = failed_attempts[client_ip]

        threat_scores[client_ip] += 15

        severity = get_severity(
            threat_scores[client_ip]
        )

        save_attack_log(
            event="failed_login",
            ip=client_ip,
            username=username,
            status="FAILED",
            reason="INVALID_PASSWORD",
            severity=severity,
        )

        log_security_event(
            event="failed_login",
            ip=client_ip,
            username=username,
            severity=severity,
            failed_attempts=current_attempts,
            request_count=request_count,
            distinct_usernames=distinct_usernames,
            request_rate=request_rate,
            threat_score=threat_scores[client_ip],
        )

        # ----------------------------------
        # CRITICAL THREAT SCORE
        # ----------------------------------

        if threat_scores[client_ip] >= 80:

            return block_ip(
                client_ip=client_ip,
                username=username,
                reason="CRITICAL_THREAT_SCORE",
                message=(
                    "Critical threat detected. "
                    "IP temporarily blocked."
                ),
                current_time=current_time,
            )

        # ----------------------------------
        # RE-EVALUATE ML AFTER FAILED LOGIN
        # ----------------------------------

        prediction, suspicious_probability = (
            predict_suspicious_activity(
                client_ip=client_ip,
                username=username,
                current_attempts=current_attempts,
                request_count=request_count,
                distinct_usernames=distinct_usernames,
                request_rate=request_rate,
            )
        )

        if (
            prediction == "SUSPICIOUS"
            and suspicious_probability >= ML_BLOCK_THRESHOLD
        ):

            threat_scores[client_ip] += 50

            return block_ip(
                client_ip=client_ip,
                username=username,
                reason="ML_SUSPICIOUS_ACTIVITY",
                message=(
                    "ML classifier detected suspicious activity. "
                    "IP temporarily blocked."
                ),
                current_time=current_time,
            )

        return {
            "status": "failed",
            "message": "Invalid credentials",
        }

    # ======================================
    # 7. SUCCESSFUL LOGIN
    # ======================================

    failed_attempts[client_ip] = 0
    threat_scores[client_ip] = 0

    save_attack_log(
        event="successful_login",
        ip=client_ip,
        username=username,
        status="SUCCESS",
        reason="NONE",
        severity="LOW",
    )

    log_security_event(
        event="successful_login",
        ip=client_ip,
        username=username,
        severity="LOW",
        request_count=request_count,
        distinct_usernames=distinct_usernames,
        request_rate=request_rate,
        threat_score=0,
    )

    return {
        "status": "success",
        "message": "Login successful",
    }