from utils.logger_config import logger
from collections import defaultdict
from services.db_logger_service import save_attack_log
from services.user_service import verify_user

from datetime import datetime
from pathlib import Path
import time
import joblib
import numpy as np

# =========================
# LOAD TRAINED ML MODEL
# =========================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = PROJECT_ROOT / "ml_engine" / "threat_detection_model.pkl"

model = joblib.load(MODEL_PATH)

# =========================
# IN-MEMORY STORAGE
# =========================

failed_attempts = {}

blocked_ips = {}

request_logs = defaultdict(list)

threat_scores = {}

# =========================
# SECURITY CONFIG
# =========================

RATE_LIMIT_WINDOW = 10

MAX_REQUESTS = 5

BLOCK_DURATION = 30

# =========================
# GET THREAT SEVERITY
# =========================

def get_severity(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    return "LOW"

# =========================
# SECURITY CHECK FUNCTION
# =========================

def process_login(username, password, client_ip):

    current_time = time.time()

    # =========================
    # INITIALIZE THREAT SCORE
    # =========================

    if client_ip not in threat_scores:

        threat_scores[client_ip] = 0

    # =========================
    # SUSPICIOUS USERNAME CHECK
    # =========================

    suspicious_keywords = [
        "admin",
        "root",
        "sql",
        "' OR 1=1",
        "--"
    ]

    for keyword in suspicious_keywords:

        if keyword.lower() in username.lower():

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
                severity=severity
            )

            logger.warning({
                "event": "suspicious_username_detected",
                "ip": client_ip,
                "username": username,
                "threat_score": threat_scores[client_ip],
                "severity": severity,
                "timestamp": str(datetime.now())
            })

            break

    # =========================
    # CLEAN OLD REQUESTS
    # =========================

    request_logs[client_ip] = [
        t for t in request_logs[client_ip]
        if current_time - t < RATE_LIMIT_WINDOW
    ]

    request_count = len(
        request_logs[client_ip]
    )

    # =========================
    # CHECK IF BLOCKED
    # =========================

    if client_ip in blocked_ips:

        block_data = blocked_ips[client_ip]

        blocked_time = block_data["blocked_at"]

        block_reason = block_data["reason"]

        if current_time - blocked_time < BLOCK_DURATION:

            remaining_time = int(
                BLOCK_DURATION - (
                    current_time - blocked_time
                )
            )

            save_attack_log(
                event="blocked_ip_access_attempt",
                ip=client_ip,
                username=username,
                status="BLOCKED",
                reason=block_reason,
                severity="CRITICAL"
            )

            logger.critical({
                "event": "blocked_ip_access_attempt",
                "ip": client_ip,
                "block_reason": block_reason,
                "request_count": 0,
                "severity": "CRITICAL",
                "timestamp": str(datetime.now())
            })

            return {
                "status": "blocked",
                "message": f"IP blocked due to {block_reason}",
                "retry_after_seconds": remaining_time
            }

        else:

            # =========================
            # AUTO RECOVERY
            # =========================

            save_attack_log(
                event="ip_unblocked",
                ip=client_ip,
                username=username,
                status="RECOVERED",
                reason="BLOCK_DURATION_EXPIRED",
                severity="LOW"
            )

            logger.info({
                "event": "ip_unblocked",
                "ip": client_ip,
                "message": "IP automatically unblocked",
                "timestamp": str(datetime.now())
            })

            del blocked_ips[client_ip]

            failed_attempts[client_ip] = 0

            threat_scores[client_ip] = 0

    # =========================
    # REQUEST RATE MONITORING
    # =========================

    request_logs[client_ip].append(
        current_time
    )

    request_logs[client_ip] = [
        t for t in request_logs[client_ip]
        if current_time - t < RATE_LIMIT_WINDOW
    ]

    request_count = len(
        request_logs[client_ip]
    )

    # =========================
    # TRAFFIC SPIKE DETECTION
    # =========================

    if request_count > MAX_REQUESTS:

        threat_scores[client_ip] += 40

        severity = get_severity(
            threat_scores[client_ip]
        )

        blocked_ips[client_ip] = {
            "blocked_at": current_time,
            "reason": "TRAFFIC_SPIKE"
        }

        save_attack_log(
            event="traffic_spike_detected",
            ip=client_ip,
            username=username,
            status="BLOCKED",
            reason="TRAFFIC_SPIKE",
            severity=severity
        )

        logger.critical({
            "event": "traffic_spike_detected",
            "ip": client_ip,
            "request_count": request_count,
            "severity": severity,
            "threat_score": threat_scores[client_ip],
            "action_taken": "IP_BLOCKED",
            "timestamp": str(datetime.now())
        })

        return {
            "status": "blocked",
            "message": "Traffic spike detected. IP temporarily blocked."
        }

    # =========================
    # FAILED LOGIN
    # =========================

    if not verify_user(
        username,
        password
    ):

        failed_attempts[client_ip] = (
            failed_attempts.get(
                client_ip,
                0
            ) + 1
        )

        current_attempts = (
            failed_attempts[client_ip]
        )

        # =========================
        # UPDATE THREAT SCORE
        # =========================

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
            severity=severity
        )

        logger.warning({
            "event": "failed_login",
            "username": username,
            "ip": client_ip,
            "failed_attempts": current_attempts,
            "request_count": request_count,
            "severity": severity,
            "threat_score": threat_scores[client_ip],
            "timestamp": str(datetime.now())
        })

        # =========================
        # CRITICAL THREAT SCORE
        # =========================

        if threat_scores[client_ip] >= 80:

            blocked_ips[client_ip] = {
                "blocked_at": current_time,
                "reason": "CRITICAL_THREAT_SCORE"
            }

            save_attack_log(
                event="critical_threat_detected",
                ip=client_ip,
                username=username,
                status="BLOCKED",
                reason="CRITICAL_THREAT_SCORE",
                severity="CRITICAL"
            )

            logger.critical({
                "event": "critical_threat_detected",
                "ip": client_ip,
                "severity": "CRITICAL",
                "threat_score": threat_scores[client_ip],
                "action_taken": "IP_BLOCKED",
                "timestamp": str(datetime.now())
            })

            return {
                "status": "blocked",
                "message": "Critical threat detected. IP blocked."
            }

        # =========================
        # ML PREDICTION
        # =========================

        feature = np.array([
            [current_attempts]
        ])

        prediction = model.predict(
            feature
        )[0]

        # =========================
        # ML ANOMALY DETECTED
        # =========================

        if prediction == -1:

            threat_scores[client_ip] += 50

            severity = get_severity(
                threat_scores[client_ip]
            )

            blocked_ips[client_ip] = {
                "blocked_at": current_time,
                "reason": "ML_ANOMALY"
            }

            save_attack_log(
                event="ml_anomaly_detected",
                ip=client_ip,
                username=username,
                status="BLOCKED",
                reason="ML_ANOMALY",
                severity=severity
            )

            logger.critical({
                "event": "ml_anomaly_detected",
                "ip": client_ip,
                "failed_attempts": current_attempts,
                "request_count": request_count,
                "severity": severity,
                "threat_score": threat_scores[client_ip],
                "action_taken": "IP_BLOCKED",
                "timestamp": str(datetime.now())
            })

            return {
                "status": "blocked",
                "message": "AI detected suspicious activity. IP blocked."
            }

        return {
            "status": "failed",
            "message": "Invalid credentials"
        }

    # =========================
    # SUCCESS LOGIN
    # =========================

    failed_attempts[client_ip] = 0

    threat_scores[client_ip] = 0

    save_attack_log(
        event="successful_login",
        ip=client_ip,
        username=username,
        status="SUCCESS",
        reason="NONE",
        severity="LOW"
    )

    logger.info({
        "event": "successful_login",
        "username": username,
        "ip": client_ip,
        "request_count": request_count,
        "severity": "LOW",
        "threat_score": 0,
        "timestamp": str(datetime.now())
    })

    return {
        "status": "success",
        "message": "Login successful"
    }