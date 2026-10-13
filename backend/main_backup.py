from fastapi import FastAPI, Request
from pydantic import BaseModel
from utils.logger_config import logger
from collections import defaultdict

from datetime import datetime
import time
import joblib
import numpy as np

app = FastAPI()

# =========================
# LOAD TRAINED ML MODEL
# =========================

model = joblib.load("../ml_engine/threat_detection_model.pkl")

# =========================
# IN-MEMORY STORAGE
# =========================

failed_attempts = {}

# ip -> {
#     blocked_at: ...,
#     reason: ...
# }
blocked_ips = {}

# REQUEST TRACKING
request_logs = defaultdict(list)

# =========================
# SECURITY CONFIG
# =========================

RATE_LIMIT_WINDOW = 10
MAX_REQUESTS = 5

BLOCK_DURATION = 30

# =========================
# REQUEST MODEL
# =========================

class LoginRequest(BaseModel):
    username: str
    password: str

# =========================
# HOME ROUTE
# =========================

@app.get("/")
def home():
    return {
        "message": "AutoSecCloud running successfully"
    }

# =========================
# LOGIN ROUTE
# =========================

@app.post("/login")
async def login(request: Request, data: LoginRequest):

    username = data.username
    password = data.password

    # REAL CLIENT IP
    client_ip = request.client.host

    current_time = time.time()

    # =========================
    # CLEAN OLD REQUESTS
    # =========================

    request_logs[client_ip] = [
        t for t in request_logs[client_ip]
        if current_time - t < RATE_LIMIT_WINDOW
    ]

    request_count = len(request_logs[client_ip])

    # =========================
    # CHECK IF IP IS BLOCKED
    # =========================

    if client_ip in blocked_ips:

        block_data = blocked_ips[client_ip]

        blocked_time = block_data["blocked_at"]

        block_reason = block_data["reason"]

        # STILL BLOCKED
        if current_time - blocked_time < BLOCK_DURATION:

            remaining_time = int(
                BLOCK_DURATION - (current_time - blocked_time)
            )

            logger.critical({
                "event": "blocked_ip_access_attempt",
                "ip": client_ip,
                "block_reason": block_reason,
                "request_count": 0,
                "timestamp": str(datetime.now())
            })

            return {
                "status": "blocked",
                "message": f"IP blocked due to {block_reason}",
                "retry_after_seconds": remaining_time
            }

        # BLOCK EXPIRED
        else:
            del blocked_ips[client_ip]
            failed_attempts[client_ip] = 0

    # =========================
    # REQUEST RATE MONITORING
    # =========================

    request_logs[client_ip].append(current_time)

    # REMOVE OLD REQUESTS AGAIN
    request_logs[client_ip] = [
        t for t in request_logs[client_ip]
        if current_time - t < RATE_LIMIT_WINDOW
    ]

    request_count = len(request_logs[client_ip])

    # =========================
    # TRAFFIC SPIKE DETECTION
    # =========================

    if request_count > MAX_REQUESTS:

        blocked_ips[client_ip] = {
            "blocked_at": current_time,
            "reason": "TRAFFIC_SPIKE"
        }

        logger.critical({
            "event": "traffic_spike_detected",
            "ip": client_ip,
            "request_count": request_count,
            "action_taken": "IP_BLOCKED",
            "timestamp": str(datetime.now())
        })

        return {
            "status": "blocked",
            "message": "Traffic spike detected. IP temporarily blocked."
        }

    # =========================
    # FAILED LOGIN HANDLING
    # =========================

    if password != "admin123":

        failed_attempts[client_ip] = (
            failed_attempts.get(client_ip, 0) + 1
        )

        current_attempts = failed_attempts[client_ip]

        logger.warning({
            "event": "failed_login",
            "username": username,
            "ip": client_ip,
            "failed_attempts": current_attempts,
            "request_count": request_count,
            "timestamp": str(datetime.now())
        })

        # =========================
        # ML FEATURE VECTOR
        # =========================

        feature = np.array([[current_attempts]])

        # ML PREDICTION
        prediction = model.predict(feature)[0]

        # =========================
        # ML ANOMALY DETECTED
        # =========================

        if prediction == -1:

            blocked_ips[client_ip] = {
                "blocked_at": current_time,
                "reason": "ML_ANOMALY"
            }

            logger.critical({
                "event": "ml_anomaly_detected",
                "ip": client_ip,
                "failed_attempts": current_attempts,
                "request_count": request_count,
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
    # SUCCESSFUL LOGIN
    # =========================

    # RESET FAILED ATTEMPTS
    failed_attempts[client_ip] = 0

    logger.info({
        "event": "successful_login",
        "username": username,
        "ip": client_ip,
        "request_count": request_count,
        "timestamp": str(datetime.now())
    })

    return {
        "status": "success",
        "message": "Login successful"
    }