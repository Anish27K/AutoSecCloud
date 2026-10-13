from config.database import SessionLocal

from models.attack_log_model import AttackLog

# =========================
# SAVE SECURITY EVENT
# =========================

def save_attack_log(
    event,
    ip,
    username="UNKNOWN",
    status="UNKNOWN",
    reason="NONE",
    severity="LOW"
):

    db = SessionLocal()

    try:

        log = AttackLog(
            event=event,
            ip=ip,
            username=username,
            status=status,
            reason=reason,
            severity=severity
        )

        db.add(log)

        db.commit()

    finally:

        db.close()