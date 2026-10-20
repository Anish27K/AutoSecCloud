from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError

from backend.config.database import SessionLocal
from backend.models.attack_log_model import AttackLog
from backend.services.auth_service import verify_admin

router = APIRouter()


# =========================
# SERIALIZE ATTACK LOG
# =========================

def serialize_attack_log(log):
    return {
        "id": log.id,
        "event": log.event,
        "ip": log.ip,
        "username": log.username,
        "status": log.status,
        "reason": log.reason,
        "severity": log.severity,
        "timestamp": (
            log.timestamp.isoformat()
            if log.timestamp
            else None
        )
    }


# =========================
# GET ALL ATTACK LOGS
# ADMIN ONLY
# =========================

@router.get("/attacks")
def get_all_attacks(user=Depends(verify_admin)):
    db = SessionLocal()

    try:
        logs = db.scalars(
            select(AttackLog).order_by(AttackLog.id.desc())
        ).all()

        log_data = [serialize_attack_log(log) for log in logs]

        return {
            "total_logs": len(log_data),
            "logs": log_data
        }

    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve attack logs"
        )

    finally:
        db.close()


# =========================
# GET ONLY BLOCKED ATTACKS
# ADMIN ONLY
# =========================

@router.get("/blocked-attacks")
def get_blocked_attacks(user=Depends(verify_admin)):
    db = SessionLocal()

    try:
        logs = db.scalars(
            select(AttackLog)
            .where(AttackLog.status == "BLOCKED")
            .order_by(AttackLog.id.desc())
        ).all()

        log_data = [serialize_attack_log(log) for log in logs]

        return {
            "blocked_logs": log_data
        }

    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve blocked attacks"
        )

    finally:
        db.close()


# =========================
# SECURITY STATISTICS
# ADMIN ONLY
# =========================

@router.get("/stats")
def get_security_stats(user=Depends(verify_admin)):
    db = SessionLocal()

    try:
        total_logs = db.scalar(
            select(func.count()).select_from(AttackLog)
        )

        blocked_count = db.scalar(
            select(func.count())
            .select_from(AttackLog)
            .where(AttackLog.status == "BLOCKED")
        )

        failed_logins = db.scalar(
            select(func.count())
            .select_from(AttackLog)
            .where(AttackLog.event == "failed_login")
        )

        successful_logins = db.scalar(
            select(func.count())
            .select_from(AttackLog)
            .where(AttackLog.event == "successful_login")
        )

        return {
            "total_logs": total_logs,
            "blocked_attacks": blocked_count,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins
        }

    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve security statistics"
        )

    finally:
        db.close()