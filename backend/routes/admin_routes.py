import sqlite3

from fastapi import APIRouter, HTTPException

from config.database import DATABASE_PATH


router = APIRouter()


# =========================
# DATABASE CONNECTION
# =========================

def get_db_connection():
    return sqlite3.connect(str(DATABASE_PATH))


# =========================
# GET ALL ATTACK LOGS
# =========================

@router.get("/attacks")
def get_all_attacks():

    try:
        with get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("""
                SELECT *
                FROM attack_logs
                ORDER BY id DESC
            """)

            logs = cursor.fetchall()

        return {
            "total_logs": len(logs),
            "logs": logs
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve attack logs"
        )


# =========================
# GET ONLY BLOCKED ATTACKS
# =========================

@router.get("/blocked-attacks")
def get_blocked_attacks():

    try:
        with get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("""
                SELECT *
                FROM attack_logs
                WHERE status = 'BLOCKED'
                ORDER BY id DESC
            """)

            logs = cursor.fetchall()

        return {
            "blocked_logs": logs
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve blocked attacks"
        )


# =========================
# SECURITY STATS
# =========================

@router.get("/stats")
def get_security_stats():

    try:
        with get_db_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("""
                SELECT COUNT(*)
                FROM attack_logs
            """)
            total_logs = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*)
                FROM attack_logs
                WHERE status = 'BLOCKED'
            """)
            blocked_count = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*)
                FROM attack_logs
                WHERE event = 'failed_login'
            """)
            failed_logins = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*)
                FROM attack_logs
                WHERE event = 'successful_login'
            """)
            successful_logins = cursor.fetchone()[0]

        return {
            "total_logs": total_logs,
            "blocked_attacks": blocked_count,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve security statistics"
        )