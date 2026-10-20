from sqlalchemy import text, Integer
from sqlalchemy.exc import IntegrityError

from backend.config.database import engine
from passlib.context import CryptContext


# =========================
# PASSWORD HASHING
# =========================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


# =========================
# CREATE USER TABLE
# =========================

def create_users_table():
    id_type = (
        "SERIAL"
        if engine.dialect.name == "postgresql"
        else "INTEGER"
    )

    with engine.begin() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS users (
                id {id_type} PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        """))


# =========================
# HASH PASSWORD
# =========================

def hash_password(password):
    return pwd_context.hash(password)


# =========================
# VERIFY PASSWORD
# =========================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# =========================
# CREATE USER
# =========================

def create_user(username, password):
    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO users (username, password, role)
                    VALUES (:username, :password, :role)
                """),
                {
                    "username": username,
                    "password": hash_password(password),
                    "role": "user"
                }
            )

        return {
            "status": "success",
            "message": "User created successfully"
        }

    except IntegrityError:
        return {
            "status": "failed",
            "message": "Username already exists"
        }


# =========================
# GET USER
# =========================

def get_user(username):
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM users WHERE username = :username"),
            {"username": username}
        )
        return result.fetchone()


# =========================
# VERIFY USER
# =========================

def verify_user(username, password):
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT password FROM users WHERE username = :username"),
            {"username": username}
        )
        user = result.fetchone()

    if not user:
        return False

    return verify_password(password, user[0])


# =========================
# GET USER ROLE
# =========================

def get_user_role(username):
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT role FROM users WHERE username = :username"),
            {"username": username}
        )
        user = result.fetchone()

    return user[0] if user else None