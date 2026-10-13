import sqlite3

from passlib.context import CryptContext

from config.database import DATABASE_PATH


# =========================
# DATABASE CONNECTION
# =========================

def get_db_connection():
    return sqlite3.connect(str(DATABASE_PATH))


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

    with get_db_connection() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT DEFAULT 'user'
            )
        """)


# =========================
# HASH PASSWORD
# =========================

def hash_password(password):

    return pwd_context.hash(password)


# =========================
# VERIFY PASSWORD
# =========================

def verify_password(plain_password, hashed_password):

    return pwd_context.verify(
        plain_password,
        hashed_password
    )


# =========================
# CREATE USER
# =========================

def create_user(username, password):

    try:

        with get_db_connection() as conn:

            hashed_password = hash_password(password)

            conn.execute("""
                INSERT INTO users (
                    username,
                    password,
                    role
                )
                VALUES (?, ?, ?)
            """, (
                username,
                hashed_password,
                "user"
            ))

        return {
            "status": "success",
            "message": "User created successfully"
        }

    except sqlite3.IntegrityError:

        return {
            "status": "failed",
            "message": "Username already exists"
        }


# =========================
# GET USER
# =========================

def get_user(username):

    with get_db_connection() as conn:

        return conn.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()


# =========================
# VERIFY USER
# =========================

def verify_user(username, password):

    with get_db_connection() as conn:

        user = conn.execute("""
            SELECT password
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

    if not user:
        return False

    return verify_password(
        password,
        user[0]
    )


# =========================
# GET USER ROLE
# =========================

def get_user_role(username):

    with get_db_connection() as conn:

        result = conn.execute("""
            SELECT role
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

    if not result:
        return None

    return result[0]