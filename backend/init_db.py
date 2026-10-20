from backend.config.database import engine, Base
from backend.models.attack_log_model import AttackLog


# =========================
# INITIALIZE DATABASE
# =========================

def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully")


# =========================
# RUN DIRECTLY
# =========================

if __name__ == "__main__":
    init_db()