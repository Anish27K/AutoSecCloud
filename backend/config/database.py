from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Central database location
DATABASE_PATH = PROJECT_ROOT / "backend" / "autoseccloud.db"

# Absolute SQLite connection URL
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


Base = declarative_base()