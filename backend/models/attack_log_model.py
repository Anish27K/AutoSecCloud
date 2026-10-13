from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime
)

from config.database import Base

from datetime import datetime

class AttackLog(Base):

    __tablename__ = "attack_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    event = Column(String)

    ip = Column(String)

    username = Column(String)

    status = Column(String)

    reason = Column(String)

    severity = Column(
        String,
        default="LOW"
    )

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )