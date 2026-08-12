import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship

from app.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """Hardcoded auth table.

    Full Setu has clinic_staff / camp_official / health_admin tiers with
    different access scopes. This fallback only seeds a single
    clinic_staff account — `role` is kept on the model so a role-check
    dependency can be added later without a schema change.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="clinic_staff")


class Worker(Base):
    __tablename__ = "workers"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False, index=True, default=lambda: uuid.uuid4().hex)
    name_ciphertext = Column(String, nullable=False)
    name_dek = Column(String, nullable=False)  # wrapped DEK
    age = Column(Integer, nullable=False)
    gender = Column(String, nullable=False)
    origin_state = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)

    records = relationship("Record", back_populates="worker", order_by="Record.id")


class Record(Base):
    __tablename__ = "records"

    id = Column(Integer, primary_key=True, index=True)
    worker_id = Column(Integer, ForeignKey("workers.id"), nullable=False)
    visit_type = Column(String, nullable=False)
    notes_ciphertext = Column(String, nullable=False)
    notes_dek = Column(String, nullable=False)  # wrapped DEK
    visit_date = Column(String, nullable=False)
    facility_id = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)

    worker = relationship("Worker", back_populates="records")


class ChainBlock(Base):
    __tablename__ = "chain_blocks"

    id = Column(Integer, primary_key=True, index=True)
    worker_token = Column(String, nullable=False, index=True)
    record_hash = Column(String, nullable=False)
    prev_hash = Column(String, nullable=False)
    block_hash = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
