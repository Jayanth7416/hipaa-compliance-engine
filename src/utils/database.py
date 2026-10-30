"""SQLAlchemy Database Persistence Layer"""

from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.utils.config import settings


def utc_now() -> datetime:
    """Return timezone-naive UTC datetime for consistent storage and serialization."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    """Declarative base for ORM models."""
    pass


class AuditLogModel(Base):
    """Immutable tamper-evident audit log table (§164.312(b))."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=utc_now, index=True)
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(128), nullable=False, index=True)
    resource_id = Column(String(256), nullable=True, index=True)
    user_id = Column(String(128), nullable=True, index=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    details = Column(JSON, nullable=False, default=dict)
    status = Column(String(32), nullable=False, default="success", index=True)
    duration_ms = Column(Integer, nullable=True)
    previous_hash = Column(String(64), nullable=False, default="GENESIS")
    entry_hash = Column(String(64), nullable=False, index=True)


class TokenVaultModel(Base):
    """Persistent encrypted token vault for reversible PHI tokenization."""

    __tablename__ = "token_vault"

    token = Column(String(128), primary_key=True)
    encrypted_value = Column(Text, nullable=False)
    value_hash = Column(String(64), nullable=False, index=True)
    field_path = Column(String(256), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utc_now)


class EncryptionKeyModel(Base):
    """Persistent encryption key store with envelope-wrapped key material."""

    __tablename__ = "encryption_keys"

    key_id = Column(String(128), primary_key=True)
    alias = Column(String(128), nullable=False)
    algorithm = Column(String(64), nullable=False, default="AES-256-GCM")
    wrapped_key = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="active")
    is_active = Column(Boolean, nullable=False, default=False)
    usage_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    rotated_at = Column(DateTime, nullable=True)


class ComplianceViolationModel(Base):
    """Persistent compliance violation record."""

    __tablename__ = "compliance_violations"

    violation_id = Column(String(64), primary_key=True)
    detected_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    resource_type = Column(String(128), nullable=False)
    resource_id = Column(String(256), nullable=True)
    policy_id = Column(String(128), nullable=False, index=True)
    policy_name = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False, default=dict)
    status = Column(String(32), nullable=False, default="open", index=True)
    resolution = Column(Text, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(128), nullable=True)


class ComplianceCheckModel(Base):
    """Persistent compliance check execution record."""

    __tablename__ = "compliance_checks"

    check_id = Column(String(64), primary_key=True)
    resource_type = Column(String(128), nullable=False)
    resource_id = Column(String(256), nullable=True)
    checks_performed = Column(JSON, nullable=False, default=list)
    status = Column(String(32), nullable=False)
    score = Column(Float, nullable=False)
    passed = Column(JSON, nullable=False, default=list)
    failed = Column(JSON, nullable=False, default=list)
    warnings = Column(JSON, nullable=False, default=list)
    details = Column(JSON, nullable=False, default=dict)
    checked_at = Column(DateTime, nullable=False, default=utc_now, index=True)


class BatchScanJobModel(Base):
    """Persistent batch scan job state."""

    __tablename__ = "batch_scan_jobs"

    job_id = Column(String(64), primary_key=True)
    status = Column(String(32), nullable=False, default="pending")
    total = Column(Integer, nullable=False, default=0)
    processed = Column(Integer, nullable=False, default=0)
    failed = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    results = Column(JSON, nullable=False, default=list)


def _create_db_engine(db_url: Optional[str] = None):
    url = db_url or settings.DATABASE_URL
    connect_args: Dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(url, connect_args=connect_args, future=True)


engine = _create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create database tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


def get_db_session() -> Session:
    """Create a new database session (ensuring tables are initialized)."""
    init_db()
    return SessionLocal()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    session = get_db_session()
    try:
        yield session
    finally:
        session.close()
