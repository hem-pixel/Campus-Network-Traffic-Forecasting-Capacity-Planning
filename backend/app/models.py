import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, DateTime, Text, ForeignKey, Float, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

URL = os.getenv("DATABASE_URL", "sqlite:///./campus.db")
engine = create_engine(URL, connect_args={"check_same_thread": False} if URL.startswith("sqlite") else {}, pool_pre_ping=True)
Session = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="Viewer")
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    version: Mapped[str] = mapped_column(String(64), unique=True)
    checksum: Mapped[str] = mapped_column(String(64))
    report_json: Mapped[str] = mapped_column(Text)
    rows_json: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Audit(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class DeviceImport(Base):
    __tablename__ = "device_imports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(120), default="approved controller export")
    report_json: Mapped[str] = mapped_column(Text)
    rows_json: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
