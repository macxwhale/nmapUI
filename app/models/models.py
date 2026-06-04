from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from ..db.session import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True)
    password_hash = Column(Text)
    role = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    ip_address = Column(String(50))
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True)
    command_template = Column(Text)

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"))
    status = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    result_output = Column(Text)
