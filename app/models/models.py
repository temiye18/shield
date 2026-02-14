from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import relationship
from app.database import Base


class Organization(Base):
    """Store company/team information and subscription details."""

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=True)
    subscription_tier = Column(String(50), default="free", nullable=False)
    max_users = Column(Integer, default=5, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    users = relationship("User", back_populates="organization")
    prompt_logs = relationship("PromptLog", back_populates="organization")
    detection_patterns = relationship("DetectionPattern", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")

    __table_args__ = (
        Index("ix_organizations_domain", "domain"),
    )


class User(Base):
    """Store user accounts and authentication."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )
    role = Column(String(50), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    organization = relationship("Organization", back_populates="users")
    prompt_logs = relationship("PromptLog", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

    __table_args__ = (
        Index("ix_users_organization_id", "organization_id"),
        Index("ix_users_org_active", "organization_id", "is_active"),
    )


class PromptLog(Base):
    """Store every AI interaction for audit and analytics."""

    __tablename__ = "prompt_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )
    original_prompt = Column(Text, nullable=False)
    redacted_prompt = Column(Text, nullable=True)
    ai_platform = Column(String(50), nullable=True)
    entities_detected = Column(Integer, default=0, nullable=False)
    entity_types = Column(JSONB, nullable=True)
    detection_details = Column(JSONB, nullable=True)
    redaction_mapping = Column(JSONB, nullable=True)
    was_blocked = Column(Boolean, default=False, nullable=False)
    was_overridden = Column(Boolean, default=False, nullable=False)
    session_id = Column(String(255), nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="prompt_logs")
    organization = relationship("Organization", back_populates="prompt_logs")

    __table_args__ = (
        Index("ix_prompt_logs_user_id", "user_id"),
        Index("ix_prompt_logs_organization_id", "organization_id"),
        Index(
            "ix_prompt_logs_org_created",
            "organization_id",
            created_at.desc(),
        ),
        Index("ix_prompt_logs_ai_platform", "ai_platform"),
        Index("ix_prompt_logs_session_id", "session_id"),
        Index(
            "ix_prompt_logs_entity_types",
            "entity_types",
            postgresql_using="gin",
        ),
    )


class DetectionPattern(Base):
    """Custom entity recognition rules per organization."""

    __tablename__ = "detection_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=False
    )
    pattern_type = Column(String(50), nullable=False)  # regex, keyword, ml
    pattern_value = Column(Text, nullable=False)
    entity_type = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    severity = Column(String(20), default="medium", nullable=False)
    action = Column(String(20), default="redact", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    organization = relationship("Organization", back_populates="detection_patterns")

    __table_args__ = (
        Index("ix_detection_patterns_org_active", "organization_id", "is_active"),
    )


class AuditLog(Base):
    """Track security-relevant events for compliance."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )
    event_type = Column(String(50), nullable=False)
    event_data = Column(JSONB, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="audit_logs")
    organization = relationship("Organization", back_populates="audit_logs")

    __table_args__ = (
        Index(
            "ix_audit_logs_org_event_created",
            "organization_id",
            "event_type",
            created_at.desc(),
        ),
        Index("ix_audit_logs_user_id", "user_id"),
    )
