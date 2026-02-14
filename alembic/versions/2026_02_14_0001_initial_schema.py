"""Initial schema - all 5 tables

Revision ID: 0001
Revises: 
Create Date: 2026-02-14
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Organizations ────────────────────────────────────────
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("subscription_tier", sa.String(50), server_default="free", nullable=False),
        sa.Column("max_users", sa.Integer(), server_default="5", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_organizations_domain", "organizations", ["domain"])

    # ── Users ────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("role", sa.String(50), server_default="user", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("is_verified", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.create_index("ix_users_org_active", "users", ["organization_id", "is_active"])

    # ── Prompt Logs ──────────────────────────────────────────
    op.create_table(
        "prompt_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("original_prompt", sa.Text(), nullable=False),
        sa.Column("redacted_prompt", sa.Text(), nullable=True),
        sa.Column("ai_platform", sa.String(50), nullable=True),
        sa.Column("entities_detected", sa.Integer(), server_default="0", nullable=False),
        sa.Column("entity_types", postgresql.JSONB(), nullable=True),
        sa.Column("detection_details", postgresql.JSONB(), nullable=True),
        sa.Column("redaction_mapping", postgresql.JSONB(), nullable=True),
        sa.Column("was_blocked", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("was_overridden", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("session_id", sa.String(255), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
    )
    op.create_index("ix_prompt_logs_user_id", "prompt_logs", ["user_id"])
    op.create_index("ix_prompt_logs_organization_id", "prompt_logs", ["organization_id"])
    op.create_index(
        "ix_prompt_logs_org_created",
        "prompt_logs",
        ["organization_id", sa.text("created_at DESC")],
    )
    op.create_index("ix_prompt_logs_ai_platform", "prompt_logs", ["ai_platform"])
    op.create_index("ix_prompt_logs_session_id", "prompt_logs", ["session_id"])
    op.create_index(
        "ix_prompt_logs_entity_types",
        "prompt_logs",
        ["entity_types"],
        postgresql_using="gin",
    )

    # ── Detection Patterns ───────────────────────────────────
    op.create_table(
        "detection_patterns",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("pattern_type", sa.String(50), nullable=False),
        sa.Column("pattern_value", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("severity", sa.String(20), server_default="medium", nullable=False),
        sa.Column("action", sa.String(20), server_default="redact", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
    )
    op.create_index(
        "ix_detection_patterns_org_active",
        "detection_patterns",
        ["organization_id", "is_active"],
    )

    # ── Audit Logs ───────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("event_data", postgresql.JSONB(), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
    )
    op.create_index(
        "ix_audit_logs_org_event_created",
        "audit_logs",
        ["organization_id", "event_type", sa.text("created_at DESC")],
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("detection_patterns")
    op.drop_table("prompt_logs")
    op.drop_table("users")
    op.drop_table("organizations")
