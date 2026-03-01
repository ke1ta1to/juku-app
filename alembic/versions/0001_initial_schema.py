"""initial schema: users, permissions, attendance_logs

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# ── リビジョン情報 ────────────────────────────────────────────────────────
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("phone", sa.String(20), nullable=True),
        sa.Column("hashed_password", sa.String(), nullable=False),
        # Enum: SQLite では VARCHAR で格納
        sa.Column(
            "role",
            sa.Enum("teacher", "student", name="roleenum"),
            nullable=False,
        ),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "status",
            sa.Enum("active", "inactive", name="statusenum"),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── permissions ───────────────────────────────────────────────────────
    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "perm",
            sa.Enum("manage_users", "manage_roles", "view_all_logs", name="permenum"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("user_id", "perm", name="uq_permissions_user_perm"),
    )
    op.create_index("ix_permissions_id", "permissions", ["id"])
    op.create_index("ix_permissions_user_id", "permissions", ["user_id"])

    # ── attendance_logs ───────────────────────────────────────────────────
    op.create_table(
        "attendance_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("date", sa.Date(), nullable=False),
        sa.Column("check_in_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "method_in",
            sa.Enum("qr", "manual", name="checkmethodenum"),
            nullable=True,
        ),
        sa.Column("check_out_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "method_out",
            sa.Enum("qr", "manual", name="checkmethodenum"),
            nullable=True,
        ),
        sa.Column("device_fingerprint", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("user_id", "date", name="uq_attendance_user_date"),
    )
    op.create_index("ix_attendance_logs_id", "attendance_logs", ["id"])
    op.create_index("ix_attendance_logs_user_id", "attendance_logs", ["user_id"])
    op.create_index("ix_attendance_logs_date", "attendance_logs", ["date"])


def downgrade() -> None:
    op.drop_table("attendance_logs")
    op.drop_table("permissions")
    op.drop_table("users")
    # Enum 型（PostgreSQL用）のクリーンアップ
    # SQLite では不要だが PostgreSQL 向けに記述しておく
    for enum_name in ("checkmethodenum", "permenum", "statusenum", "roleenum"):
        op.execute(f"DROP TYPE IF EXISTS {enum_name}")
