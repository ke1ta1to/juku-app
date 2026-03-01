"""add audit tables: scan_events, alert_logs + attendance_logs forensic columns

Revision ID: 0005
Revises: 0004
Create Date: 2025-01-05 00:00:00.000000

変更内容:
  1. attendance_logs に証跡カラム追加
       ip_in, device_in  … 入室時の IP・端末
       ip_out, device_out … 退室時の IP・端末

  2. scan_events テーブル新設
       QR スキャン 1 回ごとの完全証跡（成功・失敗両方）

  3. alert_logs テーブル新設
       不正検知エンジンが発火したアラートの記録
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. attendance_logs に証跡カラム追加 ────────────────────────────────────
    with op.batch_alter_table("attendance_logs") as batch_op:
        batch_op.add_column(sa.Column("ip_in",     sa.String(45),  nullable=True))
        batch_op.add_column(sa.Column("device_in",  sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("ip_out",    sa.String(45),  nullable=True))
        batch_op.add_column(sa.Column("device_out", sa.String(255), nullable=True))

    # ── 2. scan_events テーブル ────────────────────────────────────────────────
    op.create_table(
        "scan_events",
        sa.Column("id",            sa.Integer(),    primary_key=True),
        sa.Column("user_id",       sa.Integer(),    sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("qr_token_hash", sa.String(64),   nullable=True),
        sa.Column("ip_address",    sa.String(45),   nullable=True),
        sa.Column("device_id",     sa.String(255),  nullable=True),
        sa.Column("user_agent",    sa.String(512),  nullable=True),
        sa.Column("result",        sa.String(32),   nullable=False),
        sa.Column("result_detail", sa.Text(),       nullable=True),
        sa.Column("action",        sa.String(16),   nullable=True),
        sa.Column("scanned_at",    sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_scan_events_id",           "scan_events", ["id"])
    op.create_index("ix_scan_events_user_scanned", "scan_events", ["user_id",    "scanned_at"])
    op.create_index("ix_scan_events_ip_scanned",   "scan_events", ["ip_address", "scanned_at"])
    op.create_index("ix_scan_events_token_hash",   "scan_events", ["qr_token_hash"])

    # ── 3. alert_logs テーブル ─────────────────────────────────────────────────
    op.create_table(
        "alert_logs",
        sa.Column("id",                    sa.Integer(),  primary_key=True),
        sa.Column("alert_type",            sa.String(32), nullable=False),
        sa.Column("severity",              sa.String(16), nullable=False),
        sa.Column("user_id",               sa.Integer(),  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("qr_token_hash",         sa.String(64), nullable=True),
        sa.Column("ip_address",            sa.String(45), nullable=True),
        sa.Column("detail",                sa.Text(),     nullable=True),
        sa.Column("trigger_scan_event_id", sa.Integer(),
                  sa.ForeignKey("scan_events.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved",              sa.Boolean(),  nullable=False, server_default=sa.text("false")),
        sa.Column("resolved_at",           sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by",           sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("note",                  sa.Text(),     nullable=True),
        sa.Column("created_at",            sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_alert_logs_id",             "alert_logs", ["id"])
    op.create_index("ix_alert_logs_created_resolved","alert_logs", ["created_at", "resolved"])
    op.create_index("ix_alert_logs_type_created",   "alert_logs", ["alert_type", "created_at"])
    op.create_index("ix_alert_logs_resolved",       "alert_logs", ["resolved"])


def downgrade() -> None:
    op.drop_table("alert_logs")
    op.drop_table("scan_events")
    with op.batch_alter_table("attendance_logs") as batch_op:
        batch_op.drop_column("device_out")
        batch_op.drop_column("ip_out")
        batch_op.drop_column("device_in")
        batch_op.drop_column("ip_in")
