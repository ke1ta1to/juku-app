"""add qr_tokens table for audit logging

Revision ID: 0004
Revises: 0003
Create Date: 2025-01-04 00:00:00.000000

用途:
  塾共通QRトークンの発行・使用を監査するテーブル。
  セキュリティインシデント調査や統計収集に使う。

設計:
  - QR画面をリロードするたびに issued_at / token_hash を記録
  - スキャンされるたびに used_count / last_used_at を更新
  - token_hash は SHA-256（トークン本体は保存しない）
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "qr_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("academy_id", sa.String(64), nullable=False),
        sa.Column("window", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_qr_tokens_id", "qr_tokens", ["id"])
    op.create_index("ix_qr_tokens_window", "qr_tokens", ["window"])
    op.create_index("ix_qr_tokens_token_hash", "qr_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_table("qr_tokens")
