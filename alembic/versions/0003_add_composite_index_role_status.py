"""add composite index on users(role, status) for filtered list queries

Revision ID: 0003
Revises: 0002
Create Date: 2025-01-03 00:00:00.000000

背景:
  GET /users?role=student&status=active のような複合フィルタクエリが
  Phase 3 で追加されるため、(role, status) の複合インデックスを追加する。
  SQLite では有効。PostgreSQL 移行時もそのまま使える。
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        # (role, status) 複合インデックス
        # → WHERE role='student' AND status='active' が高速化される
        batch_op.create_index("ix_users_role_status", ["role", "status"])
        # status 単体インデックス
        # → WHERE status='inactive' のみのクエリにも対応
        batch_op.create_index("ix_users_status", ["status"])


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_role_status")
        batch_op.drop_index("ix_users_status")
