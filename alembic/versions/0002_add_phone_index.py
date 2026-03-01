"""add index on users.phone for lookup optimization

Revision ID: 0002
Revises: 0001
Create Date: 2025-01-02 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # users.phone は NULL 許容のため、NULL を除いたインデックスが理想だが
    # SQLite は partial index 非対応なので通常インデックスで対応
    with op.batch_alter_table("users") as batch_op:
        batch_op.create_index("ix_users_phone", ["phone"])


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_phone")
