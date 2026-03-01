"""
permissions テーブル

管理者教師に付与できる細粒度の権限。
is_admin=True の教師にのみ付与を許可する運用とする（アプリ層で保証）。

現在定義されている perm 値:
  manage_users   … ユーザーの追加・削除・退会処理
  manage_roles   … ロール・権限の変更
  view_all_logs  … 全ユーザーの入退室履歴閲覧

将来追加例: manage_schedule, export_csv, etc.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.base import Base
import enum


class PermEnum(str, enum.Enum):
    manage_users = "manage_users"   # ユーザー追加・削除・退会
    manage_roles = "manage_roles"   # ロール・権限変更
    view_all_logs = "view_all_logs" # 全員の入退室ログ閲覧


# 管理者が持てる全権限（シード・検証に使う）
ALL_ADMIN_PERMS: list[PermEnum] = list(PermEnum)


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("user_id", "perm", name="uq_permissions_user_perm"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    perm = Column(Enum(PermEnum), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # リレーション（逆参照は users.permissions で使う）
    user = relationship("User", back_populates="permissions")
