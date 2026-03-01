from datetime import datetime, timezone
import enum

from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String
from sqlalchemy.orm import relationship

from app.db.base import Base


class RoleEnum(str, enum.Enum):
    teacher = "teacher"
    student = "student"


class StatusEnum(str, enum.Enum):
    active = "active"
    inactive = "inactive"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    # 基本情報
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    phone = Column(String(20), nullable=True)
    hashed_password = Column(String, nullable=False)

    # 役割・権限
    role = Column(Enum(RoleEnum), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    # ↑ is_admin=True の教師のみ permissions テーブルに行を持つ運用。
    #   生徒に is_admin=True を付けることはアプリ層で禁止する。

    # 在籍状態
    status = Column(Enum(StatusEnum), default=StatusEnum.active, nullable=False)

    # 監査タイムスタンプ
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── リレーション ────────────────────────────────────────────────────────
    permissions = relationship(
        "Permission",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    attendance_logs = relationship(
        "AttendanceLog",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    # ── ヘルパー ─────────────────────────────────────────────────────────────
    def has_perm(self, perm: str) -> bool:
        """指定権限を保持しているか判定"""
        return self.is_admin and any(p.perm == perm for p in self.permissions)

    def perm_list(self) -> list[str]:
        return [p.perm for p in self.permissions]

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"
