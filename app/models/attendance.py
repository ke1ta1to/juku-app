from datetime import datetime, date, timezone
import enum

from sqlalchemy import Column, Date, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.base import Base


class CheckMethodEnum(str, enum.Enum):
    qr = "qr"
    manual = "manual"  # 将来の手動登録用


class AttendanceLog(Base):
    __tablename__ = "attendance_logs"
    __table_args__ = (
        # 同一ユーザーの同日レコードは1件のみ（入室・退室で同行を更新する）
        UniqueConstraint("user_id", "date", name="uq_attendance_user_date"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    date = Column(Date, nullable=False, index=True)

    # 入室
    check_in_at = Column(DateTime(timezone=True), nullable=True)
    method_in = Column(Enum(CheckMethodEnum), nullable=True)   # ← Phase 0: check_in_method

    # 退室
    check_out_at = Column(DateTime(timezone=True), nullable=True)
    method_out = Column(Enum(CheckMethodEnum), nullable=True)  # ← Phase 0: check_out_method

    # ── 証跡（Phase 7）────────────────────────────────────────────────────────
    # 入室時の証跡
    ip_in     = Column(String(45),  nullable=True)   # クライアント IP（IPv6 対応）
    device_in = Column(String(255), nullable=True)   # 端末識別子

    # 退室時の証跡
    ip_out     = Column(String(45),  nullable=True)
    device_out = Column(String(255), nullable=True)

    # 後方互換: Phase 0 から存在するカラム（将来削除予定）
    device_fingerprint = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # ── リレーション ────────────────────────────────────────────────────────
    user = relationship("User", back_populates="attendance_logs")

    def __repr__(self) -> str:
        return f"<AttendanceLog user_id={self.user_id} date={self.date} in={self.check_in_at} out={self.check_out_at}>"
