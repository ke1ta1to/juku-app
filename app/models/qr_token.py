"""
qr_tokens テーブルモデル

塾共通QRの発行・スキャン履歴を記録する監査テーブル。
セキュリティインシデント（異常なスキャン数など）の検出に使う。
"""
import hashlib
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String
from app.db.base import Base


class QRToken(Base):
    __tablename__ = "qr_tokens"

    id = Column(Integer, primary_key=True, index=True)

    # トークン本体の SHA-256 ハッシュ（平文は保存しない）
    token_hash = Column(String(64), nullable=False, unique=True, index=True)

    academy_id = Column(String(64), nullable=False)
    window = Column(Integer, nullable=False, index=True)  # タイムウィンドウ番号

    issued_at = Column(DateTime(timezone=True), nullable=False,
                       default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # スキャン統計（監査用）
    used_count = Column(Integer, nullable=False, default=0)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    @staticmethod
    def hash_token(token: str) -> str:
        """トークン文字列を SHA-256 ハッシュ化して返す"""
        return hashlib.sha256(token.encode()).hexdigest()

    def __repr__(self) -> str:
        return (
            f"<QRToken academy={self.academy_id} window={self.window} "
            f"used={self.used_count}>"
        )
