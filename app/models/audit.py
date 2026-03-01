"""
監査・不正検知モデル（Phase 7）

テーブル構成:
  scan_events  … QR スキャン 1 回ごとの完全証跡
  alert_logs   … 不正検知アラートの記録

設計思想:
  ─ scan_events ─────────────────────────────────────────────────
  attendance_logs は「最終状態」（1日1行）を保持する。
  scan_events は「操作の生ログ」（スキャン1回=1行）を保持する。

  なぜ分けるか:
    - 失敗したスキャン（無効QR、退会済みユーザー等）も記録したい
    - 同一ユーザーが複数回スキャンしても全部残したい（揉めた時の証拠）
    - attendance_logs への影響なしに証跡を追記できる

  ─ alert_logs ───────────────────────────────────────────────────
  不正検知エンジンが発火したアラートをすべて記録する。
  管理者が /audit/alerts で確認できる。
  解決済みは resolved=True にすることで既読管理できる。
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Index, Integer, String, Text
)
from app.db.base import Base


# ── アラート種別 ─────────────────────────────────────────────────────────────

class AlertTypeEnum(str, enum.Enum):
    qr_abuse        = "qr_abuse"         # 1トークンで大量スキャン
    ip_burst        = "ip_burst"         # 同一IPから短時間に大量スキャン
    device_mismatch = "device_mismatch"  # 同一ユーザーが複数デバイスから短時間スキャン
    unknown         = "unknown"          # その他


class AlertSeverityEnum(str, enum.Enum):
    info    = "info"    # 念のため記録（緊急度低）
    warning = "warning" # 調査推奨
    critical = "critical" # 即対応が必要


# ── スキャン結果 ─────────────────────────────────────────────────────────────

class ScanResultEnum(str, enum.Enum):
    success        = "success"         # 入退室成功
    invalid_qr     = "invalid_qr"      # QR検証失敗
    expired_qr     = "expired_qr"      # 期限切れQR
    inactive_user  = "inactive_user"   # 退会済みユーザー
    already_done   = "already_done"    # 本日すでに退室済み
    unknown_error  = "unknown_error"   # その他エラー


# ════════════════════════════════════════════════════════════
#  scan_events
# ════════════════════════════════════════════════════════════

class ScanEvent(Base):
    """
    QR スキャン 1 回ごとの完全証跡テーブル。

    成功・失敗を問わず全スキャンを記録する。
    attendance_logs の補助テーブルとして「操作の生ログ」を担う。
    """
    __tablename__ = "scan_events"
    __table_args__ = (
        # よく使う検索条件にインデックス
        Index("ix_scan_events_user_scanned", "user_id", "scanned_at"),
        Index("ix_scan_events_ip_scanned",   "ip_address", "scanned_at"),
        Index("ix_scan_events_token_hash",   "qr_token_hash"),
    )

    id = Column(Integer, primary_key=True, index=True)

    # ── 誰が ────────────────────────────────────────────────────────────────
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),  # ユーザー削除後も証跡は残す
        nullable=True,
        index=True,
    )

    # ── 何を使って ──────────────────────────────────────────────────────────
    # QR トークンの SHA-256 ハッシュ（平文は保存しない）
    # NULL の場合は手動トグル（QR 未使用）
    qr_token_hash = Column(String(64), nullable=True, index=True)

    # ── どこから ─────────────────────────────────────────────────────────────
    # リクエスト元 IP（プロキシ経由の場合は X-Forwarded-For の先頭）
    ip_address = Column(String(45), nullable=True)  # IPv6 最大 45 文字

    # 端末識別子（クライアントが送ってくる任意文字列）
    # 例: "iPad-entrance-01", "student-iPhone-abc123"
    # NULL = 端末識別なし（旧クライアントや手動トグル）
    device_id = Column(String(255), nullable=True)

    # User-Agent（詳細な端末情報）
    user_agent = Column(String(512), nullable=True)

    # ── 結果 ──────────────────────────────────────────────────────────────
    result = Column(Enum(ScanResultEnum), nullable=False)
    result_detail = Column(Text, nullable=True)  # エラーメッセージなど

    # 入室 or 退室（成功時のみ設定）
    action = Column(String(16), nullable=True)  # "check_in" | "check_out" | NULL

    # ── いつ ─────────────────────────────────────────────────────────────────
    scanned_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<ScanEvent user={self.user_id} result={self.result} "
            f"ip={self.ip_address} at={self.scanned_at}>"
        )


# ════════════════════════════════════════════════════════════
#  alert_logs
# ════════════════════════════════════════════════════════════

class AlertLog(Base):
    """
    不正検知アラートの記録テーブル。

    不正検知エンジンがトリガーされるたびに1行追加される。
    管理者ダッシュボードで確認・解決済みマークができる。
    """
    __tablename__ = "alert_logs"
    __table_args__ = (
        Index("ix_alert_logs_created_resolved", "created_at", "resolved"),
        Index("ix_alert_logs_type_created",     "alert_type", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)

    # アラート種別・重要度
    alert_type = Column(Enum(AlertTypeEnum), nullable=False)
    severity   = Column(Enum(AlertSeverityEnum), nullable=False)

    # 関連エンティティ（任意）
    user_id       = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    qr_token_hash = Column(String(64), nullable=True)  # 対象トークン
    ip_address    = Column(String(45), nullable=True)  # 対象 IP

    # 詳細メッセージ（JSON 文字列として格納）
    # 例: {"scan_count": 60, "limit": 50, "window_secs": 60}
    detail = Column(Text, nullable=True)

    # 対象スキャンイベントへの参照（任意）
    trigger_scan_event_id = Column(
        Integer,
        ForeignKey("scan_events.id", ondelete="SET NULL"),
        nullable=True,
    )

    # 解決管理
    resolved    = Column(Boolean, default=False, nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    note        = Column(Text, nullable=True)  # 解決メモ

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<AlertLog type={self.alert_type} sev={self.severity} "
            f"resolved={self.resolved} at={self.created_at}>"
        )
