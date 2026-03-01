"""
出席関連 Pydantic スキーマ

設計方針:
  - AttendanceOut        … DB ログの生データ（内部・管理用）
  - AttendanceWithUser   … ユーザー名付き（教師向け一覧・live ビュー）
  - TodayRow             … 今日の全員ビュー（欠席ユーザーも含む・教師用）
  - ToggleResponse       … POST /toggle のレスポンス
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, computed_field


# ════════════════════════════════════════════════════════════
#  出力スキーマ
# ════════════════════════════════════════════════════════════

class AttendanceOut(BaseModel):
    """生ログ（自分の履歴など）"""
    id: int
    user_id: int
    date: date
    check_in_at: datetime | None
    check_out_at: datetime | None
    method_in: str | None
    method_out: str | None

    model_config = {"from_attributes": True}

    @classmethod
    def from_log(cls, log) -> "AttendanceOut":
        return cls(
            id=log.id,
            user_id=log.user_id,
            date=log.date,
            check_in_at=log.check_in_at,
            check_out_at=log.check_out_at,
            method_in=log.method_in.value if log.method_in else None,
            method_out=log.method_out.value if log.method_out else None,
        )


class AttendanceWithUser(BaseModel):
    """
    ユーザー情報付きのログ（教師向け一覧・live）
    DB の join 結果を受け取り、ユーザー名もセットにして返す。
    """
    log_id: int | None          # ログが存在しない（欠席）場合は None
    user_id: int
    user_name: str
    user_role: str
    date: date
    check_in_at: datetime | None
    check_out_at: datetime | None
    method_in: str | None
    method_out: str | None

    @computed_field  # type: ignore[misc]
    @property
    def attendance_status(self) -> str:
        """
        フロントで使いやすい状態文字列を自動計算する。

        absent    … 今日のログなし（未出席）
        checked_in  … 入室済み・退室前（在室中）
        checked_out … 入室・退室どちらも完了
        """
        if self.check_in_at is None:
            return "absent"
        if self.check_out_at is None:
            return "checked_in"
        return "checked_out"

    @classmethod
    def from_log_and_user(cls, log, user) -> "AttendanceWithUser":
        return cls(
            log_id=log.id if log else None,
            user_id=user.id,
            user_name=user.name,
            user_role=user.role.value,
            date=log.date if log else date.today(),
            check_in_at=log.check_in_at if log else None,
            check_out_at=log.check_out_at if log else None,
            method_in=log.method_in.value if (log and log.method_in) else None,
            method_out=log.method_out.value if (log and log.method_out) else None,
        )


class LiveEntry(BaseModel):
    """現在在室中のユーザー1件（GET /live 用）"""
    log_id: int
    user_id: int
    user_name: str
    user_role: str
    check_in_at: datetime
    method_in: str | None

    @classmethod
    def from_log_and_user(cls, log, user) -> "LiveEntry":
        return cls(
            log_id=log.id,
            user_id=user.id,
            user_name=user.name,
            user_role=user.role.value,
            check_in_at=log.check_in_at,
            method_in=log.method_in.value if log.method_in else None,
        )


# ════════════════════════════════════════════════════════════
#  トグルレスポンス
# ════════════════════════════════════════════════════════════

class ToggleResponse(BaseModel):
    """
    POST /attendance/toggle のレスポンス。

    result:
      "check_in"  … 入室記録した
      "check_out" … 退室記録した
    """
    result: Literal["check_in", "check_out"]
    user_id: int
    user_name: str
    timestamp: datetime
    message: str               # 画面表示用の日本語メッセージ
    log: AttendanceOut         # 更新後のログ全体（フロントで状態同期に使う）


# ════════════════════════════════════════════════════════════
#  統計サマリースキーマ
# ════════════════════════════════════════════════════════════

class StatsResponse(BaseModel):
    """
    GET /attendance/stats のレスポンス。
    ダッシュボードのヘッダーカードに使う。
    """
    date: date
    total_active: int    # 在籍ユーザー総数
    present: int         # 現在在室中
    checked_out: int     # 退室済み
    absent: int          # 未出席（今日ログなし）
    polled_at: datetime  # サーバー応答時刻（ポーリング間隔の基準に使える）
