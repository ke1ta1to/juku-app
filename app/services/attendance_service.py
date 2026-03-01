"""
出席管理ビジネスロジック

設計方針:
  - toggle() が「QR スキャン」と「手動ボタン」両方の共通エントリーポイント
  - Phase 5 で QR スキャンルーターがこの toggle() を呼ぶことで二重実装を防ぐ
  - 全関数は Session を受け取り、commit まで責任を持つ
  - 教師向け today_all() は「欠席ユーザー」も含む（誰が来ていないかを把握）

状態遷移（1日1行制）:
  [ログなし]   → toggle() → check_in_at をセット     → "check_in"
  [入室のみ]   → toggle() → check_out_at をセット    → "check_out"
  [入退室済]   → toggle() → 409 ConflictError        → フロントに警告
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import NamedTuple

from sqlalchemy.orm import Session
from sqlalchemy import and_
from fastapi import HTTPException, status

from app.models.attendance import AttendanceLog, CheckMethodEnum
from app.models.user import User, StatusEnum, RoleEnum


# ════════════════════════════════════════════════════════════
#  内部ユーティリティ
# ════════════════════════════════════════════════════════════

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _today() -> date:
    return date.today()


def _get_today_log(db: Session, user_id: int) -> AttendanceLog | None:
    """今日の出席ログを1件取得（存在しない場合は None）"""
    return (
        db.query(AttendanceLog)
        .filter(
            AttendanceLog.user_id == user_id,
            AttendanceLog.date == _today(),
        )
        .first()
    )


# ════════════════════════════════════════════════════════════
#  出席トグル（コアロジック）
# ════════════════════════════════════════════════════════════

class ToggleResult(NamedTuple):
    result: str          # "check_in" | "check_out"
    log: AttendanceLog
    timestamp: datetime


def toggle(
    db: Session,
    user: User,
    method: CheckMethodEnum = CheckMethodEnum.manual,
) -> ToggleResult:
    """
    入室 / 退室 を自動判断して記録する。

    QR スキャン（Phase 5）も手動ボタン（Phase 4）もこの関数を使う。
    method 引数で記録方法を区別（qr / manual）。

    ガード:
      - inactive ユーザーは 403
      - 本日すでに退室済みなら 409

    状態遷移:
      ログなし      → check_in_at をセット → "check_in"
      check_in のみ → check_out_at をセット → "check_out"
      両方済み      → 409 Conflict
    """
    # ── 在籍チェック ────────────────────────────────────────────────────────
    if user.status == StatusEnum.inactive:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="退会済みのユーザーは出席記録できません",
        )

    now = _now()
    log = _get_today_log(db, user.id)

    # ── 状態分岐 ─────────────────────────────────────────────────────────────
    if log is None:
        # ① 今日のログなし → 入室
        log = AttendanceLog(
            user_id=user.id,
            date=_today(),
            check_in_at=now,
            method_in=method,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return ToggleResult(result="check_in", log=log, timestamp=now)

    elif log.check_in_at is not None and log.check_out_at is None:
        # ② 入室済み・未退室 → 退室
        log.check_out_at = now
        log.method_out = method
        db.commit()
        db.refresh(log)
        return ToggleResult(result="check_out", log=log, timestamp=now)

    else:
        # ③ 入室・退室どちらも済み → 拒否
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{user.name} さんは本日すでに退室済みです。"
                " 記録の修正が必要な場合は管理者にお問い合わせください。"
            ),
        )


# ════════════════════════════════════════════════════════════
#  今日の一覧（教師用・全員ビュー）
# ════════════════════════════════════════════════════════════

class TodayRow(NamedTuple):
    """今日の出席状況1行（欠席者も含む）"""
    user: User
    log: AttendanceLog | None   # ログなし → 欠席


def get_today_all(db: Session) -> list[TodayRow]:
    """
    今日の在籍ユーザー全員の出席状況を返す（教師 / 管理者用）。

    - active なユーザー全員を取得（teachers + students）
    - 今日のログがあればセット、なければ log=None（欠席扱い）
    - ロール順・名前順でソートして返す

    欠席の把握にも使えるため、ログが存在しないユーザーも必ず含める。
    """
    today = _today()

    # active ユーザー全員
    users = (
        db.query(User)
        .filter(User.status == StatusEnum.active)
        .order_by(User.role, User.name)
        .all()
    )

    # 今日のログを一括取得（N+1 を避ける）
    user_ids = [u.id for u in users]
    logs = (
        db.query(AttendanceLog)
        .filter(
            AttendanceLog.user_id.in_(user_ids),
            AttendanceLog.date == today,
        )
        .all()
    )
    log_map: dict[int, AttendanceLog] = {l.user_id: l for l in logs}

    return [TodayRow(user=u, log=log_map.get(u.id)) for u in users]


def get_today_for_user(db: Session, user: User) -> TodayRow:
    """自分の今日の出席状況（生徒用）"""
    log = _get_today_log(db, user.id)
    return TodayRow(user=user, log=log)


# ════════════════════════════════════════════════════════════
#  現在在室中（live ビュー）
# ════════════════════════════════════════════════════════════

class LiveRow(NamedTuple):
    user: User
    log: AttendanceLog


def get_live(db: Session) -> list[LiveRow]:
    """
    現在在室中のユーザー一覧（教師 / 管理者用）。

    条件:
      - 今日のログがある
      - check_in_at は NOT NULL
      - check_out_at は NULL（まだ退室していない）

    チェックイン時刻の早い順に返す。
    """
    today = _today()

    logs = (
        db.query(AttendanceLog)
        .filter(
            AttendanceLog.date == today,
            AttendanceLog.check_in_at.isnot(None),
            AttendanceLog.check_out_at.is_(None),
        )
        .order_by(AttendanceLog.check_in_at)
        .all()
    )

    # ユーザーを一括取得（N+1 回避）
    user_ids = [l.user_id for l in logs]
    if not user_ids:
        return []

    users = (
        db.query(User)
        .filter(User.id.in_(user_ids))
        .all()
    )
    user_map: dict[int, User] = {u.id: u for u in users}

    return [
        LiveRow(user=user_map[l.user_id], log=l)
        for l in logs
        if l.user_id in user_map
    ]


# ════════════════════════════════════════════════════════════
#  自分の履歴（全期間）
# ════════════════════════════════════════════════════════════

def get_my_history(db: Session, user_id: int) -> list[AttendanceLog]:
    """自分の入退室履歴（全日付・新しい順）"""
    return (
        db.query(AttendanceLog)
        .filter(AttendanceLog.user_id == user_id)
        .order_by(AttendanceLog.date.desc())
        .all()
    )


# ════════════════════════════════════════════════════════════
#  全履歴（管理者用）
# ════════════════════════════════════════════════════════════

def get_all_history(
    db: Session,
    user_id: int | None = None,
    from_date: date | None = None,
    to_date: date | None = None,
) -> list[AttendanceLog]:
    """
    全ユーザーの入退室履歴（管理者用）。

    フィルタ（全て任意）:
      user_id   … 特定ユーザーに絞る
      from_date … 開始日（含む）
      to_date   … 終了日（含む）
    """
    q = db.query(AttendanceLog)

    if user_id is not None:
        q = q.filter(AttendanceLog.user_id == user_id)
    if from_date is not None:
        q = q.filter(AttendanceLog.date >= from_date)
    if to_date is not None:
        q = q.filter(AttendanceLog.date <= to_date)

    return q.order_by(AttendanceLog.date.desc(), AttendanceLog.user_id).all()


# ════════════════════════════════════════════════════════════
#  統計サマリー（ダッシュボードヘッダー用）
# ════════════════════════════════════════════════════════════

class DayStats(NamedTuple):
    """今日の出席サマリー"""
    total_active: int    # 在籍ユーザー総数
    present: int         # 現在在室中（check_in のみ）
    checked_out: int     # 退室済み（check_in + check_out 両方）
    absent: int          # 未出席（ログなし）


def get_day_stats(db: Session) -> DayStats:
    """
    今日の出席統計サマリーを一括取得する。
    /attendance/stats エンドポイントと WebSocket イベントの live_count に使う。
    N+1 を避けるため aggregate クエリで取得。
    """
    today = _today()

    total_active: int = (
        db.query(User)
        .filter(User.status == StatusEnum.active)
        .count()
    )

    # 今日のログを集計
    logs = (
        db.query(AttendanceLog)
        .filter(AttendanceLog.date == today)
        .all()
    )

    present = sum(
        1 for l in logs
        if l.check_in_at is not None and l.check_out_at is None
    )
    checked_out = sum(
        1 for l in logs
        if l.check_in_at is not None and l.check_out_at is not None
    )
    absent = total_active - present - checked_out

    return DayStats(
        total_active=total_active,
        present=present,
        checked_out=checked_out,
        absent=max(absent, 0),  # 退会済み混入などでマイナスを防ぐ
    )


def get_live_count(db: Session) -> int:
    """現在在室中の人数だけ返す（WebSocket イベント用の軽量クエリ）"""
    today = _today()
    return (
        db.query(AttendanceLog)
        .filter(
            AttendanceLog.date == today,
            AttendanceLog.check_in_at.isnot(None),
            AttendanceLog.check_out_at.is_(None),
        )
        .count()
    )
