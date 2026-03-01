"""
監査・不正検知サービス（Phase 7）

責務:
  1. スキャン証跡の記録（record_scan_event）
  2. 不正検知の実行（run_fraud_checks）
  3. アラートの発火（_fire_alert）
  4. 監査ログの照会（get_scan_events / get_alerts）
  5. アラートの解決（resolve_alert）
  6. クライアント IP の抽出（extract_client_ip）

不正検知ロジック:
  ┌─────────────────────────────────────────────────────────────────┐
  │ check_qr_abuse()        … 1トークンのスキャン数 > 閾値          │
  │   → AlertType.qr_abuse / severity=warning                      │
  │                                                                 │
  │ check_ip_burst()        … 同一IPが短時間に連続スキャン          │
  │   → AlertType.ip_burst  / severity=warning                     │
  │   ※ 学内タブレットの正規スキャンと区別するため閾値は高め        │
  │                                                                 │
  │ check_device_mismatch() … 同一ユーザーが短時間に別端末でスキャン│
  │   → AlertType.device_mismatch / severity=critical              │
  │   ※ ユーザーが 2 台同時に使うのは物理的に困難 → 強い異常シグナル│
  └─────────────────────────────────────────────────────────────────┘

検知の設計思想:
  - 検知失敗でも出席記録は止めない（False Negative を許容して False Positive を避ける）
  - アラートは INSERT するだけ（ロック・ブロックしない）
  - 管理者が後から確認して判断する「揉めた時の証拠」として機能させる
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.audit import (
    AlertLog, AlertSeverityEnum, AlertTypeEnum,
    ScanEvent, ScanResultEnum,
)

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════
#  IP アドレス抽出
# ════════════════════════════════════════════════════════════

def extract_client_ip(request: Request) -> str:
    """
    リクエストからクライアント IP を取得する。

    優先順位:
      1. X-Forwarded-For ヘッダーの先頭（リバースプロキシ経由）
      2. X-Real-IP ヘッダー（nginx等）
      3. request.client.host（直接接続）
    """
    # X-Forwarded-For: client, proxy1, proxy2
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()

    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()

    if request.client:
        return request.client.host

    return "unknown"


def extract_user_agent(request: Request) -> str | None:
    """User-Agent を取得（最大 512 文字）"""
    ua = request.headers.get("user-agent")
    return ua[:512] if ua else None


# ════════════════════════════════════════════════════════════
#  スキャン証跡の記録
# ════════════════════════════════════════════════════════════

def record_scan_event(
    db: Session,
    *,
    user_id: int | None,
    ip_address: str,
    device_id: str | None,
    user_agent: str | None,
    result: ScanResultEnum,
    result_detail: str | None = None,
    action: str | None = None,        # "check_in" | "check_out"
    qr_token_hash: str | None = None, # QR スキャン時のみ
) -> ScanEvent:
    """
    スキャン証跡を scan_events テーブルに 1 行追加する。

    成功・失敗を問わず全スキャンを記録する。
    ルーターから呼ばれ、DB commit はこの関数内で行う。
    """
    event = ScanEvent(
        user_id=user_id,
        qr_token_hash=qr_token_hash,
        ip_address=ip_address,
        device_id=device_id,
        user_agent=user_agent,
        result=result,
        result_detail=result_detail,
        action=action,
        scanned_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.debug(f"[audit] scan_event id={event.id} user={user_id} result={result.value} ip={ip_address}")
    return event


# ════════════════════════════════════════════════════════════
#  attendance_logs への証跡カラム書き込み
# ════════════════════════════════════════════════════════════

def attach_forensics_to_log(
    log,               # AttendanceLog インスタンス
    action: str,       # "check_in" | "check_out"
    ip_address: str,
    device_id: str | None,
) -> None:
    """
    AttendanceLog の ip_in/device_in または ip_out/device_out を書き込む。
    commit は呼び出し元が行う。
    """
    if action == "check_in":
        log.ip_in     = ip_address
        log.device_in = device_id
    else:
        log.ip_out     = ip_address
        log.device_out = device_id


# ════════════════════════════════════════════════════════════
#  不正検知エンジン
# ════════════════════════════════════════════════════════════

def run_fraud_checks(
    db: Session,
    *,
    scan_event: ScanEvent,
    user_id: int | None,
    qr_token_hash: str | None,
    ip_address: str,
    device_id: str | None,
) -> list[AlertLog]:
    """
    全不正検知ルールを実行し、発火したアラートのリストを返す。

    設計:
      - 例外は握りつぶす（検知失敗で出席記録を止めない）
      - アラートが既に直近 5 分以内に同一条件で発火済みなら重複抑制
    """
    alerts: list[AlertLog] = []

    checks = [
        lambda: _check_qr_abuse(db, scan_event, qr_token_hash),
        lambda: _check_ip_burst(db, scan_event, ip_address),
        lambda: _check_device_mismatch(db, scan_event, user_id, device_id),
    ]

    for check in checks:
        try:
            alert = check()
            if alert:
                alerts.append(alert)
        except Exception as e:
            logger.error(f"[fraud_check] 検知エラー（無視して継続）: {e}")

    return alerts


# ─── 個別検知ロジック ────────────────────────────────────────────────────────

def _check_qr_abuse(
    db: Session,
    scan_event: ScanEvent,
    qr_token_hash: str | None,
) -> AlertLog | None:
    """
    1 つの QR トークンで短時間に大量スキャンが起きていないか検知する。

    閾値: settings.QR_ABUSE_SCAN_LIMIT（デフォルト 50）
    ウィンドウ: settings.QR_TOKEN_EXPIRE_SECONDS * (settings.QR_GRACE_WINDOWS + 1)
               ≒ 2 分間（GRACEウィンドウ込み）

    アルゴリズム:
      同じ token_hash のスキャン数を直近 N 分でカウントし、
      閾値を超えたらアラートを発火する。
    """
    if not qr_token_hash:
        return None

    window_secs = settings.QR_TOKEN_EXPIRE_SECONDS * (settings.QR_GRACE_WINDOWS + 1)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_secs)

    scan_count = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.qr_token_hash == qr_token_hash,
            ScanEvent.scanned_at >= cutoff,
        )
        .count()
    )

    limit = settings.QR_ABUSE_SCAN_LIMIT
    if scan_count <= limit:
        return None

    logger.warning(
        f"[fraud] QR abuse detected: token_hash={qr_token_hash[:8]}... "
        f"scans={scan_count} > limit={limit}"
    )
    return _fire_alert(
        db,
        alert_type=AlertTypeEnum.qr_abuse,
        severity=AlertSeverityEnum.warning,
        scan_event=scan_event,
        qr_token_hash=qr_token_hash,
        detail={
            "scan_count": scan_count,
            "limit": limit,
            "window_secs": window_secs,
        },
        dedup_window_mins=5,
    )


def _check_ip_burst(
    db: Session,
    scan_event: ScanEvent,
    ip_address: str,
) -> AlertLog | None:
    """
    同一 IP から短時間に大量スキャンが来ていないか検知する。

    閾値: settings.IP_BURST_LIMIT（デフォルト 10）
    ウィンドウ: settings.IP_BURST_WINDOW_SECS（デフォルト 60 秒）

    注意:
      学内タブレット（固定IP）は正規用途でも多くのスキャンを生成する。
      閾値は塾の規模に合わせて設定すること。
    """
    if not ip_address or ip_address == "unknown":
        return None

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.IP_BURST_WINDOW_SECS)

    scan_count = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.ip_address == ip_address,
            ScanEvent.scanned_at >= cutoff,
        )
        .count()
    )

    limit = settings.IP_BURST_LIMIT
    if scan_count <= limit:
        return None

    logger.warning(
        f"[fraud] IP burst detected: ip={ip_address} "
        f"scans={scan_count} > limit={limit} in {settings.IP_BURST_WINDOW_SECS}s"
    )
    return _fire_alert(
        db,
        alert_type=AlertTypeEnum.ip_burst,
        severity=AlertSeverityEnum.warning,
        scan_event=scan_event,
        ip_address=ip_address,
        detail={
            "scan_count": scan_count,
            "limit": limit,
            "window_secs": settings.IP_BURST_WINDOW_SECS,
            "ip_address": ip_address,
        },
        dedup_window_mins=2,
    )


def _check_device_mismatch(
    db: Session,
    scan_event: ScanEvent,
    user_id: int | None,
    device_id: str | None,
) -> AlertLog | None:
    """
    同一ユーザーが短時間に異なる端末からスキャンしていないか検知する。

    閾値: settings.DEVICE_MISMATCH_WINDOW_MINS（デフォルト 5 分）

    ロジック:
      ユーザーの直近スキャンに使われた device_id と今回が異なれば警告。
      device_id が null の場合は比較しない（旧クライアント互換）。

    なぜ重要か:
      「自分のQRコードを友達に送って代わりにスキャンさせる」行為を検知できる。
      同一人物が 2 台持ちの場合もあるため severity=critical にして
      管理者が個別判断する。
    """
    if not user_id or not device_id:
        return None

    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=settings.DEVICE_MISMATCH_WINDOW_MINS
    )

    # 同じユーザーの直近スキャンで device_id が記録されているもの
    recent = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.user_id == user_id,
            ScanEvent.device_id.isnot(None),
            ScanEvent.scanned_at >= cutoff,
            ScanEvent.id != scan_event.id,  # 今回のスキャン自身は除外
        )
        .order_by(ScanEvent.scanned_at.desc())
        .first()
    )

    if recent is None:
        return None  # 直近スキャンなし → 比較不可

    if recent.device_id == device_id:
        return None  # 同じ端末 → 正常

    # 異なる端末を検知
    logger.warning(
        f"[fraud] Device mismatch: user_id={user_id} "
        f"prev_device={recent.device_id} curr_device={device_id}"
    )
    return _fire_alert(
        db,
        alert_type=AlertTypeEnum.device_mismatch,
        severity=AlertSeverityEnum.critical,
        scan_event=scan_event,
        user_id=user_id,
        detail={
            "user_id": user_id,
            "prev_device_id": recent.device_id,
            "curr_device_id": device_id,
            "prev_scan_at": recent.scanned_at.isoformat(),
            "window_mins": settings.DEVICE_MISMATCH_WINDOW_MINS,
        },
        dedup_window_mins=settings.DEVICE_MISMATCH_WINDOW_MINS,
    )


# ── アラート発火（重複抑制付き） ────────────────────────────────────────────

def _fire_alert(
    db: Session,
    *,
    alert_type: AlertTypeEnum,
    severity: AlertSeverityEnum,
    scan_event: ScanEvent,
    user_id: int | None = None,
    qr_token_hash: str | None = None,
    ip_address: str | None = None,
    detail: dict | None = None,
    dedup_window_mins: int = 5,
) -> AlertLog | None:
    """
    アラートを alert_logs に記録する。

    dedup_window_mins 以内に同一条件のアラートが既に存在する場合は
    重複として発火しない（アラート洪水防止）。
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=dedup_window_mins)

    # 重複チェック
    q = db.query(AlertLog).filter(
        AlertLog.alert_type == alert_type,
        AlertLog.created_at >= cutoff,
    )
    if user_id:       q = q.filter(AlertLog.user_id == user_id)
    if qr_token_hash: q = q.filter(AlertLog.qr_token_hash == qr_token_hash)
    if ip_address:    q = q.filter(AlertLog.ip_address == ip_address)

    if q.first():
        logger.debug(f"[fraud] アラート重複スキップ: type={alert_type.value}")
        return None

    alert = AlertLog(
        alert_type=alert_type,
        severity=severity,
        user_id=user_id,
        qr_token_hash=qr_token_hash,
        ip_address=ip_address,
        detail=json.dumps(detail or {}, ensure_ascii=False),
        trigger_scan_event_id=scan_event.id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    logger.warning(
        f"[ALERT] type={alert_type.value} severity={severity.value} "
        f"user={user_id} ip={ip_address} id={alert.id}"
    )
    return alert


# ════════════════════════════════════════════════════════════
#  監査照会（管理者用）
# ════════════════════════════════════════════════════════════

def get_scan_events(
    db: Session,
    *,
    user_id: int | None = None,
    ip_address: str | None = None,
    result: ScanResultEnum | None = None,
    from_dt: datetime | None = None,
    to_dt: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[ScanEvent], int]:
    """
    スキャン証跡の一覧取得（全フィルタ任意）。
    Returns (items, total_count)
    """
    q = db.query(ScanEvent)
    if user_id:    q = q.filter(ScanEvent.user_id == user_id)
    if ip_address: q = q.filter(ScanEvent.ip_address == ip_address)
    if result:     q = q.filter(ScanEvent.result == result)
    if from_dt:    q = q.filter(ScanEvent.scanned_at >= from_dt)
    if to_dt:      q = q.filter(ScanEvent.scanned_at <= to_dt)

    total = q.count()
    items = q.order_by(ScanEvent.scanned_at.desc()).offset(offset).limit(limit).all()
    return items, total


def get_alerts(
    db: Session,
    *,
    resolved: bool | None = None,
    severity: AlertSeverityEnum | None = None,
    alert_type: AlertTypeEnum | None = None,
    from_dt: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AlertLog], int]:
    """アラート一覧取得（全フィルタ任意）"""
    q = db.query(AlertLog)
    if resolved is not None: q = q.filter(AlertLog.resolved == resolved)
    if severity:             q = q.filter(AlertLog.severity == severity)
    if alert_type:           q = q.filter(AlertLog.alert_type == alert_type)
    if from_dt:              q = q.filter(AlertLog.created_at >= from_dt)

    total = q.count()
    items = q.order_by(AlertLog.created_at.desc()).offset(offset).limit(limit).all()
    return items, total


def resolve_alert(
    db: Session,
    alert_id: int,
    resolver_id: int,
    note: str | None = None,
) -> AlertLog | None:
    """アラートを解決済みにする"""
    alert = db.query(AlertLog).filter(AlertLog.id == alert_id).first()
    if alert is None:
        return None
    alert.resolved    = True
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by = resolver_id
    if note:
        alert.note = note
    db.commit()
    db.refresh(alert)
    return alert


# ════════════════════════════════════════════════════════════
#  サマリー統計（監査ダッシュボード用）
# ════════════════════════════════════════════════════════════

def get_audit_summary(db: Session) -> dict:
    """
    監査サマリー統計を返す。
    - 今日のスキャン数・成功率
    - 未解決アラート数（重要度別）
    """
    from datetime import date
    today_start = datetime.combine(date.today(), datetime.min.time()).replace(tzinfo=timezone.utc)

    total_scans_today = (
        db.query(ScanEvent)
        .filter(ScanEvent.scanned_at >= today_start)
        .count()
    )
    success_scans_today = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.scanned_at >= today_start,
            ScanEvent.result == ScanResultEnum.success,
        )
        .count()
    )
    unresolved_warnings  = (
        db.query(AlertLog)
        .filter(AlertLog.resolved == False, AlertLog.severity == AlertSeverityEnum.warning)
        .count()
    )
    unresolved_criticals = (
        db.query(AlertLog)
        .filter(AlertLog.resolved == False, AlertLog.severity == AlertSeverityEnum.critical)
        .count()
    )

    return {
        "today_total_scans":    total_scans_today,
        "today_success_scans":  success_scans_today,
        "today_failed_scans":   total_scans_today - success_scans_today,
        "success_rate_pct": (
            round(success_scans_today / total_scans_today * 100, 1)
            if total_scans_today > 0 else 100.0
        ),
        "unresolved_warnings":  unresolved_warnings,
        "unresolved_criticals": unresolved_criticals,
        "polled_at": datetime.now(timezone.utc).isoformat(),
    }
