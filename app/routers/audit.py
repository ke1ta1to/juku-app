"""
監査 API ルーター（Phase 7）

エンドポイント（すべて管理者専用）:
  GET  /audit/scan-events           … スキャン証跡一覧
  GET  /audit/scan-events/{id}      … 証跡1件詳細
  GET  /audit/alerts                … アラート一覧
  GET  /audit/alerts/{id}           … アラート1件詳細
  POST /audit/alerts/{id}/resolve   … アラートを解決済みにする
  GET  /audit/summary               … 今日の監査サマリー

アクセス制御:
  - require_permission("manage_users") … 管理者のみ
  - inactive ユーザーは JWT 認証時点で弾かれる
"""
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import require_permission
from app.db.session import get_db
from app.models.audit import AlertLog, AlertSeverityEnum, AlertTypeEnum, ScanEvent, ScanResultEnum
from app.models.user import User
from app.services import audit_service

router = APIRouter(prefix="/api/audit", tags=["audit"])

_require_admin = Depends(require_permission("manage_users"))


# ════════════════════════════════════════════════════════════
#  出力スキーマ
# ════════════════════════════════════════════════════════════

class ScanEventOut(BaseModel):
    id: int
    user_id: int | None
    qr_token_hash: str | None
    ip_address: str | None
    device_id: str | None
    user_agent: str | None
    result: str
    result_detail: str | None
    action: str | None
    scanned_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, ev: ScanEvent) -> "ScanEventOut":
        return cls(
            id=ev.id,
            user_id=ev.user_id,
            # token_hash は先頭8文字だけ返す（全文は不要・誤用防止）
            qr_token_hash=ev.qr_token_hash[:8] + "..." if ev.qr_token_hash else None,
            ip_address=ev.ip_address,
            device_id=ev.device_id,
            user_agent=ev.user_agent,
            result=ev.result.value if hasattr(ev.result, "value") else ev.result,
            result_detail=ev.result_detail,
            action=ev.action,
            scanned_at=ev.scanned_at,
        )


class AlertOut(BaseModel):
    id: int
    alert_type: str
    severity: str
    user_id: int | None
    qr_token_hash: str | None
    ip_address: str | None
    detail: str | None          # JSON 文字列
    trigger_scan_event_id: int | None
    resolved: bool
    resolved_at: datetime | None
    resolved_by: int | None
    note: str | None
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, a: AlertLog) -> "AlertOut":
        return cls(
            id=a.id,
            alert_type=a.alert_type.value if hasattr(a.alert_type, "value") else a.alert_type,
            severity=a.severity.value if hasattr(a.severity, "value") else a.severity,
            user_id=a.user_id,
            qr_token_hash=a.qr_token_hash[:8] + "..." if a.qr_token_hash else None,
            ip_address=a.ip_address,
            detail=a.detail,
            trigger_scan_event_id=a.trigger_scan_event_id,
            resolved=a.resolved,
            resolved_at=a.resolved_at,
            resolved_by=a.resolved_by,
            note=a.note,
            created_at=a.created_at,
        )


class PaginatedScanEvents(BaseModel):
    total: int
    items: list[ScanEventOut]


class PaginatedAlerts(BaseModel):
    total: int
    items: list[AlertOut]


class ResolveRequest(BaseModel):
    note: str | None = None


# ════════════════════════════════════════════════════════════
#  GET /audit/scan-events
# ════════════════════════════════════════════════════════════

@router.get(
    "/scan-events",
    response_model=PaginatedScanEvents,
    summary="スキャン証跡一覧（管理者専用）",
)
def list_scan_events(
    user_id:    int | None = Query(None, description="ユーザーIDで絞り込み"),
    ip_address: str | None = Query(None, description="IPアドレスで絞り込み"),
    result:     ScanResultEnum | None = Query(None, description="スキャン結果で絞り込み"),
    from_dt:    datetime | None = Query(None, description="開始日時 ISO8601"),
    to_dt:      datetime | None = Query(None, description="終了日時 ISO8601"),
    limit:      int = Query(100, ge=1, le=500),
    offset:     int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: User = _require_admin,
):
    """
    スキャン証跡一覧を返す（新しい順）。

    クエリパラメータで絞り込み可能:
    - `user_id`: 特定ユーザーのスキャン履歴
    - `ip_address`: 特定 IP からのスキャン（不正調査に使う）
    - `result`: success / invalid_qr / expired_qr / inactive_user / already_done

    例: `?result=invalid_qr&from_dt=2025-01-01T00:00:00Z` → 無効QRスキャン一覧
    """
    items, total = audit_service.get_scan_events(
        db,
        user_id=user_id,
        ip_address=ip_address,
        result=result,
        from_dt=from_dt,
        to_dt=to_dt,
        limit=limit,
        offset=offset,
    )
    return PaginatedScanEvents(
        total=total,
        items=[ScanEventOut.from_model(e) for e in items],
    )


@router.get(
    "/scan-events/{event_id}",
    response_model=ScanEventOut,
    summary="スキャン証跡1件詳細",
)
def get_scan_event(
    event_id: int,
    db: Session = Depends(get_db),
    _: User = _require_admin,
):
    """スキャン証跡の1件詳細を返す"""
    from fastapi import HTTPException
    ev = db.query(ScanEvent).filter(ScanEvent.id == event_id).first()
    if not ev:
        raise HTTPException(404, "スキャンイベントが見つかりません")
    return ScanEventOut.from_model(ev)


# ════════════════════════════════════════════════════════════
#  GET /audit/alerts
# ════════════════════════════════════════════════════════════

@router.get(
    "/alerts",
    response_model=PaginatedAlerts,
    summary="アラート一覧（管理者専用）",
)
def list_alerts(
    resolved:   bool | None = Query(None, description="true=解決済み / false=未解決"),
    severity:   AlertSeverityEnum | None = Query(None),
    alert_type: AlertTypeEnum | None = Query(None),
    from_dt:    datetime | None = Query(None),
    limit:      int = Query(50, ge=1, le=200),
    offset:     int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: User = _require_admin,
):
    """
    不正検知アラート一覧を返す（新しい順）。

    よく使うフィルタ:
    - `?resolved=false` → 未解決アラートのみ（デイリーチェック用）
    - `?severity=critical` → 緊急アラートのみ
    - `?alert_type=device_mismatch` → デバイス偽装疑いのみ
    """
    items, total = audit_service.get_alerts(
        db,
        resolved=resolved,
        severity=severity,
        alert_type=alert_type,
        from_dt=from_dt,
        limit=limit,
        offset=offset,
    )
    return PaginatedAlerts(
        total=total,
        items=[AlertOut.from_model(a) for a in items],
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertOut,
    summary="アラート1件詳細",
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _: User = _require_admin,
):
    from fastapi import HTTPException
    a = db.query(AlertLog).filter(AlertLog.id == alert_id).first()
    if not a:
        raise HTTPException(404, "アラートが見つかりません")
    return AlertOut.from_model(a)


# ════════════════════════════════════════════════════════════
#  POST /audit/alerts/{id}/resolve
# ════════════════════════════════════════════════════════════

@router.post(
    "/alerts/{alert_id}/resolve",
    response_model=AlertOut,
    summary="アラートを解決済みにする",
)
def resolve_alert(
    alert_id: int,
    body: ResolveRequest,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_users")),
):
    """
    アラートを解決済みにマークする。

    `note` に解決の経緯（例: 「本人確認済・正常利用」）を記録できる。
    解決日時・誰が解決したかも自動記録される。
    """
    from fastapi import HTTPException
    alert = audit_service.resolve_alert(
        db, alert_id, resolver_id=operator.id, note=body.note
    )
    if not alert:
        raise HTTPException(404, "アラートが見つかりません")
    return AlertOut.from_model(alert)


# ════════════════════════════════════════════════════════════
#  GET /audit/summary
# ════════════════════════════════════════════════════════════

@router.get(
    "/summary",
    summary="監査サマリー（今日の統計）",
)
def audit_summary(
    db: Session = Depends(get_db),
    _: User = _require_admin,
):
    """
    今日のスキャン統計と未解決アラート数を返す。
    ダッシュボードのセキュリティセクションに使う。

    レスポンス例:
    ```json
    {
      "today_total_scans":   45,
      "today_success_scans": 43,
      "today_failed_scans":   2,
      "success_rate_pct":  95.6,
      "unresolved_warnings":  1,
      "unresolved_criticals": 0,
      "polled_at": "2025-01-01T09:30:00+00:00"
    }
    ```
    """
    return audit_service.get_audit_summary(db)
