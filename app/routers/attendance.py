"""
出席管理ルーター（Phase 6 完全版）

エンドポイント一覧:
  POST /attendance/toggle          … 手動入退室（自分）
  POST /attendance/scan            … QRスキャン入退室（自分）
  GET  /attendance/me              … 自分の全履歴
  GET  /attendance/today           … 今日の状況（全員 or 自分）
  GET  /attendance/live            … 現在在室中（教師専用・ETag対応）
  GET  /attendance/stats           … 今日のサマリー統計（ダッシュボード用）
  GET  /attendance/all             … 全履歴（管理者専用）
  GET  /attendance/user/{id}       … 特定ユーザー履歴（管理者専用）

リアルタイム更新:
  - ポーリング: GET /live を 4 秒ごとに取得（ETag で 304 を活用）
  - WebSocket:  ws:///ws/live で push 受信（接続中は即時更新）

Phase 6 の追加点:
  - BackgroundTasks: toggle/scan 後に WebSocket へ broadcast
  - ETag: /live のレスポンスに ETag ヘッダー付与（304 Not Modified 対応）
  - /stats: ダッシュボードヘッダー用の集計
"""
import hashlib
import json
from datetime import date, datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import require_login, require_teacher, require_permission
from app.core.events import manager, make_attendance_event
from app.db.session import get_db
from app.models.attendance import CheckMethodEnum
from app.models.user import User, RoleEnum
from app.schemas.attendance import (
    AttendanceOut,
    AttendanceWithUser,
    LiveEntry,
    StatsResponse,
    ToggleResponse,
)
from app.services import attendance_service
from app.services.audit_service import (
    attach_forensics_to_log,
    extract_client_ip,
    extract_user_agent,
    record_scan_event,
    run_fraud_checks,
)
from app.models.audit import ScanResultEnum
from app.services.user_service import get_user_or_404

router = APIRouter(prefix="/api/attendance", tags=["attendance"])


# ── 内部ユーティリティ ────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _etag_for(data: list) -> str:
    """リストの内容から ETag 文字列を生成（SHA-1 truncated）"""
    raw = json.dumps(
        [d.model_dump() if hasattr(d, "model_dump") else d for d in data],
        default=str,
        sort_keys=True,
    )
    return '"' + hashlib.sha1(raw.encode()).hexdigest()[:16] + '"'


async def _run_fraud_checks_bg(
    db: Session,
    scan_event,
    user_id: int | None,
    qr_token_hash: str | None,
    ip_address: str,
    device_id: str | None,
) -> None:
    """
    不正検知を BackgroundTask として実行する。
    例外はログに記録して握りつぶす（出席記録に影響させない）。
    """
    try:
        alerts = run_fraud_checks(
            db,
            scan_event=scan_event,
            user_id=user_id,
            qr_token_hash=qr_token_hash,
            ip_address=ip_address,
            device_id=device_id,
        )
        if alerts:
            import logging
            logging.getLogger(__name__).warning(
                f"[fraud] {len(alerts)} alerts fired for user={user_id} ip={ip_address}"
            )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"[fraud] BackgroundTask 例外: {e}")


async def _broadcast_event(
    db: Session,
    result,       # attendance_service.ToggleResult
    user: User,
    method: CheckMethodEnum,
) -> None:
    """
    WebSocket 全接続へ出席イベントを broadcast する。
    BackgroundTasks から呼ばれるため async 関数。
    """
    live_count = attendance_service.get_live_count(db)
    payload = make_attendance_event(
        event_type=result.result,
        user_id=user.id,
        user_name=user.name,
        user_role=user.role.value,
        timestamp=result.timestamp,
        live_count=live_count,
        method=method.value,
    )
    await manager.broadcast(payload)


# ════════════════════════════════════════════════════════════
#  POST /toggle  ──  手動入退室トグル
# ════════════════════════════════════════════════════════════

class ToggleRequest(BaseModel):
    device_id: str | None = None  # 端末識別子（任意）


@router.post("/toggle", response_model=ToggleResponse, summary="入退室トグル（手動）")
async def toggle_attendance(
    request: Request,
    background_tasks: BackgroundTasks,
    body: ToggleRequest = ToggleRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_login),
):
    """
    ボタン1つで入室 / 退室 を自動判断して記録する。

    **Phase 7**: スキャン証跡（IP・端末）を記録。不正検知を非同期実行。

    オプションボディ:
    - `device_id`: 端末識別子（省略可）
    """
    ip         = extract_client_ip(request)
    ua         = extract_user_agent(request)
    device_id  = body.device_id

    from fastapi import HTTPException
    try:
        result = attendance_service.toggle(db, current_user, method=CheckMethodEnum.manual)
    except HTTPException as exc:
        # 403（退会済み）・409（退室済み）も証跡に記録してから再 raise
        _result = (
            ScanResultEnum.inactive_user if exc.status_code == 403
            else ScanResultEnum.already_done
        )
        record_scan_event(
            db, user_id=current_user.id, ip_address=ip, device_id=device_id,
            user_agent=ua, result=_result, result_detail=str(exc.detail),
            qr_token_hash=None,
        )
        raise

    # 証跡: attendance_logs にIP・端末を書き込む
    attach_forensics_to_log(result.log, result.result, ip, device_id)
    db.commit()

    # scan_events に1行追加（成功）
    scan_ev = record_scan_event(
        db,
        user_id=current_user.id,
        ip_address=ip,
        device_id=device_id,
        user_agent=ua,
        result=ScanResultEnum.success,
        action=result.result,
        qr_token_hash=None,  # 手動トグルはQRなし
    )

    # BackgroundTasks: WebSocket broadcast + 不正検知
    background_tasks.add_task(
        _broadcast_event, db, result, current_user, CheckMethodEnum.manual
    )
    background_tasks.add_task(
        _run_fraud_checks_bg, db, scan_ev, current_user.id, None, ip, device_id
    )

    msg = (
        f"{current_user.name} さんが入室しました"
        if result.result == "check_in"
        else f"{current_user.name} さんが退室しました"
    )
    return ToggleResponse(
        result=result.result,
        user_id=current_user.id,
        user_name=current_user.name,
        timestamp=result.timestamp,
        message=msg,
        log=AttendanceOut.from_log(result.log),
    )


# ════════════════════════════════════════════════════════════
#  POST /scan  ──  塾共通QRスキャン入退室（Phase 5）
# ════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    qr_token: str
    device_id: str | None = None  # 端末識別子（任意）


@router.post("/scan", response_model=ToggleResponse, summary="QRスキャンで入退室記録")
async def scan_attendance(
    request: Request,
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_login),
):
    """
    塾共通QRをスキャンして入退室を記録する（Phase 5 方式）。

    **Phase 7**: QR検証失敗も含む全スキャンを scan_events に記録。
    不正検知（QR乱用・IP集中・デバイス偽装）を BackgroundTasks で実行。

    オプションボディ:
    - `device_id`: 端末識別子（省略可）
    """
    from fastapi import HTTPException
    from app.services import qr_service
    import hashlib

    ip        = extract_client_ip(request)
    ua        = extract_user_agent(request)
    device_id = body.device_id
    token_hash = hashlib.sha256(body.qr_token.encode()).hexdigest()

    # ── QR 検証 ─────────────────────────────────────────────────────────────
    verify_result = qr_service.verify_for_scan(db, body.qr_token)
    if not verify_result.ok:
        # 失敗も証跡に残す
        record_scan_event(
            db,
            user_id=current_user.id,
            ip_address=ip,
            device_id=device_id,
            user_agent=ua,
            result=ScanResultEnum.invalid_qr,
            result_detail=verify_result.reason,
            qr_token_hash=token_hash,
        )
        raise HTTPException(
            status_code=400,
            detail=f"QR コードが無効です: {verify_result.reason}",
        )

    # ── 入退室記録 ───────────────────────────────────────────────────────────
    try:
        result = attendance_service.toggle(db, current_user, method=CheckMethodEnum.qr)
    except HTTPException as exc:
        # 403（退会済み）・409（退室済み）も証跡に記録してから再 raise
        _result = (
            ScanResultEnum.inactive_user if exc.status_code == 403
            else ScanResultEnum.already_done
        )
        record_scan_event(
            db, user_id=current_user.id, ip_address=ip, device_id=device_id,
            user_agent=ua, result=_result, result_detail=str(exc.detail),
            qr_token_hash=token_hash,
        )
        raise

    # 証跡: attendance_logs にIP・端末を書き込む
    attach_forensics_to_log(result.log, result.result, ip, device_id)
    db.commit()

    # scan_events に1行追加（成功）
    scan_ev = record_scan_event(
        db,
        user_id=current_user.id,
        ip_address=ip,
        device_id=device_id,
        user_agent=ua,
        result=ScanResultEnum.success,
        action=result.result,
        qr_token_hash=token_hash,
    )

    # BackgroundTasks: WebSocket broadcast + 不正検知
    background_tasks.add_task(
        _broadcast_event, db, result, current_user, CheckMethodEnum.qr
    )
    background_tasks.add_task(
        _run_fraud_checks_bg, db, scan_ev, current_user.id, token_hash, ip, device_id
    )

    msg = (
        f"{current_user.name} さんが入室しました"
        if result.result == "check_in"
        else f"{current_user.name} さんが退室しました"
    )
    return ToggleResponse(
        result=result.result,
        user_id=current_user.id,
        user_name=current_user.name,
        timestamp=result.timestamp,
        message=msg,
        log=AttendanceOut.from_log(result.log),
    )


# ════════════════════════════════════════════════════════════
#  GET /me  ──  自分の全履歴
# ════════════════════════════════════════════════════════════

@router.get("/me", response_model=list[AttendanceOut], summary="自分の出席履歴")
def my_attendance(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_login),
):
    """自分の入退室履歴を全日付・新しい順で返す"""
    logs = attendance_service.get_my_history(db, current_user.id)
    return [AttendanceOut.from_log(l) for l in logs]


# ════════════════════════════════════════════════════════════
#  GET /today  ──  今日の状況（ポーリング用）
# ════════════════════════════════════════════════════════════

@router.get("/today", response_model=list[AttendanceWithUser], summary="今日の出席状況")
def today_attendance(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_login),
):
    """
    今日の出席状況を返す。

    - **教師**: 在籍全員（欠席者も含む）
    - **生徒**: 自分のみ

    `attendance_status` フィールド: absent / checked_in / checked_out
    """
    if current_user.role == RoleEnum.teacher:
        rows = attendance_service.get_today_all(db)
    else:
        row = attendance_service.get_today_for_user(db, current_user)
        rows = [row]

    return [
        AttendanceWithUser.from_log_and_user(row.log, row.user)
        for row in rows
    ]


# ════════════════════════════════════════════════════════════
#  GET /live  ──  現在在室中（ETag 対応ポーリング用）
# ════════════════════════════════════════════════════════════

@router.get("/live", response_model=list[LiveEntry], summary="現在在室中の一覧（ETag対応）")
def live_attendance(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    """
    現在在室中のユーザー一覧（教師専用）。

    **ETag 対応**:
    - レスポンスに `ETag` ヘッダーを付与
    - クライアントが `If-None-Match: "<etag>"` ヘッダーを送ると
      データが変わっていない場合に `304 Not Modified` を返す
    - これによりポーリングの帯域を大幅削減できる

    **推奨ポーリング実装**:
    ```js
    let etag = null;
    async function pollLive() {
      const headers = etag ? {'If-None-Match': etag} : {};
      const res = await fetch('/api/attendance/live', {headers});
      if (res.status === 200) {
        etag = res.headers.get('ETag');
        const data = await res.json();
        updateDisplay(data);
      }
      // 304 の場合は何もしない（データ変化なし）
    }
    setInterval(pollLive, 4000);
    ```
    """
    rows = attendance_service.get_live(db)
    entries = [LiveEntry.from_log_and_user(row.log, row.user) for row in rows]

    # ETag を計算
    etag = _etag_for(entries)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"  # ETag 検証を強制

    # If-None-Match チェック（データ変化なし → 304）
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match == etag:
        return Response(status_code=304)

    return entries


# ════════════════════════════════════════════════════════════
#  GET /stats  ──  今日のサマリー統計
# ════════════════════════════════════════════════════════════

@router.get("/stats", response_model=StatsResponse, summary="今日の出席サマリー")
def attendance_stats(
    db: Session = Depends(get_db),
    _: User = Depends(require_teacher),
):
    """
    ダッシュボードのヘッダーカード用サマリー。

    レスポンス例:
    ```json
    {
      "date": "2025-01-01",
      "total_active": 30,
      "present": 12,
      "checked_out": 5,
      "absent": 13,
      "polled_at": "2025-01-01T09:30:00+00:00"
    }
    ```

    ポーリング間隔: 10〜30秒程度でよい（/live より変化が少ない）
    """
    stats = attendance_service.get_day_stats(db)
    return StatsResponse(
        date=date.today(),
        total_active=stats.total_active,
        present=stats.present,
        checked_out=stats.checked_out,
        absent=stats.absent,
        polled_at=_now(),
    )


# ════════════════════════════════════════════════════════════
#  GET /all / GET /user/{id}  ──  管理者専用全履歴
# ════════════════════════════════════════════════════════════

@router.get("/all", response_model=list[AttendanceOut], summary="全ユーザーの全履歴")
def all_attendance(
    from_date: date | None = Query(None, description="開始日 YYYY-MM-DD"),
    to_date: date | None = Query(None, description="終了日 YYYY-MM-DD"),
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("view_all_logs")),
):
    """全ユーザーの入退室履歴（管理者専用・期間フィルタ対応）"""
    logs = attendance_service.get_all_history(db, from_date=from_date, to_date=to_date)
    return [AttendanceOut.from_log(l) for l in logs]


@router.get("/user/{user_id}", response_model=list[AttendanceOut], summary="特定ユーザーの履歴")
def user_attendance(
    user_id: int,
    from_date: date | None = Query(None, description="開始日 YYYY-MM-DD"),
    to_date: date | None = Query(None, description="終了日 YYYY-MM-DD"),
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("view_all_logs")),
):
    """特定ユーザーの入退室履歴（管理者専用）"""
    get_user_or_404(db, user_id)
    logs = attendance_service.get_all_history(
        db, user_id=user_id, from_date=from_date, to_date=to_date
    )
    return [AttendanceOut.from_log(l) for l in logs]
