"""
QR コードルーター（Phase 5 完全版）

─── 塾共通QR（Phase 5 推奨） ─────────────────────────────────────────────────
  [入口タブレット]                         [学生スマホ]
    ↓ 1分ごとに自動リロード                  ↓ ログイン済み
  GET /qr/current/image                   ┐
  GET /qr/current          ←── 表示 ───   │
                                          ├→ POST /attendance/scan {qr_token}
                                          │    ① QR署名検証
                                          │    ② JWT で学生特定
                                          │    ③ toggle() 入退室記録

  セキュリティ:
    - QRに個人情報なし → 画面盗撮されても無効
    - JWT必須 → 本人のスマホ以外では使えない
    - HMAC署名 → 改ざん不可
    - ウィンドウ制限 → 古いQRは無効（最大 ~2分）

─── ユーザー個別QR（Phase 0〜4 後方互換） ─────────────────────────────────────
  GET /qr/token          … 自分のQRトークン取得（JSON）
  GET /qr/token/image    … 自分のQR画像取得（PNG）
  POST /qr/scan          … [旧] タブレットがユーザーQRを読む方式
"""
import io

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import require_login
from app.core.security import generate_qr_token, verify_qr_token
from app.db.session import get_db
from app.models.attendance import CheckMethodEnum
from app.models.user import User
from app.schemas.attendance import ToggleResponse, AttendanceOut
from app.services import attendance_service, qr_service

router = APIRouter(prefix="/api/qr", tags=["qr"])


def _make_qr_png(token: str) -> bytes:
    """トークン文字列から QR コード PNG bytes を生成"""
    img = qrcode.make(token)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()

# ════════════════════════════════════════════════════════════
#  タブレット専用 QR 表示（ログイン不要・表示キー認証）
# ════════════════════════════════════════════════════════════

@router.get("/display-token", summary="タブレット表示用QRトークン（表示キー認証）")
def get_display_qr_token(
    key: str,
    db: Session = Depends(get_db),
):
    from app.core.config import settings as s
    if key != s.QR_DISPLAY_KEY:
        raise HTTPException(status_code=403, detail="表示キーが無効です")
    data = qr_service.generate_and_record(db)
    checkin_url = _make_checkin_url(data["token"])
    return {
        "checkin_url": checkin_url,
        "expires_at": data["expires_at"],
        "window": data["window"],
        "academy_id": data["academy_id"],
    }


@router.get("/display-token/image", summary="タブレット表示用QR画像（PNG）")
def get_display_qr_image(
    key: str,
    db: Session = Depends(get_db),
):
    from app.core.config import settings as s
    if key != s.QR_DISPLAY_KEY:
        raise HTTPException(status_code=403, detail="表示キーが無効です")
    data = qr_service.generate_and_record(db)
    checkin_url = _make_checkin_url(data["token"])
    png = _make_qr_png(checkin_url)
    return Response(
        content=png,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-Token-Expires-At": str(data["expires_at"]),
            "X-Academy-Id": data["academy_id"],
        },
    )


# ════════════════════════════════════════════════════════════
#  塾共通 QR（Phase 5 推奨）
# ════════════════════════════════════════════════════════════

@router.get("/current", summary="塾共通QRトークン取得（JSON）")
def get_current_qr(
    db: Session = Depends(get_db),
    _: User = Depends(require_login),  # タブレット担当者のログイン必須
):
    """
    現在の塾共通 QR トークンを JSON で返す（入口タブレット用）。

    - 1分ごとに新しいトークンが生成される
    - QR には個人情報を含まない
    - フロント側は `expires_at` を監視して自動リロードすること

    推奨実装（タブレット側 JS）:
    ```js
    async function refreshQR() {
      const data = await fetch('/api/qr/current').then(r => r.json());
      showQR(data.token);
      const msUntilExpiry = (data.expires_at * 1000) - Date.now() - 3000;
      setTimeout(refreshQR, Math.max(msUntilExpiry, 1000));
    }
    ```
    """
    data = qr_service.generate_and_record(db)
    return {
        "token":      data["token"],
        "expires_at": data["expires_at"],
        "window":     data["window"],
        "academy_id": data["academy_id"],
    }


@router.get("/current/image", summary="塾共通QR画像（PNG）")
def get_current_qr_image(
    db: Session = Depends(get_db),
    _: User = Depends(require_login),
):
    """
    現在の塾共通 QR コードを PNG 画像で返す（タブレット画面直接表示用）。

    Cache-Control: no-store で常に最新を返す。
    X-Token-Expires-At ヘッダーで有効期限を通知（フロントの自動リロードに使う）。
    """
    data = qr_service.generate_and_record(db)
    png = _make_qr_png(data["token"])
    return Response(
        content=png,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-Token-Expires-At": str(data["expires_at"]),
            "X-Academy-Id": data["academy_id"],
        },
    )


# ════════════════════════════════════════════════════════════
#  ユーザー個別 QR（Phase 0〜4 後方互換）
# ════════════════════════════════════════════════════════════

@router.get("/token", summary="[legacy] 自分のQRトークン", include_in_schema=False)
def get_my_qr_token(current_user: User = Depends(require_login)):
    """後方互換: ユーザー個別 QR トークン（Phase 5 では /qr/current を使うこと）"""
    return generate_qr_token(current_user.id)


@router.get("/token/image", summary="[legacy] 自分のQR画像", include_in_schema=False)
def get_my_qr_image(current_user: User = Depends(require_login)):
    """後方互換: ユーザー個別 QR PNG"""
    token_data = generate_qr_token(current_user.id)
    png = _make_qr_png(token_data["token"])
    return Response(
        content=png,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-Token-Expires-At": str(token_data["expires_at"]),
        },
    )


@router.post("/scan", response_model=ToggleResponse, summary="[legacy] ユーザーQRスキャン", include_in_schema=False)
def scan_user_qr(
    body: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_login),
):
    """
    後方互換: ユーザー個別QRをタブレットで読む旧方式。
    Phase 5 では POST /attendance/scan（塾共通QR方式）を使うこと。
    """
    token = body.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="token が必要です")

    user_id = verify_qr_token(token)
    if user_id is None:
        raise HTTPException(status_code=400, detail="QR コードが無効または期限切れです")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=403, detail="ユーザーが見つかりません")

    result = attendance_service.toggle(db, target, method=CheckMethodEnum.qr)
    msg = (
        f"{target.name} さんが入室しました（QR-legacy）"
        if result.result == "check_in"
        else f"{target.name} さんが退室しました（QR-legacy）"
    )
    return ToggleResponse(
        result=result.result,
        user_id=target.id,
        user_name=target.name,
        timestamp=result.timestamp,
        message=msg,
        log=AttendanceOut.from_log(result.log),
    )
