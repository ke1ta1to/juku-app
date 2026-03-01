"""
WebSocket ルーター

エンドポイント:
  ws:// /ws/live   … 教師向けリアルタイム出席更新ストリーム

接続フロー:
  1. クライアントが ws://host/ws/live?token=<JWT> で接続
  2. サーバーが JWT を検証し、教師ロールを確認
  3. "connected" イベントを送信
  4. 入退室が起きるたびにサーバー側から push
  5. 30秒ごとに "ping" を送って接続を維持

クライアント側の実装指針:
  - 接続失敗・切断時は 3 秒後に再接続
  - "ping" イベントは無視（keepalive のみ）
  - "check_in" / "check_out" イベントを受けたら
    live_count フィールドで即座に人数表示を更新
    （/live への再 GET は不要）
  - ページ非表示中は接続を維持しつつ再接続を throttle する

認証:
  - クエリパラメータ ?token=<JWT> または
    Authorization: Bearer <JWT> ヘッダー（どちらでも可）
  - 教師（role=teacher）のみ接続可能
  - inactive ユーザーは接続即切断
"""
import asyncio
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.core.events import manager
from app.core.security import decode_access_token
from app.db.session import SessionLocal
from app.models.user import User, RoleEnum, StatusEnum

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

# keepalive ping 間隔（秒）
_PING_INTERVAL = 30


async def _authenticate_ws(token: str | None) -> User | None:
    """
    WebSocket 用 JWT 認証。
    有効なトークンかつ教師ロールなら User を返す。失敗なら None。
    """
    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    sub = payload.get("sub")
    if sub is None:
        return None

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(sub)).first()
    finally:
        db.close()

    if user is None:
        return None
    if user.status == StatusEnum.inactive:
        return None
    if user.role != RoleEnum.teacher:
        return None

    return user


@router.websocket("/ws/live")
async def ws_live(
    ws: WebSocket,
    token: str | None = Query(None, description="JWT アクセストークン"),
):
    """
    教師向けリアルタイム出席更新 WebSocket。

    接続方法（JS）:
    ```js
    const ws = new WebSocket(
      `wss://your-host/ws/live?token=${localStorage.getItem('access_token')}`
    );
    ws.onmessage = (e) => {
      const event = JSON.parse(e.data);
      if (event.event === 'check_in' || event.event === 'check_out') {
        updateDashboard(event);
      }
    };
    ```

    受信するイベント例:
    ```json
    {
      "event":     "check_in",
      "user_id":   42,
      "user_name": "田中 太郎",
      "user_role": "student",
      "timestamp": "2025-01-01T09:00:00+00:00",
      "live_count": 12,
      "method":    "qr"
    }
    ```
    """
    # ── 認証チェック ──────────────────────────────────────────────────────────
    user = await _authenticate_ws(token)
    if user is None:
        # 認証失敗: 接続は拒否する（accept せずに close）
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        logger.warning("[WS] 認証失敗（トークン無効 or 非教師）")
        return

    logger.info(f"[WS] 接続: user_id={user.id} name={user.name}")

    # ── 接続登録 ──────────────────────────────────────────────────────────────
    await manager.connect(ws)

    try:
        # ── メインループ: keepalive ping + クライアントメッセージ受信 ─────────
        while True:
            try:
                # ping_interval より少し短い時間でクライアントからのメッセージを待つ
                # タイムアウトしたら ping を送って継続
                msg = await asyncio.wait_for(ws.receive_text(), timeout=_PING_INTERVAL)
                # クライアントからのメッセージは基本的に無視（ping/pong のみ想定）
                logger.debug(f"[WS] クライアントから受信: {msg[:50]}")

            except asyncio.TimeoutError:
                # keepalive ping
                await manager.ping_all()

    except WebSocketDisconnect as e:
        logger.info(f"[WS] 切断: user_id={user.id} code={e.code}")
    except Exception as e:
        logger.error(f"[WS] 予期しないエラー: {e}")
    finally:
        await manager.disconnect(ws)
