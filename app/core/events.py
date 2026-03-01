"""
WebSocket イベントバス

設計:
  - ConnectionManager … 教師用 WebSocket 接続を一元管理
  - broadcast()       … 全接続中クライアントへ同一メッセージを送信（fan-out）
  - イベント発火は attendance ルーターが BackgroundTasks 経由で行う
    （サービス層を async に依存させない分離設計）

メモリ上の接続リストのみ。
スケールアウト（複数 uvicorn worker）が必要になったら
Redis Pub/Sub に置き換える箇所はここだけ。

イベント JSON フォーマット:
  {
    "event":     "check_in" | "check_out" | "ping" | "connected",
    "user_id":   1,
    "user_name": "田中 太郎",
    "user_role": "student",
    "timestamp": "2025-01-01T09:00:00+00:00",
    "live_count": 12,      # 現在在室中の人数（受信側が再取得不要）
    "method":    "qr"      # "qr" | "manual"
  }
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    WebSocket 接続プール。

    - connect()   … 接続を登録し "connected" イベントを送る
    - disconnect() … 接続を削除
    - broadcast() … 全接続へ同じ JSON を送る（失敗接続は自動削除）
    - ping()      … keepalive（uvicorn のタイムアウト対策）
    """

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)
        logger.info(f"[WS] 接続 +1 → 計 {self.connection_count} 接続")

        # 接続直後に "connected" イベントを送る
        await ws.send_json({
            "event": "connected",
            "message": "リアルタイム更新に接続しました",
            "timestamp": _now_iso(),
        })

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            try:
                self._connections.remove(ws)
            except ValueError:
                pass
        logger.info(f"[WS] 切断 -1 → 計 {self.connection_count} 接続")

    async def broadcast(self, payload: dict) -> None:
        """
        全接続中クライアントへ payload を JSON 送信する。
        送信に失敗した接続は自動的に切断扱いにする。
        """
        if not self._connections:
            return

        data = json.dumps(payload, ensure_ascii=False, default=str)
        dead: list[WebSocket] = []

        async with self._lock:
            targets = list(self._connections)

        for ws in targets:
            try:
                await ws.send_text(data)
            except Exception as e:
                logger.warning(f"[WS] 送信失敗（接続を削除）: {e}")
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    try:
                        self._connections.remove(ws)
                    except ValueError:
                        pass

    async def ping_all(self) -> None:
        """全接続へ keepalive ping を送る"""
        await self.broadcast({"event": "ping", "timestamp": _now_iso()})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── シングルトン（アプリ全体で1インスタンス）──────────────────────────────────
manager = ConnectionManager()


# ── イベント生成ヘルパー ──────────────────────────────────────────────────────

def make_attendance_event(
    event_type: str,    # "check_in" | "check_out"
    user_id: int,
    user_name: str,
    user_role: str,
    timestamp: datetime,
    live_count: int,
    method: str = "manual",
) -> dict:
    """
    出席イベントの標準フォーマットを生成する。
    attendance ルーターが toggle/scan 後に broadcast() へ渡す。
    """
    return {
        "event":     event_type,
        "user_id":   user_id,
        "user_name": user_name,
        "user_role": user_role,
        "timestamp": timestamp.isoformat(),
        "live_count": live_count,
        "method":    method,
    }
