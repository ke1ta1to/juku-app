"""
アプリケーションエントリーポイント（Phase 6 完全版）

起動時:
  1. Alembic マイグレーション自動適用
  2. INITIAL_ADMIN_EMAIL が設定されていれば初期管理者シード

静的ファイル:
  GET /               … ダッシュボード HTML
  GET /dashboard.html … 同上（直接アクセス用）
  staticfiles/        … 将来の CSS/JS 追加時に使う

エンドポイント一覧:
  POST /api/auth/login
  GET  /api/auth/me
  POST /api/auth/me/password
  GET  /api/users/
  POST /api/users/
  ...（Phase 2〜5 で実装済み）
  POST /api/attendance/toggle   … 手動入退室（Phase 4）
  POST /api/attendance/scan     … QRスキャン（Phase 5）
  GET  /api/attendance/live     … 在室中一覧・ETag 対応（Phase 6）
  GET  /api/attendance/stats    … 今日のサマリー（Phase 6）
  GET  /api/qr/current          … 塾共通QR（Phase 5）
  WS   /ws/live                 … リアルタイム push（Phase 6）
  GET  /health                  … 死活監視（WS接続数も返す）
"""
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── 静的ファイルの場所 ──────────────────────────────────────────────────────
_HERE = Path(__file__).parent.parent  # プロジェクトルート（manage.py と同列）
_STATIC_DIR = _HERE / "static"
_DASHBOARD = _HERE / "dashboard.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    _run_migrations()   # 항상 실행
    _run_seed()
    yield
    # シャットダウン時: 必要になったら DB pool close など追加


def _run_migrations() -> None:
    """
    Alembic マイグレーションを自動適用する。
    AUTO_MIGRATE=1 の場合は alembic upgrade head を実行。
    未設定の場合は create_all にフォールバック（ローカル開発用）。
    """
    import os
    from app.core.config import settings

    auto_migrate = os.environ.get("AUTO_MIGRATE", "0") == "1"

    if auto_migrate:
        try:
            from alembic.config import Config
            from alembic import command

            alembic_cfg = Config("alembic.ini")
            # 環境変数の DATABASE_URL を優先（alembic.ini の値を上書き）
            alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
            command.upgrade(alembic_cfg, "head")
            logger.info("[startup] Alembic マイグレーション完了")
        except Exception as e:
            logger.error(f"[startup] Alembic マイグレーション失敗: {e}")
            raise
    else:
        # ローカル開発用フォールバック（SQLite など）
        from app.db.base import Base
        from app.db.session import engine
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("[startup] DB create_all 完了（AUTO_MIGRATE 未設定）")
        except Exception as e:
            logger.error(f"[startup] DB create_all 失敗: {e}")
            raise

def _run_seed() -> None:
    if not settings.INITIAL_ADMIN_EMAIL:
        return
    from app.db.session import SessionLocal
    from app.services.seed import run_seed
    db = SessionLocal()
    try:
        run_seed(
            db,
            email=settings.INITIAL_ADMIN_EMAIL,
            password=settings.INITIAL_ADMIN_PASSWORD,
            name=settings.INITIAL_ADMIN_NAME,
        )
        logger.info("[startup] seed: 完了")
    except Exception as e:
        # 起動を止めない
        logger.error(f"[startup] seed 失敗（起動は継続）: {e}")
    finally:
        db.close()


# ── FastAPI アプリ ─────────────────────────────────────────────────────────
app = FastAPI(
    title="百燈塾 管理アプリ",
    description="出席・QR・監査ログ管理システム",
    version="1.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # 本番では特定オリジンに絞ること
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 静的ファイル配信 ──────────────────────────────────────────────────────
# static/ ディレクトリが存在する場合のみマウント（任意）
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
@app.get("/dashboard.html", include_in_schema=False)
def serve_dashboard():
    """先生向けダッシュボード HTML を配信する"""
    if _DASHBOARD.exists():
        return FileResponse(str(_DASHBOARD), media_type="text/html")
    return {"detail": "dashboard.html が見つかりません"}


# ── ルーター登録 ───────────────────────────────────────────────────────────
from app.routers import auth, users, attendance as att_router, qr, ws, audit  # noqa: E402

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(att_router.router)
app.include_router(qr.router)
app.include_router(ws.router)   # WS /ws/live
app.include_router(audit.router)  # Phase 7 監査API


# ── ヘルスチェック ─────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
def health():
    """死活監視。WS 接続数も含む。"""
    from app.core.events import manager as ws_manager
    return {
        "ok": True,
        "ws_connections": ws_manager.connection_count,
    }
