#!/usr/bin/env python
"""
手動シードスクリプト（alembic migrate 後に手動で叩く用）。

起動時の自動シードは app/main.py の lifespan が担うが、
CLI から直接実行したいときはこちらを使う。

使い方:
    python seed_admin.py
    INITIAL_ADMIN_EMAIL=admin@example.com python seed_admin.py

環境変数 INITIAL_ADMIN_EMAIL が未設定の場合は .env を参照する。
"""
import sys
import os
from pathlib import Path

# プロジェクトルートを path に追加
sys.path.insert(0, str(Path(__file__).parent))

from app.core.config import settings
from app.db.session import SessionLocal
from app.services.seed import run_seed

if not settings.INITIAL_ADMIN_EMAIL:
    print("ERROR: INITIAL_ADMIN_EMAIL が設定されていません。")
    print("  .env に INITIAL_ADMIN_EMAIL=... を追加するか、")
    print("  環境変数で渡してください。")
    sys.exit(1)

db = SessionLocal()
try:
    run_seed(
        db,
        email=settings.INITIAL_ADMIN_EMAIL,
        password=settings.INITIAL_ADMIN_PASSWORD,
        name=settings.INITIAL_ADMIN_NAME,
    )
    print(f"完了: {settings.INITIAL_ADMIN_EMAIL}")
finally:
    db.close()
