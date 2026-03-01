import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from alembic import context

# プロジェクトルートを sys.path に追加（alembic コマンドをどこから叩いても動くよう）
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# alembic の config オブジェクト
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── DATABASE_URL を .env / 環境変数から上書き ─────────────────────────────
# alembic.ini の sqlalchemy.url より環境変数を優先する
from app.core.config import settings  # noqa: E402
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# ── 全モデルを登録（autogenerate に必要）────────────────────────────────────
from app.db.base import Base          # noqa: E402
import app.models                     # noqa: E402, F401  ← __init__.py で全モデルをインポート済み

target_metadata = Base.metadata


# ── マイグレーション実行 ────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    """DB 接続なしで SQL スクリプトを生成するモード"""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite では Enum を VARCHAR で扱うため比較を文字列に
        render_as_batch=True,  # SQLite の ALTER TABLE 対応
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """実際の DB に接続してマイグレーションを適用するモード"""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite の ALTER TABLE 対応
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
