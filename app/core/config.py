from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # アプリ基本設定
    APP_NAME: str = "JukuApp"
    DEBUG: bool = True

    # アプリURL（QRコードにフルURLを埋め込むため必要）
    BASE_URL: str = "http://localhost:8000"

    # DB設定（開発=SQLite, 本番=PostgreSQL）
    DATABASE_URL: str = "sqlite:///./juku.db"

    # JWT設定
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_STRING"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8時間

    # ── QR設定 ────────────────────────────────────────────────────────────────
    QR_SECRET_KEY: str = "CHANGE_ME_QR_SECRET_IN_PRODUCTION"
    QR_TOKEN_EXPIRE_SECONDS: int = 60
    ACADEMY_ID: str = "juku01"
    QR_GRACE_WINDOWS: int = 1
    QR_DISPLAY_KEY: str = "changeme-display-key"

    # ── 不正検知設定 ──────────────────────────────────────────────────────────
    # 1トークン当たりの許容スキャン数（50人塾想定。超えたらアラート）
    QR_ABUSE_SCAN_LIMIT: int = 50

    # 同一 IP から N 秒以内に M 回スキャンでアラート
    IP_BURST_LIMIT: int = 10
    IP_BURST_WINDOW_SECS: int = 60

    # 同一ユーザーが異なる端末から N 分以内にスキャンでアラート
    DEVICE_MISMATCH_WINDOW_MINS: int = 5

    # ── その他 ────────────────────────────────────────────────────────────────
    POLLING_INTERVAL_SECONDS: int = 4

    # ── 初期管理者シード ─────────────────────────────────────────────────────
    INITIAL_ADMIN_EMAIL: str = ""
    INITIAL_ADMIN_PASSWORD: str = "changeme1234!"
    INITIAL_ADMIN_NAME: str = "管理者"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
