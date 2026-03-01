"""
QR トークンサービス

責務:
  - 塾共通QRトークンの生成・監査ログ記録
  - スキャン時の検証・使用カウント更新
  - 古い監査ログの定期クリーンアップ

フロー（塾共通QR）:
  [タブレット側]
    GET /qr/current
      → generate_and_record() でトークン生成 + qr_tokens に記録
      → PNG を返す（1分ごとにリロード）

  [学生スマホ側]
    POST /attendance/scan
      → verify_and_record_use() でトークン検証 + used_count 更新
      → attendance_service.toggle() で入退室記録
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.core.config import settings
from app.core.security import (
    generate_school_qr_token,
    verify_school_qr_token,
    QRVerifyError,
)
from app.models.qr_token import QRToken


# ════════════════════════════════════════════════════════════
#  トークン生成 + 監査ログ記録
# ════════════════════════════════════════════════════════════

def generate_and_record(db: Session) -> dict:
    """
    塾共通 QR トークンを生成し、qr_tokens テーブルに記録する。

    同じウィンドウ内で複数回呼ばれた場合（タブレットのリロード）は、
    新しいトークン（nonce が異なる）を生成し、追加で記録する。

    Returns:
        generate_school_qr_token() と同じ dict
        + "token_id": qr_tokens.id（デバッグ用）
    """
    token_data = generate_school_qr_token()
    token = token_data["token"]

    token_hash = QRToken.hash_token(token)
    expires_dt = datetime.fromtimestamp(token_data["expires_at"], tz=timezone.utc)

    record = QRToken(
        token_hash=token_hash,
        academy_id=settings.ACADEMY_ID,
        window=token_data["window"],
        expires_at=expires_dt,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {**token_data, "token_id": record.id}


# ════════════════════════════════════════════════════════════
#  スキャン時の検証 + 使用カウント更新
# ════════════════════════════════════════════════════════════

class ScanVerifyResult:
    """verify_for_scan の戻り値"""
    def __init__(self, ok: bool, reason: str = ""):
        self.ok = ok
        self.reason = reason


def verify_for_scan(db: Session, token: str) -> ScanVerifyResult:
    """
    スキャン時のQRトークン検証。

    手順:
      1. HMAC・ウィンドウ・academy_id を verify_school_qr_token() で検証
      2. qr_tokens テーブルの監査レコードを更新（used_count++, last_used_at）

    監査レコードが存在しない場合でも①が通れば受け入れる。
    （タブレットが DB に記録する前にスキャンされた場合などの極小ケース）

    Returns:
        ScanVerifyResult(ok=True)  → 有効
        ScanVerifyResult(ok=False, reason=...) → 無効
    """
    # ① HMAC・ウィンドウ・academy_id 検証
    try:
        verify_school_qr_token(token)
    except QRVerifyError as e:
        return ScanVerifyResult(ok=False, reason=str(e.reason))

    # ② 監査ログ更新（存在しなければ skip）
    token_hash = QRToken.hash_token(token)
    record = db.query(QRToken).filter(QRToken.token_hash == token_hash).first()
    if record:
        record.used_count += 1
        record.last_used_at = datetime.now(timezone.utc)
        db.commit()

    return ScanVerifyResult(ok=True)


# ════════════════════════════════════════════════════════════
#  古い監査ログのクリーンアップ
# ════════════════════════════════════════════════════════════

def cleanup_expired_tokens(db: Session, keep_hours: int = 24) -> int:
    """
    期限切れかつ keep_hours 時間以上経過した qr_tokens を削除する。

    推奨: 管理コマンドや定期バッチから呼ぶ。
    起動時に実行する場合は main.py の lifespan に追加する。

    Returns:
        削除した行数
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=keep_hours)
    result = (
        db.query(QRToken)
        .filter(QRToken.expires_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return result
