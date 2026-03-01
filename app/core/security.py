"""
セキュリティモジュール

機能:
  1. パスワード（bcrypt）
  2. JWT アクセストークン
  3. QR HMAC トークン（塾共通 / ユーザー個別の2種）

QR トークンの2モード:
  ┌─────────────────────────────────────────────────────────────────┐
  │ [塾共通QR - Phase 5 推奨]                                        │
  │  payload = "{academy_id}:{window}:{nonce}"                      │
  │  → 入口タブレットに表示、学生が自分のスマホでスキャン             │
  │  → QRに個人情報なし、JWT が「誰か」を特定                         │
  │                                                                 │
  │ [ユーザー個別QR - Phase 0〜4 後方互換]                            │
  │  payload = "{user_id}:{window}"                                 │
  │  → 学生QRをタブレットで読む旧方式                                │
  │  → legacy エンドポイントが使用                                   │
  └─────────────────────────────────────────────────────────────────┘
"""
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ════════════════════════════════════════════════════════════
#  パスワード
# ════════════════════════════════════════════════════════════

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ════════════════════════════════════════════════════════════
#  JWT
# ════════════════════════════════════════════════════════════

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


# ════════════════════════════════════════════════════════════
#  QR 共通ユーティリティ
# ════════════════════════════════════════════════════════════

def _current_window() -> int:
    """現在の時間ウィンドウ番号を返す（epoch // QR_TOKEN_EXPIRE_SECONDS）"""
    return int(time.time()) // settings.QR_TOKEN_EXPIRE_SECONDS


def _hmac_sign(payload: str) -> str:
    """HMAC-SHA256 で署名して hex 文字列を返す"""
    return hmac.new(
        settings.QR_SECRET_KEY.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()


def _valid_windows() -> tuple[int, ...]:
    """
    現在から過去 QR_GRACE_WINDOWS 分のウィンドウ番号セットを返す。
    デフォルト (GRACE=1): (current, current-1) → 最大約2分間有効
    """
    current = _current_window()
    return tuple(current - i for i in range(settings.QR_GRACE_WINDOWS + 1))


# ════════════════════════════════════════════════════════════
#  塾共通 QR トークン（Phase 5 推奨）
# ════════════════════════════════════════════════════════════
#
# トークン形式:
#   "{academy_id}:{window}:{nonce}.{hmac_hex}"
#
# academy_id … 塾ID（誤配信・クロス検証防止）
# window     … epoch // 60 （1分ごとに変わる）
# nonce      … secrets.token_hex(8) 16文字ランダム（同一ウィンドウ内の
#              複数トークン生成時に区別するが、replay防止は window で行う）
# hmac_hex   … HMAC-SHA256(secret, payload_str) の hex
#
# セキュリティ特性:
#   - QRに個人情報なし → 画面盗撮されても成立しない
#   - JWT ログイン必須 → 「誰か」はサーバー側で特定
#   - 署名検証 → 改ざん不可
#   - ウィンドウ制限 → 古いトークンは無効（最大 ~2 分）
#   - academy_id 検証 → 他塾のトークン流用不可

def generate_school_qr_token() -> dict:
    """
    塾共通 QR トークンを生成する。

    入口タブレットに表示する1枚のQRを生成する。
    複数の学生が同じQRをスキャンする運用に対応。

    Returns:
        {
          "token":      "<payload>.<hmac>",
          "expires_at": <unix_timestamp>,
          "window":     <window_number>,
          "academy_id": "<academy_id>"
        }
    """
    window = _current_window()
    nonce = secrets.token_hex(8)  # 16文字ランダム
    payload = f"{settings.ACADEMY_ID}:{window}:{nonce}"
    sig = _hmac_sign(payload)
    token = f"{payload}.{sig}"
    expires_at = (window + 1) * settings.QR_TOKEN_EXPIRE_SECONDS

    return {
        "token": token,
        "expires_at": expires_at,
        "window": window,
        "academy_id": settings.ACADEMY_ID,
    }


class QRVerifyError(Exception):
    """QR トークン検証失敗の詳細情報を持つ例外"""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def verify_school_qr_token(token: str) -> bool:
    """
    塾共通 QR トークンを検証する。

    検証手順:
      1. フォーマット検証（payload.sig の形式）
      2. ペイロード分解（academy_id:window:nonce）
      3. academy_id 一致確認
      4. タイムウィンドウ検証（現在 or 直前のみ）
      5. HMAC 署名検証（タイミング攻撃対策で compare_digest 使用）

    Returns:
        True: 有効
    Raises:
        QRVerifyError: 無効（reason に詳細）
    """
    try:
        # ① フォーマット: "<payload>.<hmac_hex>"
        if "." not in token:
            raise QRVerifyError("フォーマット不正（'.' がありません）")
        payload_str, sig = token.rsplit(".", 1)

        # ② ペイロード分解: "academy_id:window:nonce"
        parts = payload_str.split(":")
        if len(parts) != 3:
            raise QRVerifyError("ペイロードの形式が不正です")
        academy_id, window_str, nonce = parts

        # ③ academy_id 検証
        if academy_id != settings.ACADEMY_ID:
            raise QRVerifyError(f"academy_id 不一致: '{academy_id}'")

        # ④ タイムウィンドウ検証
        window = int(window_str)
        if window not in _valid_windows():
            raise QRVerifyError(
                f"期限切れ QR（window={window}, "
                f"valid={_valid_windows()}）"
            )

        # ⑤ HMAC 署名検証（タイミング攻撃対策）
        expected_sig = _hmac_sign(payload_str)
        if not hmac.compare_digest(sig, expected_sig):
            raise QRVerifyError("署名検証失敗（改ざんの可能性）")

        return True

    except QRVerifyError:
        raise
    except ValueError as e:
        raise QRVerifyError(f"パース失敗: {e}")
    except Exception as e:
        raise QRVerifyError(f"予期しないエラー: {e}")


# ════════════════════════════════════════════════════════════
#  ユーザー個別 QR トークン（Phase 0〜4 後方互換）
# ════════════════════════════════════════════════════════════

def generate_qr_token(user_id: int) -> dict:
    """
    [後方互換] ユーザー個別QRトークンを生成する。
    Phase 5 以降は generate_school_qr_token() を使うこと。
    """
    import base64
    window = _current_window()
    payload = f"{user_id}:{window}"
    sig = hmac.new(
        settings.QR_SECRET_KEY.encode(),
        payload.encode(),
        hashlib.sha256,
    ).digest()
    token = base64.urlsafe_b64encode(f"{payload}:".encode() + sig).decode()
    expires_at = (window + 1) * settings.QR_TOKEN_EXPIRE_SECONDS
    return {"token": token, "expires_at": expires_at, "user_id": user_id}


def verify_qr_token(token: str) -> int | None:
    """
    [後方互換] ユーザー個別QRトークンを検証する。
    有効なら user_id を返す。無効なら None。
    """
    import base64
    try:
        decoded = base64.urlsafe_b64decode(token.encode())
        parts = decoded.split(b":", 2)
        if len(parts) != 3:
            return None
        user_id = int(parts[0])
        window = int(parts[1])
        sig = parts[2]

        if window not in _valid_windows():
            return None

        expected_payload = f"{user_id}:{window}"
        expected_sig = hmac.new(
            settings.QR_SECRET_KEY.encode(),
            expected_payload.encode(),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return user_id
    except Exception:
        return None
