"""
FastAPI 依存関数（Dependency Injection）モジュール

使い方:
    # ログイン済み全ユーザー
    current_user: User = Depends(require_login)

    # 特定権限が必要なエンドポイント
    _: User = Depends(require_permission("manage_users"))

    # 教師ロール以上（閲覧系）
    current_user: User = Depends(require_teacher)

権限チェックの流れ:
    1. JWT デコード → user_id 取得
    2. DB から User を取得（status=active のみ通過）
    3. is_admin フラグで管理者か判定（高速パス）
    4. permissions テーブルで細粒度チェック
"""
from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User, StatusEnum, RoleEnum
from app.models.permission import PermEnum

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ── 定型例外 ─────────────────────────────────────────────────────────────────
_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="認証情報が無効です",
    headers={"WWW-Authenticate": "Bearer"},
)


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


# ── 基底：ログイン済みユーザー取得 ───────────────────────────────────────────
def require_login(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    JWT を検証して User を返す。
    - トークン無効 / 期限切れ → 401
    - ユーザーが存在しない / inactive → 401
    """
    payload = decode_access_token(token)
    if payload is None:
        raise _CREDENTIALS_EXC

    sub = payload.get("sub")
    if sub is None:
        raise _CREDENTIALS_EXC

    user = db.query(User).filter(User.id == int(sub)).first()
    if user is None or user.status == StatusEnum.inactive:
        raise _CREDENTIALS_EXC

    return user


# ── 権限ガード：ファクトリ関数 ────────────────────────────────────────────────
def require_permission(perm: str) -> Callable:
    """
    指定した権限を持つ管理者のみ通過させる依存関数を返すファクトリ。

    使用例:
        @router.post("/users/")
        def create_user(_: User = Depends(require_permission("manage_users"))):
            ...

    権限チェック順:
        1. require_login（JWT・在籍確認）
        2. is_admin=False なら即 403
        3. permissions テーブルに perm が存在しなければ 403

    Parameters:
        perm: PermEnum の値文字列
              "manage_users" / "manage_roles" / "view_all_logs"
    """
    # サーバー起動時に誤字を検出する事前検証
    try:
        perm_enum = PermEnum(perm)
    except ValueError:
        raise ValueError(
            f"require_permission に無効な perm 値: '{perm}'. "
            f"有効値: {[e.value for e in PermEnum]}"
        )

    def _guard(current_user: User = Depends(require_login)) -> User:
        # ① 管理者フラグの高速チェック（DB アクセスなし）
        if not current_user.is_admin:
            raise _forbidden("この操作には管理者権限が必要です")

        # ② 細粒度権限チェック（User.permissions リレーションを参照）
        if not current_user.has_perm(perm_enum):
            raise _forbidden(
                f"この操作には '{perm}' 権限が必要です。"
                f"現在の権限: {current_user.perm_list()}"
            )

        return current_user

    # FastAPI が関数名でキャッシュするため、一意な名前をつける
    _guard.__name__ = f"require_permission_{perm}"
    return _guard


# ── 教師ロールガード（閲覧系で使用）──────────────────────────────────────────
def require_teacher(current_user: User = Depends(require_login)) -> User:
    """
    教師ロールのみ通過。生徒専用 UI では使わない。
    """
    if current_user.role != RoleEnum.teacher:
        raise _forbidden("教師権限が必要です")
    return current_user


# ── 後方互換エイリアス（Phase 0/1 との互換性）────────────────────────────────
get_current_user = require_login
require_admin = require_permission("manage_users")
