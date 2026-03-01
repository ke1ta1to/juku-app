"""
認証ルーター

POST /api/auth/login  … JWT 発行
GET  /api/auth/me     … ログイン中ユーザーの情報
POST /api/auth/me/password … 自分のパスワード変更
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.deps import require_login
from app.core.security import create_access_token, verify_password, get_password_hash
from app.db.session import get_db
from app.models.user import User, StatusEnum
from app.schemas.auth import TokenResponse, MeResponse
from app.schemas.user import MyPasswordUpdate

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── POST /api/auth/login ─────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    メールアドレス + パスワードで JWT を発行する。

    - 存在しない / パスワード不一致 → 401（情報を出し分けない）
    - inactive ユーザー → 403
    """
    user = db.query(User).filter(User.email == form_data.username).first()

    # 存在チェックとパスワード検証を同時に行い、タイミング攻撃を防ぐ
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="メールアドレスまたはパスワードが正しくありません",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.status == StatusEnum.inactive:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="このアカウントは無効化されています。管理者にお問い合わせください。",
        )

    token = create_access_token({
        "sub": str(user.id),
        "role": user.role.value,
        "is_admin": user.is_admin,
    })

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=MeResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role.value,
            is_admin=user.is_admin,
            status=user.status.value,
            permissions=user.perm_list(),
        ),
    )


# ── GET /api/auth/me ─────────────────────────────────────────────────────────
@router.get("/me", response_model=MeResponse)
def me(current_user: User = Depends(require_login)):
    """
    ログイン中のユーザー情報を返す。
    フロントのセッション確認・権限チェックに使う。
    """
    return MeResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        role=current_user.role.value,
        is_admin=current_user.is_admin,
        status=current_user.status.value,
        permissions=current_user.perm_list(),
    )


# ── POST /api/auth/me/password ───────────────────────────────────────────────
@router.post("/me/password", status_code=204)
def change_my_password(
    body: MyPasswordUpdate,
    current_user: User = Depends(require_login),
    db: Session = Depends(get_db),
):
    """
    本人によるパスワード変更。
    現在のパスワードを確認してから新しいパスワードを設定する。
    """
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="現在のパスワードが正しくありません",
        )
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新しいパスワードは現在のパスワードと異なる必要があります",
        )

    current_user.hashed_password = get_password_hash(body.new_password)
    db.commit()
