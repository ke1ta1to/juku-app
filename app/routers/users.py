"""
ユーザー管理ルーター

権限マトリクス:
  エンドポイント                        必要権限          教師(一般)  生徒
  ─────────────────────────────────────────────────────────────────────
  GET    /users/                         manage_users       ✗          ✗
  POST   /users/                         manage_users       ✗          ✗
  GET    /users/{id}                     manage_users       ✗          ✗
  PATCH  /users/{id}                     manage_users       ✗          ✗
  PATCH  /users/{id}/status              manage_users       ✗          ✗
  PATCH  /users/{id}/role                manage_users       ✗          ✗
  DELETE /users/{id}                     manage_users       ✗          ✗
  GET    /users/{id}/permissions         manage_roles       ✗          ✗
  POST   /users/{id}/permissions         manage_roles       ✗          ✗
  DELETE /users/{id}/permissions/{perm}  manage_roles       ✗          ✗
"""
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.deps import require_permission
from app.db.session import get_db
from app.models.user import User, RoleEnum, StatusEnum
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserOut,
    UserListItem,
    UserListQuery,
    StatusUpdate,
    RoleUpdate,
    PermissionGrant,
    PermissionListResponse,
)
from app.services import user_service

router = APIRouter(prefix="/api/users", tags=["users"])

# ── Depends ショートハンド ───────────────────────────────────────────────────
_manage_users = Depends(require_permission("manage_users"))
_manage_roles = Depends(require_permission("manage_roles"))


# ════════════════════════════════════════════════════════════
#  一覧・詳細
# ════════════════════════════════════════════════════════════

@router.get("/", response_model=list[UserListItem], summary="ユーザー一覧（フィルタ付き）")
def list_users(
    role: RoleEnum | None = Query(None, description="ロールで絞り込み: teacher / student"),
    status_filter: StatusEnum | None = Query(None, alias="status", description="在籍状態で絞り込み: active / inactive"),
    q: str | None = Query(None, description="名前またはメールの部分一致検索"),
    db: Session = Depends(get_db),
    _: User = _manage_users,
):
    """
    ユーザー一覧を取得する（管理者のみ）。

    クエリパラメータ例:
    - `?role=student`               在籍中の生徒のみ
    - `?role=student&status=active` 在籍中の生徒のみ
    - `?status=inactive`            退会者のみ
    - `?q=田中`                     名前・メールに「田中」を含む全ユーザー
    - 引数なし                      全件
    """
    query = UserListQuery(role=role, status=status_filter, q=q)
    return user_service.list_users(db, query)


@router.get("/{user_id}", response_model=UserOut, summary="ユーザー詳細")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = _manage_users,
):
    """特定ユーザーの詳細情報（権限リスト・タイムスタンプ含む）"""
    user = user_service.get_user_or_404(db, user_id)
    return UserOut.from_user(user)


# ════════════════════════════════════════════════════════════
#  ユーザー作成・更新・削除
# ════════════════════════════════════════════════════════════

@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="ユーザー追加")
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    _: User = _manage_users,
):
    """
    新規ユーザーを追加する（管理者のみ）。

    - email 重複は 409
    - パスワードは8文字以上
    - 生徒に is_admin=True は 400
    """
    user = user_service.create_user(db, body)
    return UserOut.from_user(user)


@router.patch("/{user_id}", response_model=UserOut, summary="ユーザー情報更新")
def update_user(
    user_id: int,
    body: UserUpdate,
    db: Session = Depends(get_db),
    _: User = _manage_users,
):
    """
    ユーザー情報を部分更新する（名前 / 電話番号 / パスワード）。

    - 退会済みユーザーは 400
    - 変更フィールドを1つも指定しないと 422
    """
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.update_user(db, user, body)
    return UserOut.from_user(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="ユーザー削除")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_users")),
):
    """
    ユーザーを物理削除する（管理者のみ）。

    **在籍中（active）のユーザーは削除不可。先に `/status` で inactive にすること。**
    退会者のアカウントを完全消去する用途に使う。
    関連する入退室ログも CASCADE で削除される。
    """
    user = user_service.get_user_or_404(db, user_id)
    user_service.delete_user(db, user, operator)


# ════════════════════════════════════════════════════════════
#  在籍状態の変更
# ════════════════════════════════════════════════════════════

@router.patch("/{user_id}/status", response_model=UserOut, summary="在籍状態変更")
def change_status(
    user_id: int,
    body: StatusUpdate,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_users")),
):
    """
    在籍状態を変更する（統合エンドポイント）。

    ```
    { "status": "inactive" }  → 退会処理
    { "status": "active"   }  → 復帰処理
    ```

    ガード:
    - 自分自身を inactive にはできない
    - 現在と同じ status への変更は 409
    """
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.change_status(db, user, body.status, operator)
    return UserOut.from_user(user)


# ── 後方互換エイリアス（既存クライアントへの影響なし）──────────────────────
@router.patch("/{user_id}/deactivate", response_model=UserOut, include_in_schema=False)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_users")),
):
    """後方互換: PATCH /deactivate → /status に統合済み"""
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.deactivate_user(db, user, operator)
    return UserOut.from_user(user)


@router.patch("/{user_id}/reactivate", response_model=UserOut, include_in_schema=False)
def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = _manage_users,
):
    """後方互換: PATCH /reactivate → /status に統合済み"""
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.reactivate_user(db, user)
    return UserOut.from_user(user)


# ════════════════════════════════════════════════════════════
#  ロール変更
# ════════════════════════════════════════════════════════════

@router.patch("/{user_id}/role", response_model=UserOut, summary="ロール変更")
def change_role(
    user_id: int,
    body: RoleUpdate,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_users")),
):
    """
    ユーザーのロールを変更する（管理者のみ）。

    **重要な副作用**:
    - teacher → student への変更時、管理者権限（is_admin）と全 permissions が自動削除される
    - 自分自身のロール変更は不可
    - 退会済みユーザーは変更不可
    """
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.change_role(db, user, body.role, operator)
    return UserOut.from_user(user)


# ════════════════════════════════════════════════════════════
#  権限管理（manage_roles 権限が必要）
# ════════════════════════════════════════════════════════════

@router.get("/{user_id}/permissions", response_model=PermissionListResponse, summary="権限一覧")
def list_user_permissions(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = _manage_roles,
):
    """対象ユーザーが持つ権限の一覧を返す"""
    user = user_service.get_user_or_404(db, user_id)
    return PermissionListResponse(user_id=user.id, permissions=user.perm_list())


@router.post(
    "/{user_id}/permissions",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="権限付与",
)
def grant_permission(
    user_id: int,
    body: PermissionGrant,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_roles")),
):
    """
    ユーザーに権限を付与する。

    - 生徒への付与は 400
    - 退会済みへの付与は 400
    - 重複付与は 409
    - 初回付与時は is_admin=True が自動セットされる
    """
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.grant_permission(db, user, body.perm, operator)
    return UserOut.from_user(user)


@router.delete(
    "/{user_id}/permissions/{perm}",
    response_model=UserOut,
    summary="権限剥奪",
)
def revoke_permission(
    user_id: int,
    perm: str,
    db: Session = Depends(get_db),
    operator: User = Depends(require_permission("manage_roles")),
):
    """
    ユーザーから指定権限を剥奪する。

    - 自分自身の権限は剥奪不可（ロックアウト防止）
    - 存在しない権限は 404
    - 全権限剥奪後は is_admin=False に自動降格
    """
    user = user_service.get_user_or_404(db, user_id)
    user = user_service.revoke_permission(db, user, perm, operator)
    return UserOut.from_user(user)
