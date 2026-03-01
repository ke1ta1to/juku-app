"""
ユーザー操作のビジネスロジック

設計原則:
  - ルーターは HTTP の入出力に専念し、DB 操作・ビジネスルールはここに集約
  - 全関数は「成功時は更新済み User を返す / 失敗時は HTTPException を raise」
  - inactive ユーザーへの操作制限はこの層で一元管理し、ルーターに漏らさない
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy import or_
from fastapi import HTTPException, status

from app.core.security import get_password_hash
from app.models.user import User, RoleEnum, StatusEnum
from app.models.permission import Permission, PermEnum
from app.schemas.user import UserCreate, UserUpdate, UserListQuery


# ════════════════════════════════════════════════════════════
#  ユーティリティ
# ════════════════════════════════════════════════════════════

def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_user_or_404(db: Session, user_id: int) -> User:
    """存在しなければ 404"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    return user


def _assert_active(user: User) -> None:
    """
    退会済みユーザーへの操作をブロックする共通ガード。
    スキャン以外の操作（情報更新・権限変更など）でも退会済みなら拒否する。
    """
    if user.status == StatusEnum.inactive:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"退会済みのユーザー（id={user.id}）には操作できません。先に復帰処理を行ってください。",
        )


# ════════════════════════════════════════════════════════════
#  一覧取得
# ════════════════════════════════════════════════════════════

def list_users(db: Session, query: UserListQuery) -> list[User]:
    """
    フィルタ付きユーザー一覧を返す。

    フィルタ:
      role   … teacher / student
      status … active / inactive
      q      … name または email の部分一致（大文字小文字無視）
    """
    q = db.query(User)

    if query.role is not None:
        q = q.filter(User.role == query.role)

    if query.status is not None:
        q = q.filter(User.status == query.status)

    if query.q:
        keyword = f"%{query.q}%"
        q = q.filter(
            or_(
                User.name.ilike(keyword),
                User.email.ilike(keyword),
            )
        )

    return q.order_by(User.role, User.name).all()


# ════════════════════════════════════════════════════════════
#  ユーザー作成
# ════════════════════════════════════════════════════════════

def create_user(db: Session, body: UserCreate) -> User:
    """
    新規ユーザーを作成する。

    バリデーション（スキーマ層でも行っているが二重防衛として実施）:
      - email 重複禁止
      - 生徒に is_admin=True 不可
    """
    # email 重複チェック（DB レベル）
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"メールアドレス '{body.email}' はすでに使用されています",
        )

    if body.is_admin and body.role == RoleEnum.student:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="生徒（student）に管理者権限は付与できません",
        )

    user = User(
        name=body.name,
        email=body.email,
        phone=body.phone,
        hashed_password=get_password_hash(body.password),
        role=body.role,
        is_admin=body.is_admin,
        status=StatusEnum.active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ════════════════════════════════════════════════════════════
#  ユーザー情報更新
# ════════════════════════════════════════════════════════════

def update_user(db: Session, user: User, body: UserUpdate) -> User:
    """
    管理者による他ユーザーの情報更新（部分更新）。
    退会済みユーザーには操作不可。
    """
    _assert_active(user)

    if body.name is not None:
        user.name = body.name.strip()
    if body.phone is not None:
        user.phone = body.phone
    if body.password is not None:
        user.hashed_password = get_password_hash(body.password)

    user.updated_at = _now()
    db.commit()
    db.refresh(user)
    return user


# ════════════════════════════════════════════════════════════
#  在籍状態の変更（統合版）
# ════════════════════════════════════════════════════════════

def change_status(
    db: Session,
    user: User,
    new_status: StatusEnum,
    operator: User,
) -> User:
    """
    在籍状態を変更する統合関数。

    ガード:
      - 自分自身を inactive にはできない
      - 現在と同じ status への変更は拒否（冪等ではなくエラーにして誤操作を防ぐ）

    active  → inactive: 退会処理
    inactive → active:  復帰処理
    """
    if new_status == StatusEnum.inactive and user.id == operator.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="自分自身を退会させることはできません",
        )
    if user.status == new_status:
        label = "在籍中" if new_status == StatusEnum.active else "退会済み"
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"すでに{label}のユーザーです（変更なし）",
        )

    user.status = new_status
    user.updated_at = _now()
    db.commit()
    db.refresh(user)
    return user


# 後方互換エイリアス（Phase 2 のルーターから呼ばれる分）
def deactivate_user(db: Session, user: User, operator: User) -> User:
    return change_status(db, user, StatusEnum.inactive, operator)


def reactivate_user(db: Session, user: User) -> User:
    # operator チェックが不要な復帰は自分自身でも可（将来の self-reactivation 用）
    # ただし現状は管理者しか呼べないため実質制限あり
    if user.status == StatusEnum.active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="すでに在籍中のユーザーです",
        )
    user.status = StatusEnum.active
    user.updated_at = _now()
    db.commit()
    db.refresh(user)
    return user


# ════════════════════════════════════════════════════════════
#  ロール変更
# ════════════════════════════════════════════════════════════

def change_role(
    db: Session,
    user: User,
    new_role: RoleEnum,
    operator: User,
) -> User:
    """
    ユーザーのロールを変更する。

    ガード:
      - 退会済みユーザーは変更不可
      - 自分自身のロールは変更不可（自己降格防止）
      - 現在と同じロールへの変更はエラー
      - teacher → student 変更時: is_admin を False に強制し、permissions を全削除
        （生徒が権限を持ち続けるのを防ぐ）
    """
    _assert_active(user)

    if user.id == operator.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="自分自身のロールは変更できません",
        )
    if user.role == new_role:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"すでに '{new_role.value}' ロールです（変更なし）",
        )

    # teacher → student: 管理者権限を強制剥奪
    if new_role == RoleEnum.student and user.is_admin:
        db.query(Permission).filter(Permission.user_id == user.id).delete()
        user.is_admin = False

    user.role = new_role
    user.updated_at = _now()
    db.commit()
    db.refresh(user)
    return user


# ════════════════════════════════════════════════════════════
#  ユーザー削除
# ════════════════════════════════════════════════════════════

def delete_user(db: Session, user: User, operator: User) -> None:
    """
    ユーザーを物理削除する。

    ガード:
      - 自分自身は削除不可
      - 在籍中（active）は削除不可（先に退会させること）
      → attendance_logs は CASCADE で自動削除される
    """
    if user.id == operator.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="自分自身を削除することはできません",
        )
    if user.status == StatusEnum.active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="在籍中のユーザーは削除できません。先に退会処理（status=inactive）を行ってください。",
        )
    db.delete(user)
    db.commit()


# ════════════════════════════════════════════════════════════
#  権限管理
# ════════════════════════════════════════════════════════════

def grant_permission(db: Session, user: User, perm: str, operator: User) -> User:
    """
    ユーザーに権限を付与する。

    ガード:
      - 退会済みユーザーには付与不可
      - 生徒への付与は不可
      - 重複付与は 409
      - 最初の権限付与時に is_admin=True を自動セット
    """
    _assert_active(user)

    try:
        perm_enum = PermEnum(perm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"無効な権限値: '{perm}'. 有効値: {[e.value for e in PermEnum]}",
        )

    if user.role == RoleEnum.student:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="生徒（student）に権限を付与することはできません",
        )

    existing = db.query(Permission).filter(
        Permission.user_id == user.id,
        Permission.perm == perm_enum,
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"'{perm}' 権限はすでに付与されています",
        )

    if not user.is_admin:
        user.is_admin = True

    db.add(Permission(user_id=user.id, perm=perm_enum))
    user.updated_at = _now()
    db.commit()
    db.refresh(user)
    return user


def revoke_permission(db: Session, user: User, perm: str, operator: User) -> User:
    """
    ユーザーから権限を剥奪する。

    ガード:
      - 自分自身の権限は剥奪不可（ロックアウト防止）
      - 存在しない権限の剥奪は 404
      - 全権限剥奪後は is_admin=False に自動降格
    """
    if user.id == operator.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="自分自身の権限を剥奪することはできません",
        )

    try:
        perm_enum = PermEnum(perm)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"無効な権限値: '{perm}'. 有効値: {[e.value for e in PermEnum]}",
        )

    perm_row = db.query(Permission).filter(
        Permission.user_id == user.id,
        Permission.perm == perm_enum,
    ).first()
    if not perm_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"'{perm}' 権限は付与されていません",
        )

    db.delete(perm_row)

    # 残り権限を確認（削除直後は flush が必要）
    db.flush()
    remaining = db.query(Permission).filter(Permission.user_id == user.id).count()
    if remaining == 0:
        user.is_admin = False

    user.updated_at = _now()
    db.commit()
    db.refresh(user)
    return user
