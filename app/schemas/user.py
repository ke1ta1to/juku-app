"""
ユーザー関連 Pydantic スキーマ

入力（リクエスト）と出力（レスポンス）を明確に分離する。
パスワードハッシュは絶対に出力スキーマに含めない。
"""
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from app.models.user import RoleEnum, StatusEnum
from app.models.permission import PermEnum


# ════════════════════════════════════════════════════════════
#  出力スキーマ
# ════════════════════════════════════════════════════════════

class UserOut(BaseModel):
    """ユーザー詳細（権限リスト含む）"""
    id: int
    name: str
    email: str
    phone: str | None
    role: RoleEnum
    is_admin: bool
    status: StatusEnum
    permissions: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_user(cls, user) -> "UserOut":
        return cls(
            id=user.id,
            name=user.name,
            email=user.email,
            phone=user.phone,
            role=user.role,
            is_admin=user.is_admin,
            status=user.status,
            permissions=user.perm_list(),
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class UserListItem(BaseModel):
    """ユーザー一覧の1行（軽量版）"""
    id: int
    name: str
    email: str
    phone: str | None
    role: RoleEnum
    is_admin: bool
    status: StatusEnum
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════════════
#  一覧フィルタ（Query Parameters）
# ════════════════════════════════════════════════════════════

class UserListQuery(BaseModel):
    """
    GET /users のクエリパラメータ

    使用例:
      GET /api/users?role=student&status=active
      GET /api/users?role=teacher&status=inactive
      GET /api/users?q=田中&status=active
      GET /api/users  （全件）
    """
    role: RoleEnum | None = Field(None, description="絞り込み: teacher / student")
    status: StatusEnum | None = Field(None, description="絞り込み: active / inactive")
    q: str | None = Field(None, description="名前 or メールの部分一致検索")

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════════════
#  作成・更新スキーマ
# ════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    """新規ユーザー作成（管理者のみ）"""
    name: Annotated[str, Field(min_length=1, max_length=100)]
    email: EmailStr
    password: Annotated[str, Field(min_length=8, description="8文字以上")]
    phone: str | None = Field(None, pattern=r"^[\d\-\+\(\) ]{7,20}$")
    role: RoleEnum
    is_admin: bool = False

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """メールアドレスを小文字に正規化"""
        return v.lower().strip()

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("名前は空にできません")
        return v

    @model_validator(mode="after")
    def admin_requires_teacher(self) -> "UserCreate":
        """生徒に管理者フラグは付与不可"""
        if self.is_admin and self.role == RoleEnum.student:
            raise ValueError("生徒（student）に管理者権限は付与できません")
        return self


class UserUpdate(BaseModel):
    """ユーザー情報の部分更新（管理者が行う）"""
    name: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    phone: str | None = Field(None, pattern=r"^[\d\-\+\(\) ]{7,20}$")
    password: Annotated[str, Field(min_length=8)] | None = None

    @field_validator("name")
    @classmethod
    def strip_name(cls, v):
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("名前は空にできません")
        return v

    @model_validator(mode="after")
    def at_least_one_field(self) -> "UserUpdate":
        if all(v is None for v in [self.name, self.phone, self.password]):
            raise ValueError("更新フィールドを少なくとも1つ指定してください")
        return self


class StatusUpdate(BaseModel):
    """
    PATCH /users/{id}/status のボディ

    active  … 在籍（復帰）
    inactive … 退会
    """
    status: StatusEnum = Field(..., description="active: 在籍復帰 / inactive: 退会")


class RoleUpdate(BaseModel):
    """
    PATCH /users/{id}/role のボディ

    注意: teacher → student に変更すると is_admin が強制 False になり
    permissions テーブルの行も全削除される。
    """
    role: RoleEnum = Field(..., description="teacher / student")


class MyPasswordUpdate(BaseModel):
    """本人によるパスワード変更"""
    current_password: str
    new_password: Annotated[str, Field(min_length=8, description="8文字以上")]

    @model_validator(mode="after")
    def passwords_differ(self) -> "MyPasswordUpdate":
        if self.current_password == self.new_password:
            raise ValueError("新しいパスワードは現在のパスワードと異なる必要があります")
        return self


# ════════════════════════════════════════════════════════════
#  権限関連スキーマ
# ════════════════════════════════════════════════════════════

class PermissionGrant(BaseModel):
    """権限付与リクエスト"""
    perm: str = Field(
        ...,
        description=f"付与する権限。有効値: {[e.value for e in PermEnum]}",
    )


class PermissionListResponse(BaseModel):
    """権限一覧レスポンス"""
    user_id: int
    permissions: list[str]
