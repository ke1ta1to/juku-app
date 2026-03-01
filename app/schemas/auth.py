from pydantic import BaseModel


class TokenResponse(BaseModel):
    """POST /auth/login のレスポンス"""
    access_token: str
    token_type: str = "bearer"
    user: "MeResponse"


class MeResponse(BaseModel):
    """GET /auth/me のレスポンス"""
    id: int
    name: str
    email: str
    role: str
    is_admin: bool
    status: str
    permissions: list[str]  # PermEnum の値リスト

    model_config = {"from_attributes": True}


# TokenResponse が MeResponse を前方参照しているので再構築
TokenResponse.model_rebuild()
