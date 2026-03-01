"""
初期管理者ユーザーのシードロジック。

動作:
  1. INITIAL_ADMIN_EMAIL が未設定なら何もしない（本番で誤作成を防ぐ）
  2. 同 email のユーザーが既に存在するならスキップ
  3. 存在しない場合、is_admin=True の teacher を作成し、全権限を付与する

環境変数:
  INITIAL_ADMIN_EMAIL    （必須）管理者のメールアドレス
  INITIAL_ADMIN_PASSWORD （任意）デフォルト: "changeme1234!"
  INITIAL_ADMIN_NAME     （任意）デフォルト: "管理者"
"""
import logging

from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.models.user import User, RoleEnum, StatusEnum
from app.models.permission import Permission, ALL_ADMIN_PERMS

logger = logging.getLogger(__name__)


def run_seed(db: Session, *, email: str, password: str, name: str) -> None:
    """
    管理者ユーザーを1件だけ作成する。
    既に存在する場合はスキップ。
    """
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        logger.info(f"[seed] 管理者 {email} は既に存在します → スキップ")
        return

    admin = User(
        name=name,
        email=email,
        hashed_password=get_password_hash(password),
        role=RoleEnum.teacher,
        is_admin=True,
        status=StatusEnum.active,
    )
    db.add(admin)
    db.flush()  # id を確定させてから permissions を挿入

    for perm in ALL_ADMIN_PERMS:
        db.add(Permission(user_id=admin.id, perm=perm))

    db.commit()
    db.refresh(admin)
    logger.info(
        f"[seed] 管理者を作成しました: id={admin.id}, email={email}, "
        f"perms={[p.perm for p in admin.permissions]}"
    )
    logger.warning("[seed] ⚠️  本番環境では INITIAL_ADMIN_PASSWORD を必ず変更してください")
