# モデルをここで全部インポートしておくと
# alembic env.py や main.py での import 漏れを防げる
from app.models.user import User, RoleEnum, StatusEnum                    # noqa: F401
from app.models.permission import Permission, PermEnum, ALL_ADMIN_PERMS   # noqa: F401
from app.models.attendance import AttendanceLog, CheckMethodEnum           # noqa: F401
from app.models.qr_token import QRToken   # noqa: F401
from app.models.audit import ScanEvent, AlertLog   # noqa: F401
