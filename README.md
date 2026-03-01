# 塾管理アプリ (JukuApp) - バックエンド

## Phase 0 完了状態
- `GET /health` → `{"ok": true}` で動作確認済み
- JWT認証・HMAC署名付きQRトークン実装済み
- 権限モデル（管理者/一般教師/生徒）実装済み

## ディレクトリ構成

```
juku_app/
├── app/
│   ├── main.py            # エントリーポイント
│   ├── core/
│   │   ├── config.py      # 設定（.envから読込）
│   │   ├── security.py    # JWT + パスワード + QR HMAC
│   │   └── deps.py        # FastAPI 依存関数（認証・権限）
│   ├── db/
│   │   ├── base.py        # SQLAlchemy Base
│   │   └── session.py     # DBセッション
│   ├── models/
│   │   ├── user.py        # Userモデル
│   │   └── attendance.py  # AttendanceLogモデル
│   ├── routers/
│   │   ├── auth.py        # POST /api/auth/login
│   │   ├── users.py       # /api/users（管理者操作）
│   │   ├── attendance.py  # /api/attendance（閲覧）
│   │   └── qr.py          # /api/qr（QR発行・スキャン）
│   ├── schemas/           # (Phase 1以降で追加)
│   └── services/          # (Phase 1以降で追加)
├── alembic/               # DBマイグレーション
├── alembic.ini
├── requirements.txt
├── seed_admin.py          # 初回管理者作成スクリプト
└── .env.example
```

## セットアップ

```bash
# 1. 仮想環境
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 2. 依存インストール
pip install -r requirements.txt

# 3. 環境変数
cp .env.example .env
# .env を編集して SECRET_KEY などを設定

# 4. 初回管理者を作成
python seed_admin.py

# 5. 起動
uvicorn app.main:app --reload

# → http://localhost:8000/health  で {"ok": true} が返ればOK
# → http://localhost:8000/docs    でSwagger UIを確認
```

## API 概要

| エンドポイント | 権限 | 説明 |
|---|---|---|
| `POST /api/auth/login` | 全員 | ログイン→JWT取得 |
| `GET  /api/qr/token` | 在籍中の全員 | QRトークン取得（1分更新） |
| `GET  /api/qr/token/image` | 在籍中の全員 | QRコード画像（PNG） |
| `POST /api/qr/scan` | 在籍中の全員 | QRスキャン→入退室自動判断 |
| `GET  /api/attendance/me` | 全員 | 自分の履歴 |
| `GET  /api/attendance/today` | 全員（範囲は権限次第） | 本日のライブ状況 |
| `GET  /api/attendance/all` | 管理者のみ | 全履歴 |
| `GET  /api/users/` | 管理者のみ | 全ユーザー一覧 |
| `POST /api/users/` | 管理者のみ | 新規ユーザー追加 |
| `PATCH /api/users/{id}/deactivate` | 管理者のみ | 退会処理 |
| `DELETE /api/users/{id}` | 管理者のみ | アカウント削除 |

## QRコードの仕組み（HMAC方式）

- サーバーが `user_id:タイムウィンドウ番号` をHMAC-SHA256で署名
- タイムウィンドウ = `unix_time // 60`（1分ごとに変わる）
- スキャン時に署名を検証→改ざん・使い回し不可
- 直前ウィンドウ（最大59秒）も許容してスキャン遅延に対応

## 入退室の自動判断ロジック

```
今日のレコードなし          → check_in（入室）記録
check_in あり・check_out なし → check_out（退室）記録  
check_in・check_out どちらもあり → 409エラー「退室済み」
在籍（active）でないユーザー  → 403エラー（スキャン拒否）
```

## 次のPhase

- **Phase 1**: Alembicマイグレーション整備 + ユーザー更新エンドポイント
- **Phase 2**: フロントエンド（React/Next.js）- QR表示・スキャン・ライブ一覧
- **Phase 3**: WebSocket対応（現在はポーリング4秒推奨）
