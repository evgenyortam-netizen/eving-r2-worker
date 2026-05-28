# eving-r2-worker

Cloudflare Worker — API для DROP-модуля приложения [EVING](https://app.eving.app).
Production endpoint: **https://api.eving.app**

## Endpoints

| Method | Path | Auth | Назначение |
|---|---|---|---|
| GET | `/health` | — | Liveness check |
| POST | `/presign` | Bearer JWT (Supabase) | Presigned PUT URL для upload в R2 (max 250 MB) |
| GET | `/list` | Bearer JWT | Список файлов юзера из `drops/<userId>/` |
| GET | `/download?key=...` | Bearer JWT | Presigned GET URL (5 мин TTL) для просмотра/скачивания |
| DELETE | `/file?key=...` | Bearer JWT | Удалить файл (только из своего prefix) |

## Архитектура upload

```
Browser → POST /presign к Worker (с Supabase JWT)
       ← presigned PUT URL на *.r2.cloudflarestorage.com
Browser → PUT файла прямо в R2 (минуя Worker, без лимита 100 MB)
```

JWT валидируется через `jose` + Supabase JWKS endpoint.
Presigning через `aws4fetch` (R2 S3-compatible).

## R2 bucket

- Имя: `eving-files`
- Lifecycle: `drops/` → автоудаление через 1 день
- CORS: PUT/GET/HEAD для localhost:5173, eving.app, www.eving.app, app.eving.app, eving-v2.pages.dev

## Деплой

```bash
npx wrangler deploy
```

Secrets (через Cloudflare Dashboard или `wrangler secret put`):
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_ACCOUNT_ID`
- `SUPABASE_PROJECT_URL`

## Frontend

Соответствующий React+Vite фронт: [eving-v2](https://github.com/evgenyortam-netizen/eving-v2)
