/**
 * EVING R2 API Worker
 *
 * Endpoints:
 *   GET    /health         - liveness check (без авторизации)
 *   POST   /presign        - выдаёт presigned PUT URL для загрузки файла в R2
 *   GET    /list           - список файлов текущего юзера (drops/<userId>/)
 *   DELETE /file?key=...   - удалить файл (только свой, проверка по prefix)
 *
 * Все endpoints кроме /health требуют Authorization: Bearer <Supabase JWT>.
 *
 * Архитектура upload: браузер просит presigned URL → грузит файл напрямую в R2.
 * Worker не пропускает данные через себя (обход лимита 100 MB request body).
 * Для list/delete используем нативный R2 binding (быстрее presign).
 */

import { AwsClient } from 'aws4fetch';
import { createRemoteJWKSet, jwtVerify } from 'jose';

interface Env {
  BUCKET: R2Bucket;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  R2_ACCOUNT_ID: string;
  SUPABASE_PROJECT_URL: string;
}

// FREE tier лимиты
const MAX_FILE_SIZE = 250 * 1024 * 1024; // 250 MB на файл
const MAX_STORAGE_BYTES = 1 * 1024 * 1024 * 1024; // 1 GB total

// Разрешённые origins для CORS
const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'https://eving.app',
  'https://www.eving.app',
  'https://app.eving.app',
  'https://eving-v2.pages.dev',
];

function corsHeaders(origin: string | null): Record<string, string> {
  const allow = origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function json(body: unknown, init: ResponseInit = {}, origin: string | null = null): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...corsHeaders(origin),
      ...(init.headers || {}),
    },
  });
}

// Кэш JWKS на время жизни Worker isolate
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks(env: Env) {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${env.SUPABASE_PROJECT_URL}/auth/v1/.well-known/jwks.json`));
  }
  return jwks;
}

async function verifyJwt(token: string, env: Env): Promise<string> {
  const { payload } = await jwtVerify(token, getJwks(env), {
    issuer: `${env.SUPABASE_PROJECT_URL}/auth/v1`,
  });
  if (!payload.sub) throw new Error('Token missing sub claim');
  return payload.sub;
}

/**
 * Достаёт userId из Authorization-заголовка. Бросает Response (401) при ошибке —
 * caller должен ловить и возвращать.
 */
async function requireUserId(request: Request, env: Env, origin: string | null): Promise<string> {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) throw json({ error: 'Missing Bearer token' }, { status: 401 }, origin);
  try {
    return await verifyJwt(token, env);
  } catch (e) {
    throw json({ error: 'Invalid token', detail: (e as Error).message }, { status: 401 }, origin);
  }
}

function sanitizeName(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[^\w.\-]+/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 100);
}

/**
 * Восстанавливает человекочитаемое имя из R2 key.
 * Key формат: drops/<userId>/<timestamp>-<random>-<safeName>
 */
function extractName(key: string): string {
  const base = key.split('/').pop() || key;
  const m = base.match(/^\d+-[a-z0-9]{8}-(.+)$/);
  return m ? m[1] : base;
}

/**
 * Считает общий объём storage пользователя суммируя все размеры в `drops/<userId>/`.
 * Хождение в R2 list — стоит копейки, но кэшировать стоило бы для high-traffic.
 */
async function calculateUsage(env: Env, userId: string): Promise<number> {
  const prefix = `drops/${userId}/`;
  let total = 0;
  let cursor: string | undefined;
  // Пагинация на случай >1000 файлов
  do {
    const listing: R2Objects = await env.BUCKET.list({ prefix, limit: 1000, cursor });
    for (const obj of listing.objects) total += obj.size;
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
  return total;
}

async function handleUsage(request: Request, env: Env, origin: string | null): Promise<Response> {
  const userId = await requireUserId(request, env, origin);
  const used = await calculateUsage(env, userId);
  return json(
    { used, limit: MAX_STORAGE_BYTES, fileSizeLimit: MAX_FILE_SIZE },
    {},
    origin
  );
}

async function handlePresign(request: Request, env: Env, origin: string | null): Promise<Response> {
  const userId = await requireUserId(request, env, origin);

  let body: { fileName?: string; size?: number; contentType?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, { status: 400 }, origin);
  }

  const { fileName, size, contentType } = body;
  if (!fileName || typeof size !== 'number' || !contentType) {
    return json({ error: 'fileName, size, contentType required' }, { status: 400 }, origin);
  }
  if (size <= 0 || size > MAX_FILE_SIZE) {
    return json(
      { error: `File too large. Max ${MAX_FILE_SIZE} bytes (250 MB)` },
      { status: 413 },
      origin
    );
  }

  // Storage quota check (1 GB FREE tier)
  const usage = await calculateUsage(env, userId);
  if (usage + size > MAX_STORAGE_BYTES) {
    return json(
      {
        error: 'Storage quota exceeded',
        detail: `Used ${usage} of ${MAX_STORAGE_BYTES} bytes. Adding ${size} bytes would exceed limit.`,
        used: usage,
        limit: MAX_STORAGE_BYTES,
        wouldAdd: size,
      },
      { status: 413 },
      origin
    );
  }

  const timestamp = Date.now();
  const random = Math.random().toString(36).slice(2, 10);
  const safeName = sanitizeName(fileName);
  const key = `drops/${userId}/${timestamp}-${random}-${safeName}`;

  const aws = new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    service: 's3',
    region: 'auto',
  });

  const r2Url = new URL(
    `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/eving-files/${key}`
  );
  r2Url.searchParams.set('X-Amz-Expires', '900');

  const signed = await aws.sign(
    new Request(r2Url.toString(), {
      method: 'PUT',
      headers: { 'content-type': contentType },
    }),
    { aws: { signQuery: true } }
  );

  return json(
    {
      uploadUrl: signed.url,
      key,
      expiresAt: new Date(timestamp + 15 * 60 * 1000).toISOString(),
    },
    {},
    origin
  );
}

async function handleList(request: Request, env: Env, origin: string | null): Promise<Response> {
  const userId = await requireUserId(request, env, origin);
  const prefix = `drops/${userId}/`;

  const listing = await env.BUCKET.list({
    prefix,
    include: ['httpMetadata'],
    limit: 1000,
  });

  const files = listing.objects.map((o) => ({
    key: o.key,
    name: extractName(o.key),
    size: o.size,
    uploaded: o.uploaded.toISOString(),
    contentType: o.httpMetadata?.contentType ?? 'application/octet-stream',
  }));

  // Свежие первыми
  files.sort((a, b) => (a.uploaded < b.uploaded ? 1 : -1));

  return json({ files, truncated: listing.truncated }, {}, origin);
}

async function handleDelete(request: Request, env: Env, origin: string | null): Promise<Response> {
  const userId = await requireUserId(request, env, origin);
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) return json({ error: 'key query param required' }, { status: 400 }, origin);

  // Защита: только свои файлы
  const expectedPrefix = `drops/${userId}/`;
  if (!key.startsWith(expectedPrefix)) {
    return json({ error: 'Forbidden: not your file' }, { status: 403 }, origin);
  }

  await env.BUCKET.delete(key);
  return json({ ok: true, key }, {}, origin);
}

async function handleDownload(request: Request, env: Env, origin: string | null): Promise<Response> {
  const userId = await requireUserId(request, env, origin);
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) return json({ error: 'key query param required' }, { status: 400 }, origin);

  const expectedPrefix = `drops/${userId}/`;
  if (!key.startsWith(expectedPrefix)) {
    return json({ error: 'Forbidden: not your file' }, { status: 403 }, origin);
  }

  const aws = new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    service: 's3',
    region: 'auto',
  });

  const r2Url = new URL(
    `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/eving-files/${key}`
  );
  // 5 минут жизни
  r2Url.searchParams.set('X-Amz-Expires', '300');

  const signed = await aws.sign(
    new Request(r2Url.toString(), { method: 'GET' }),
    { aws: { signQuery: true } }
  );

  return json(
    {
      downloadUrl: signed.url,
      key,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    },
    {},
    origin
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/health' && request.method === 'GET') {
        return json({ ok: true, service: 'eving-r2-api' }, {}, origin);
      }

      if (url.pathname === '/presign' && request.method === 'POST') {
        return await handlePresign(request, env, origin);
      }

      if (url.pathname === '/list' && request.method === 'GET') {
        return await handleList(request, env, origin);
      }

      if (url.pathname === '/file' && request.method === 'DELETE') {
        return await handleDelete(request, env, origin);
      }

      if (url.pathname === '/download' && request.method === 'GET') {
        return await handleDownload(request, env, origin);
      }

      if (url.pathname === '/usage' && request.method === 'GET') {
        return await handleUsage(request, env, origin);
      }

      return json({ error: 'Not found' }, { status: 404 }, origin);
    } catch (e) {
      // requireUserId бросает Response — отдаём как есть
      if (e instanceof Response) return e;
      console.error('Worker error', e);
      return json(
        { error: 'Internal error', detail: (e as Error).message },
        { status: 500 },
        origin
      );
    }
  },
};
