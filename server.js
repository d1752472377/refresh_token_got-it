const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// [保持原样] 端口恢复为 3000
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// [保持原样] 这里的端口是 1455，用于骗过 OpenAI 的白名单
const DEFAULT_OPENAI_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';

const OPENAI_CONFIG = {
  BASE_URL: process.env.OPENAI_BASE_URL || 'https://auth.openai.com',
  CLIENT_ID: process.env.OPENAI_CLIENT_ID || DEFAULT_OPENAI_CLIENT_ID,
  REDIRECT_URI: process.env.OPENAI_REDIRECT_URI || 'http://localhost:1455/auth/callback',
  SCOPE: process.env.OPENAI_SCOPE || 'openid profile email offline_access'
};

// 简单的 API 访问控制（用于保护 /api/*）
// 通过环境变量设置：API_KEY=一个足够长的随机字符串
// 客户端请求时带上：Authorization: Bearer <API_KEY>
const API_KEY = String(process.env.API_KEY || '').trim();

const OAUTH_SESSIONS = new Map();
const SESSION_TTL_MS = 10 * 60 * 1000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8'
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function isAuthorizedApiRequest(req) {
  // 如果未配置 API_KEY，则不启用鉴权（便于本地开发）。部署到公网时强烈建议设置。
  if (!API_KEY) return true;

  const auth = String(req.headers['authorization'] || '').trim();
  const prefix = 'Bearer ';
  if (!auth.startsWith(prefix)) return false;
  const token = auth.slice(prefix.length).trim();
  return safeEqual(token, API_KEY);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } 
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [sid, session] of OAUTH_SESSIONS) {
    if (session.expiresAt <= now) OAUTH_SESSIONS.delete(sid);
  }
}

function generateOpenAIPKCE() {
  const codeVerifier = crypto.randomBytes(64).toString('hex');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

function decodeJwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Invalid ID token');
  const payload = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
  return JSON.parse(payload);
}


function resolveClientId(clientIdFromRequest) {
  const candidate = String(clientIdFromRequest || '').trim();
  if (candidate) return candidate;
  return OPENAI_CONFIG.CLIENT_ID;
}

async function parseJsonResponse(response) {
  const rawText = await response.text();
  if (!rawText) return {};

  try {
    return JSON.parse(rawText);
  } catch {
    const snippet = rawText.slice(0, 200).replace(/\s+/g, ' ').trim();
    throw new Error(`上游返回了非 JSON 响应（HTTP ${response.status}）：${snippet}`);
  }
}

// 路由处理
async function handleGenerateAuthUrl(req, res) {
  try {
    cleanupExpiredSessions();
    const pkce = generateOpenAIPKCE();
    const state = crypto.randomBytes(32).toString('hex');
    const sessionId = crypto.randomUUID();

    const { clientId } = await readJsonBody(req);
    const resolvedClientId = resolveClientId(clientId);

    OAUTH_SESSIONS.set(sessionId, {
      codeVerifier: pkce.codeVerifier,
      state,
      clientId: resolvedClientId,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: resolvedClientId,
      redirect_uri: OPENAI_CONFIG.REDIRECT_URI,
      scope: OPENAI_CONFIG.SCOPE,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
      state,
      id_token_add_organizations: 'true',
      codex_cli_simplified_flow: 'true'
    });

    return sendJson(res, 200, {
      success: true,
      data: {
        authUrl: `${OPENAI_CONFIG.BASE_URL}/oauth/authorize?${params.toString()}`,
        sessionId
      }
    });
  } catch (err) {
    return sendJson(res, 500, { success: false, message: err.message });
  }
}

async function handleExchangeCode(req, res) {
  try {
    const { code, sessionId, debugRaw } = await readJsonBody(req);
    const debugRawEnabled =
      debugRaw === true ||
      debugRaw === 1 ||
      debugRaw === '1' ||
      debugRaw === 'true' ||
      debugRaw === 'on';

    const session = OAUTH_SESSIONS.get(String(sessionId));

    if (!session) return sendJson(res, 400, { success: false, message: '会话无效或已过期' });

    const clientId = resolveClientId(session.clientId);

    const redact = (value, keep = 8) => {
      const v = String(value || '');
      if (!v) return '';
      if (v.length <= keep) return `${v}(${v.length})`;
      return `${v.slice(0, keep)}...(${v.length})`;
    };

    const tokenEndpoint = `${OPENAI_CONFIG.BASE_URL}/oauth/token`;
    const upstreamBody = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: OPENAI_CONFIG.REDIRECT_URI,
      client_id: clientId,
      code_verifier: session.codeVerifier
    };

    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(upstreamBody)
    });

    const rawText = await tokenRes.text();
    let tokenData = {};
    try {
      tokenData = rawText ? JSON.parse(rawText) : {};
    } catch {
      const snippet = String(rawText || '').slice(0, 200).replace(/\s+/g, ' ').trim();
      const requestForLog = debugRawEnabled
        ? { ...upstreamBody }
        : {
          ...upstreamBody,
          code: redact(upstreamBody.code),
          code_verifier: redact(upstreamBody.code_verifier)
        };

      return sendJson(res, 502, {
        success: false,
        message: `上游返回了非 JSON 响应（HTTP ${tokenRes.status}）：${snippet}`,
        debug: {
          token_endpoint: tokenEndpoint,
          request: requestForLog,
          response: {
            status: tokenRes.status,
            ok: tokenRes.ok,
            content_type: tokenRes.headers.get('content-type') || ''
          }
        }
      });
    }

    const requestForLog = debugRawEnabled
      ? { ...upstreamBody }
      : {
        ...upstreamBody,
        code: redact(upstreamBody.code),
        code_verifier: redact(upstreamBody.code_verifier)
      };

    const tokenDataForLog = { ...tokenData };
    if (!debugRawEnabled) {
      for (const k of ['access_token', 'refresh_token', 'id_token']) {
        if (k in tokenDataForLog) tokenDataForLog[k] = redact(tokenDataForLog[k]);
      }
    }

    let decodedIdTokenPayloadForLog = null;
    if (tokenData && tokenData.id_token) {
      try {
        decodedIdTokenPayloadForLog = decodeJwtPayload(tokenData.id_token);
      } catch {
        decodedIdTokenPayloadForLog = null;
      }
    }

    const debug = {
      debug_raw_enabled: debugRawEnabled,
      token_endpoint: tokenEndpoint,
      request: requestForLog,
      response: {
        status: tokenRes.status,
        ok: tokenRes.ok,
        content_type: tokenRes.headers.get('content-type') || '',
        fields: Object.keys(tokenData || {}),
        body: tokenDataForLog,
        decoded_id_token_payload: decodedIdTokenPayloadForLog
      }
    };

    if (!tokenRes.ok) {
      const statusCode = tokenRes.status === 429 ? 429 : 400;
      const message = tokenRes.status === 429
        ? 'OpenAI 限流（429）。请稍后重试，或使用你自己的 OPENAI_CLIENT_ID / 代理后再试。'
        : 'OpenAI error';
      return sendJson(res, statusCode, { success: false, message, error: tokenData, debug });
    }

    const payload = decodeJwtPayload(tokenData.id_token);
    OAUTH_SESSIONS.delete(String(sessionId));

    return sendJson(res, 200, {
      success: true,
      data: {
        // 返回 Token 信息与 OAuth client_id
        refresh_token: tokenData.refresh_token,
        access_token: tokenData.access_token,
        expires_in: tokenData.expires_in,
        client_id: clientId,

        // OpenID Connect ID Token (JWT)
        id_token: tokenData.id_token,

        // id_token 的 payload（未验签，仅用于展示/调试）
        id_token_payload: payload,
        user_email: payload.email
      },
      debug
    });
  } catch (err) {
    return sendJson(res, 500, { success: false, message: err.message });
  }
}

// 静态文件服务
const server = http.createServer((req, res) => {
  // 保护所有 /api/* 请求（简单 Bearer Token）
  if (String(req.url || '').startsWith('/api/')) {
    if (!isAuthorizedApiRequest(req)) {
      return sendJson(res, 401, {
        success: false,
        message: 'Unauthorized: missing/invalid API key'
      });
    }
  }

  if (req.method === 'POST' && req.url === '/api/generate-auth-url') return handleGenerateAuthUrl(req, res);
  if (req.method === 'POST' && req.url === '/api/exchange-code') return handleExchangeCode(req, res);

  let filePath = path.join(PUBLIC_DIR, req.url === '/' ? 'index.html' : req.url);
  if (!path.normalize(filePath).startsWith(PUBLIC_DIR)) return sendJson(res, 403, { error: 'Forbidden' });

  fs.readFile(filePath, (err, content) => {
    if (err) return sendJson(res, 404, { error: 'Not Found' });
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(content);
  });
});

server.listen(PORT, () => {
  console.log(`\n> 服务已启动: http://localhost:${PORT}\n`);
});
