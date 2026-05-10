'use strict';
// ============================================================
//  Helpers de autenticação — JWT + bcrypt
//
//  JWT é assimétrico ao tenant: o payload inclui tenant_slug.
//  Tokens de um tenant são rejeitados em outro.
// ============================================================
const crypto  = require('crypto');
const bcryptjs = require('bcryptjs');

// ── JWT_SECRET obrigatório — sem fallback ────────────────────────────
const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.error('[FATAL] JWT_SECRET não definido nas variáveis de ambiente. O servidor não pode iniciar com segurança.');
  process.exit(1);
}

// ── JWT ──────────────────────────────────────────────────────────────
function jwtSign(payload, secs = 43200) {
  const hdr  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + secs })).toString('base64url');
  const sig  = crypto.createHmac('sha256', SECRET).update(`${hdr}.${body}`).digest('base64url');
  return `${hdr}.${body}.${sig}`;
}

function jwtVerify(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('token inválido');
  const [hdr, body, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${hdr}.${body}`).digest('base64url');
  if (sig !== expected) throw new Error('assinatura inválida');
  const p = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (p.exp && Date.now() / 1000 > p.exp) throw new Error('token expirado');
  return p;
}

// ── Senhas ───────────────────────────────────────────────────────────
const BCRYPT_ROUNDS = 10;

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

async function bcryptHash(plain) {
  return bcryptjs.hash(plain, BCRYPT_ROUNDS);
}

// Retorna { ok: bool, needsRehash: bool }
// needsRehash=true quando o hash era SHA-256 e o login foi bem-sucedido
// — o chamador deve salvar o novo hash bcrypt silenciosamente.
async function verifyPassword(plain, hash) {
  if (typeof hash === 'string' && (hash.startsWith('$2b$') || hash.startsWith('$2a$'))) {
    return { ok: await bcryptjs.compare(plain, hash), needsRehash: false };
  }
  // Hash legado SHA-256: verifica e sinaliza para migração transparente
  const ok = sha256(plain) === hash;
  return { ok, needsRehash: ok };
}

// ── Rate limiting — login ─────────────────────────────────────────────
// 10 tentativas por IP a cada 15 minutos. Usuário legítimo nunca percebe.
const _loginAttempts = new Map();
const RATE_MAX    = 10;
const RATE_WINDOW = 15 * 60 * 1000; // 15 minutos em ms

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'unknown';
}

function checkRateLimit(req) {
  const ip  = getClientIp(req);
  const now = Date.now();
  const entry = _loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    _loginAttempts.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_MAX;
}

function resetRateLimit(req) {
  _loginAttempts.delete(getClientIp(req));
}

// ── Middleware de autenticação ────────────────────────────────────────
const PUBLIC_ROUTES = new Set([
  '/api/auth/login',
  '/api/version',
  '/api/brand',
  '/api/conveniencia/catalog',
  '/api/conveniencia/order',
]);

function authMiddleware(req, res, next) {
  const path = (req.url || '').split('?')[0];

  // Rotas públicas (sem token)
  // Nota: /api/superadmin/auth/login é pública, mas as demais rotas
  // super-admin precisam ter o token validado para definir ctx.user.
  if (PUBLIC_ROUTES.has(path) || path === '/api/superadmin/auth/login') {
    return next();
  }

  const rawToken = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!rawToken) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Token não fornecido' }));
  }

  let payload;
  try {
    payload = jwtVerify(rawToken);
  } catch (e) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: `Token inválido: ${e.message}` }));
  }

  // Valida que o token pertence ao tenant da requisição
  if (req.tenantSlug && payload.tenant_slug && payload.tenant_slug !== req.tenantSlug) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Token de outro tenant — acesso negado' }));
  }

  req.user = payload;
  return next();
}

module.exports = { jwtSign, jwtVerify, sha256, bcryptHash, verifyPassword, checkRateLimit, resetRateLimit, authMiddleware };
