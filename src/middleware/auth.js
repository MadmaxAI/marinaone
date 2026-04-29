'use strict';
// ============================================================
//  Helpers de autenticação — JWT + bcrypt
//
//  JWT é assimétrico ao tenant: o payload inclui tenant_slug.
//  Tokens de um tenant são rejeitados em outro.
// ============================================================
const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'marinaone_secret_2025_change_me';

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
// Usa SHA-256 simples (compatibilidade com dados existentes).
// Para novos sistemas, troque por bcrypt — veja bcrypt.js na pasta utils.
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function verifyPassword(plain, hash) {
  // Compatibilidade: tenta SHA-256 direto
  return sha256(plain) === hash;
}

// ── Middleware de autenticação ────────────────────────────────────────
const PUBLIC_ROUTES = new Set(['/api/auth/login', '/api/version']);

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

module.exports = { jwtSign, jwtVerify, sha256, verifyPassword, authMiddleware };
