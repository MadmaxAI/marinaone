'use strict';
// ============================================================
//  Middleware de resolução de tenant
//
//  Estratégias (em ordem de prioridade):
//    1. Header X-Tenant-Slug (setado pelo NGINX/Cloudflare)
//    2. Subdomínio do Host: porto-belo.marinaone.com.br
//    3. Query string: ?tenant=porto-belo  (dev local only)
//    4. Env SINGLE_TENANT_SLUG (para deploy single-tenant)
// ============================================================
const { getGlobalPool } = require('../db/pool');

// Cache de tenants válidos (slug → tenant object)
const _tenantCache = new Map();
let _cacheTs = 0;
const CACHE_TTL = 60_000; // 1 minuto

async function loadTenantCache() {
  const now = Date.now();
  if (now - _cacheTs < CACHE_TTL) return;
  _cacheTs = now;

  try {
    const pool = getGlobalPool();
    const rows = await pool.unsafe(`SELECT id, slug, name, plan, active FROM saas.tenants`);
    _tenantCache.clear();
    for (const row of rows) {
      _tenantCache.set(row.slug, { ...row });
    }
  } catch (e) {
    // Schema saas pode não existir ainda na primeira inicialização
    console.warn('[tenant] Aviso: não foi possível carregar cache de tenants:', e.message);
  }
}

/**
 * Extrai o slug do tenant da requisição.
 * Retorna null se não conseguir determinar.
 */
function extractSlug(req) {
  // 1. Header explícito (definido pelo NGINX reverse proxy)
  const headerSlug = req.headers['x-tenant-slug'];
  if (headerSlug) return headerSlug.toLowerCase().trim();

  // 2. Modo single-tenant via variável de ambiente
  if (process.env.SINGLE_TENANT_SLUG) return process.env.SINGLE_TENANT_SLUG;

  // 3. Subdomínio: porto-belo.marinaone.com.br → porto-belo
  const host = (req.headers.host || '').split(':')[0].toLowerCase();
  const baseDomain = (process.env.BASE_DOMAIN || 'marinaone.com.br').toLowerCase();
  if (host !== baseDomain && host.endsWith(`.${baseDomain}`)) {
    return host.replace(`.${baseDomain}`, '');
  }

  // 4. Query string — permitido sempre (validado contra o banco de qualquer forma)
  //    Necessário no Railway sem domínio customizado e para testes
  const qs = new URLSearchParams((req.url || '').split('?')[1] || '');
  const qsSlug = qs.get('tenant');
  if (qsSlug) return qsSlug.toLowerCase().trim();

  return null;
}

/**
 * Middleware de tenant.
 * Resolve req.tenantSlug e req.tenant (objeto do banco).
 * Rotas super-admin (/api/superadmin/*) pulam esta resolução.
 * Rotas globais (/api/version, /api/superadmin/*) são liberadas sem tenant.
 */
async function tenantMiddleware(req, res, next) {
  // Rotas que não precisam de tenant
  const path = (req.url || '').split('?')[0];
  if (path === '/api/version' || path.startsWith('/api/superadmin')) {
    return next();
  }

  const slug = extractSlug(req);
  if (!slug) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Tenant não identificado. Use subdomínio ou header X-Tenant-Slug.' }));
  }

  // Valida contra o cache (ou banco)
  await loadTenantCache();
  const tenant = _tenantCache.get(slug);

  if (!tenant) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: `Marina '${slug}' não encontrada.` }));
  }

  if (!tenant.active) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: `Marina '${slug}' está inativa.` }));
  }

  req.tenantSlug = slug;
  req.tenant     = tenant;
  return next();
}

module.exports = { tenantMiddleware };
