'use strict';
// ============================================================
//  Marina One v2.0 — SaaS Multi-Tenant
//  Stack: Node.js 20+ | PostgreSQL | postgres.js
//  Arquitetura: schema-per-tenant (marina_<slug>)
// ============================================================
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

// ── Versão ───────────────────────────────────────────────────────────
const pkg         = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
const APP_VERSION = pkg.version || '2.0.0';
function _gitHash() {
  try { const { execSync } = require('child_process'); return execSync('git rev-parse --short HEAD', { encoding:'utf8', stdio:['pipe','pipe','ignore'] }).trim(); }
  catch { return null; }
}
const GIT_HASH   = _gitHash();
const BUILD_DATE = new Date().toISOString().slice(0, 10);

// ── DB / Middleware layers ────────────────────────────────────────────
const { initSaasSchema, runMigrations, provisionTenant, seedDefaultPermissions } = require('./src/db/migrate');
const { createDbHelpers, createSaasHelpers }  = require('./src/db/compat');
const { getTenantPool, getGlobalPool }         = require('./src/db/pool');
const { tenantMiddleware }                     = require('./src/middleware/tenant');
const { jwtSign, sha256, verifyPassword, authMiddleware } = require('./src/middleware/auth');

// ── Constantes ───────────────────────────────────────────────────────
const MODULES = [
  { key: 'dashboard',   label: 'Dashboard',         group: 'Principal' },
  { key: 'queue',       label: 'Fila de Operações', group: 'Principal' },
  { key: 'clients',     label: 'Clientes',          group: 'Gestão'    },
  { key: 'vessels',     label: 'Embarcações',       group: 'Gestão'    },
  { key: 'spots',       label: 'Vagas',             group: 'Gestão'    },
  { key: 'contracts',   label: 'Contratos',         group: 'Gestão'    },
  { key: 'financial',   label: 'Financeiro',        group: 'Operações' },
  { key: 'store',       label: 'Loja / PDV',        group: 'Operações' },
  { key: 'maintenance', label: 'Manutenção',        group: 'Operações' },
  { key: 'analytics',   label: 'Analytics',         group: 'Análise'   },
  { key: 'alerts',      label: 'Alertas',           group: 'Análise'   },
  { key: 'settings',    label: 'Configurações',     group: 'Sistema'   },
];
const MODULE_KEYS  = MODULES.map(m => m.key);
const VALID_ROLES  = ['admin', 'operador', 'loja', 'cliente'];

// ── HTTP helpers ─────────────────────────────────────────────────────
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Tenant-Slug');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
}
function sendJson(res, data, status = 200) {
  setCors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
function parseBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { resolve({}); }
    });
  });
}
function getQS(url) {
  const o = {};
  new URLSearchParams((url.split('?')[1] || '')).forEach((v, k) => { o[k] = v; });
  return o;
}

// ── Date helpers ─────────────────────────────────────────────────────
const _pad = n => String(n).padStart(2, '0');
const _localDate = (d = new Date()) => `${d.getFullYear()}-${_pad(d.getMonth()+1)}-${_pad(d.getDate())}`;
const _localDateTime = (d = new Date()) => `${_localDate(d)} ${_pad(d.getHours())}:${_pad(d.getMinutes())}:${_pad(d.getSeconds())}`;
const nowStr   = () => _localDateTime();
const todayStr = () => _localDate();
function monthStart() { const d = new Date(); d.setDate(1); return _localDate(d); }
function daysAgo(n)   { const d = new Date(); d.setDate(d.getDate() - n); return _localDate(d); }
function daysAhead(n) { const d = new Date(); d.setDate(d.getDate() + n); return _localDate(d); }

// ── PIX ──────────────────────────────────────────────────────────────
function crc16(data) {
  let crc = 0xFFFF;
  for (const b of Buffer.from(data, 'utf-8')) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}
function buildPix(key, name, city, amount, txid) {
  const sanitize = (s, max) => (s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^\x20-\x7E]/g,'').replace(/\s+/g,' ').trim().slice(0, max).toUpperCase();
  const tlv = (id, val) => `${id}${String(val.length).padStart(2,'0')}${val}`;
  const safeName = sanitize(name, 25) || 'LOJA', safeCity = sanitize(city, 15) || 'CIDADE';
  const safeTxid = (txid||'').replace(/[^A-Za-z0-9]/g,'').slice(0,25) || 'MARINA001';
  const ma = tlv('00','BR.GOV.BCB.PIX') + tlv('01', key);
  const ad = tlv('05', safeTxid);
  let p = tlv('00','01') + tlv('01','12') + tlv('26', ma) + tlv('52','0000') + tlv('53','986')
        + (amount > 0 ? tlv('54', amount.toFixed(2)) : '') + tlv('58','BR') + tlv('59', safeName) + tlv('60', safeCity) + tlv('62', ad);
  p += tlv('63', crc16(p + '6304'));
  return p;
}

// ── Router ───────────────────────────────────────────────────────────
const ROUTES = [];
function addRoute(method, pattern, fn) {
  const rx    = new RegExp('^' + pattern.replace(/:[^/]+/g, '([^/]+)') + '$');
  const names = [...pattern.matchAll(/:([^/]+)/g)].map(m => m[1]);
  ROUTES.push({ method, rx, names, fn });
}
function matchRoute(method, urlpath) {
  for (const r of ROUTES) {
    if (r.method !== method) continue;
    const m = urlpath.match(r.rx);
    if (!m) continue;
    const params = {};
    r.names.forEach((n, i) => { params[n] = m[i + 1]; });
    return { fn: r.fn, params };
  }
  return null;
}

// ── Helpers RBAC (usam ctx.db) ───────────────────────────────────────
async function can(user, module, action = 'view', dbGet) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const row = await dbGet('SELECT * FROM role_permissions WHERE role=? AND module=?', [user.role, module]);
  if (!row) return false;
  return row[`can_${action}`] === 1;
}
function requireRole(ctx, res, roles) {
  if (!ctx.user) { sendJson(res, { error: 'Não autorizado' }, 401); return false; }
  const arr = Array.isArray(roles) ? roles : [roles];
  if (!arr.includes(ctx.user.role)) { sendJson(res, { error: 'Acesso negado' }, 403); return false; }
  return true;
}
async function requirePerm(ctx, res, module, action = 'view') {
  if (!ctx.user) { sendJson(res, { error: 'Não autorizado' }, 401); return false; }
  if (!(await can(ctx.user, module, action, ctx.db.dbGet))) { sendJson(res, { error: 'Sem permissão' }, 403); return false; }
  return true;
}
function clientScope(user) {
  if (!user) return null;
  if (user.role === 'cliente') return user.client_id || -1;
  return null;
}
function canAccessClient(user, clientId) {
  if (!user) return false;
  if (user.role !== 'cliente') return true;
  return Number(user.client_id) === Number(clientId);
}
async function loadPermissions(role, dbGet) {
  if (role === 'admin') {
    const out = {};
    for (const m of MODULE_KEYS) out[m] = { view: true, create: true, edit: true, delete: true };
    return out;
  }
  const rows = await dbGet('SELECT * FROM role_permissions WHERE role=?', [role]);
  const out  = {};
  for (const m of MODULE_KEYS) out[m] = { view: false, create: false, edit: false, delete: false };
  // rows pode ser um único objeto (quando usa dbGet) — normaliza para array
  const arr  = Array.isArray(rows) ? rows : (rows ? [rows] : []);
  for (const r of arr) {
    out[r.module] = {
      view:   r.can_view   === 1,
      create: r.can_create === 1,
      edit:   r.can_edit   === 1,
      delete: r.can_delete === 1,
    };
  }
  return out;
}
async function loadPermissionsAll(role, dbAll) {
  if (role === 'admin') {
    const out = {};
    for (const m of MODULE_KEYS) out[m] = { view: true, create: true, edit: true, delete: true };
    return out;
  }
  const rows = await dbAll('SELECT * FROM role_permissions WHERE role=?', [role]);
  const out  = {};
  for (const m of MODULE_KEYS) out[m] = { view: false, create: false, edit: false, delete: false };
  for (const r of rows) {
    out[r.module] = {
      view:   r.can_view   === 1,
      create: r.can_create === 1,
      edit:   r.can_edit   === 1,
      delete: r.can_delete === 1,
    };
  }
  return out;
}

// ── Side effects (todos async agora) ────────────────────────────────
async function addAlert(type, message, severity, entity_type, entity_id, dbRun) {
  await dbRun('INSERT INTO alerts(type,message,severity,entity_type,entity_id) VALUES(?,?,?,?,?)',
              [type, message, severity || 'info', entity_type || null, entity_id || null]);
}
async function checkOverdue(dbRun) {
  await dbRun(`UPDATE financial_charges SET status='overdue' WHERE status='pending' AND due_date<?`, [todayStr()]);
}
async function recalcLtv(client_id, dbGet, dbRun) {
  const r = await dbGet(`SELECT COALESCE(SUM(amount),0) as t FROM financial_charges WHERE client_id=? AND status='paid'`, [client_id]);
  await dbRun('UPDATE clients SET ltv=? WHERE id=?', [r ? Number(r.t) : 0, client_id]);
}
async function checkStock(dbAll, dbAll2, dbGet, dbRun) {
  const low = await dbAll('SELECT * FROM store_items WHERE active=1 AND stock<=min_stock');
  for (const item of low) {
    const ex = await dbAll2(`SELECT id FROM alerts WHERE entity_type='store_item' AND entity_id=? AND read_at IS NULL`, [item.id]);
    if (!ex.length) await addAlert('estoque', `Estoque baixo: ${item.name} (${item.stock} ${item.unit})`, 'warning', 'store_item', item.id, dbRun);
  }
}
function getAvgDurationSync(settings, vesselSize, opType) {
  const settingKey = `avg_time_${opType}_${vesselSize || 'media'}`;
  const val = settings[settingKey];
  return val ? parseInt(val) || 30 : 30;
}

// ── syncClientUser (async) ────────────────────────────────────────────
async function syncClientUser(clientId, b, opts = {}, db) {
  const { dbGet, dbRun } = db;
  const { mode } = opts;
  const result = { created: false, updated: false, deactivated: false, warning: null, initialPassword: null };
  const existing = await dbGet(`SELECT * FROM users WHERE client_id=? AND role='cliente' LIMIT 1`, [clientId]);

  if (mode === 'delete') {
    if (existing) { await dbRun('UPDATE users SET active=0 WHERE id=?', [existing.id]); result.deactivated = true; }
    return result;
  }

  const email = (b.email || '').toLowerCase().trim();
  if (!email) { result.warning = 'Cliente sem e-mail: usuário de acesso não foi criado/atualizado.'; return result; }

  const conflict = await dbGet('SELECT id, client_id, role FROM users WHERE email=? AND id<>?',
                               [email, existing ? existing.id : -1]);
  if (conflict) {
    result.warning = `E-mail ${email} já está em uso por outro usuário (${conflict.role}). Usuário de acesso não sincronizado.`;
    return result;
  }

  if (existing) {
    await dbRun('UPDATE users SET name=?, email=?, active=1 WHERE id=?', [b.name, email, existing.id]);
    result.updated = true;
  } else {
    const cpfDigits    = String(b.cpf || '').replace(/\D/g, '');
    const initialPwd   = cpfDigits.length >= 6 ? cpfDigits : 'cliente@123';
    await dbRun('INSERT INTO users(email,password_hash,name,role,client_id,active) VALUES(?,?,?,?,?,1)',
                [email, sha256(initialPwd), b.name, 'cliente', clientId]);
    result.created = true;
    result.initialPassword = initialPwd;
  }
  return result;
}

// ── isVesselInWater (async) ───────────────────────────────────────────
async function isVesselInWater(vesselId, spotType, dbGet) {
  const lastOp = await dbGet(`SELECT operation_type FROM queue_operations WHERE vessel_id=? AND status='completed' ORDER BY completed_at DESC LIMIT 1`, [vesselId]);
  const t = lastOp?.operation_type;
  if (t === 'descida' || t === 'atracacao') return true;
  if (t === 'subida') return false;
  return spotType === 'molhada';
}
async function vesselStatus(vesselId, spotType, dbGet) {
  const inWater = await isVesselInWater(vesselId, spotType, dbGet);
  if (inWater) return spotType === 'molhada' ? 'Na vaga molhada' : 'Na água';
  return spotType === 'seca' ? 'Na vaga seca' : 'Em terra';
}
async function enrichQueueRow(q, settings, dbGet) {
  const spot     = await dbGet(`SELECT s.type FROM spots s JOIN contracts ct ON ct.spot_id=s.id WHERE ct.vessel_id=? AND ct.status='active'`, [q.vessel_id]);
  const spotType = spot?.type || null;
  const inWater  = await isVesselInWater(q.vessel_id, spotType, dbGet);
  const vs       = await vesselStatus(q.vessel_id, spotType, dbGet);
  let inconsistent = false;
  if (q.status === 'waiting' || q.status === 'in_progress') {
    if (q.operation_type === 'descida' && inWater)  inconsistent = true;
    if (q.operation_type === 'subida'  && !inWater) inconsistent = true;
  }
  const estimated_duration_min = getAvgDurationSync(settings, q.vessel_size, q.operation_type);
  return { ...q, vessel_status: vs, is_inconsistent: inconsistent, estimated_duration_min };
}
function applyEstimatedTimes(enriched, maneuver) {
  const now = new Date();
  let cursor = new Date(now);
  const inProg = enriched.find(r => r.status === 'in_progress');
  if (inProg && inProg.started_at) {
    const endTime = new Date(String(inProg.started_at).replace(' ', 'T'));
    endTime.setMinutes(endTime.getMinutes() + inProg.estimated_duration_min);
    if (isNaN(endTime) || endTime < now) endTime.setTime(now.getTime());
    inProg.estimated_end_at = endTime.toISOString();
    cursor = new Date(endTime);
    cursor.setMinutes(cursor.getMinutes() + maneuver);
  }
  for (const row of enriched) {
    if (row.status === 'in_progress') continue;
    if (row.status === 'waiting') {
      row.estimated_start_at = cursor.toISOString();
      const end = new Date(cursor);
      end.setMinutes(end.getMinutes() + row.estimated_duration_min);
      row.estimated_end_at = end.toISOString();
      cursor = new Date(end);
      cursor.setMinutes(cursor.getMinutes() + maneuver);
    }
  }
}
async function getSettings(dbAll) {
  const rows = await dbAll('SELECT key, value FROM settings');
  const obj  = {};
  rows.forEach(r => { obj[r.key] = r.value; });
  return obj;
}
function getManeuverTime(settings) {
  const val = settings['maneuver_time_min'];
  return val ? parseInt(val) || 0 : 0;
}

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — VERSION (pública, sem tenant)
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/version', (req, res) => {
  sendJson(res, {
    version:     APP_VERSION,
    git_hash:    GIT_HASH,
    build_date:  BUILD_DATE,
    node:        process.version,
    uptime_sec:  Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'production',
    saas:        true,
  });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — SUPER-ADMIN (/api/superadmin/*)
// ═════════════════════════════════════════════════════════════════════
const { saasAll, saasGet, saasRun } = createSaasHelpers();

addRoute('POST', '/api/superadmin/auth/login', async (req, res, ctx) => {
  const { email = '', password = '' } = ctx.body;
  const admin = await saasGet('SELECT * FROM saas.super_admins WHERE email=$1', [email.toLowerCase()]);
  if (!admin || !verifyPassword(password, admin.password_hash))
    return sendJson(res, { error: 'Credenciais inválidas' }, 401);
  const token = jwtSign({ super_admin_id: admin.id, email: admin.email, name: admin.name, role: 'superadmin' }, 86400);
  sendJson(res, { token, admin: { id: admin.id, name: admin.name, email: admin.email } });
});

function requireSuperAdmin(ctx, res) {
  if (!ctx.user || ctx.user.role !== 'superadmin') {
    sendJson(res, { error: 'Acesso restrito ao super-admin' }, 403);
    return false;
  }
  return true;
}

addRoute('GET', '/api/superadmin/tenants', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const tenants = await saasAll('SELECT * FROM saas.tenants ORDER BY created_at DESC');
  sendJson(res, tenants);
});

addRoute('POST', '/api/superadmin/tenants', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { slug, name, plan, adminEmail, adminPassword, adminName, spots_seca, spots_molhada, logo_base64 } = ctx.body || {};
  if (!slug || !name) return sendJson(res, { error: 'slug e name são obrigatórios' }, 400);
  const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-');
  const finalAdminEmail    = adminEmail    || `admin@${cleanSlug}.marina`;
  const finalAdminPassword = adminPassword || 'marina123';
  try {
    await provisionTenant(cleanSlug, {
      marinaName: name, plan: plan || 'professional',
      adminEmail: finalAdminEmail,
      adminPassword: finalAdminPassword,
      adminName: adminName || 'Administrador',
      spots_seca:   parseInt(spots_seca   || 0, 10),
      spots_molhada: parseInt(spots_molhada || 0, 10),
      logo_base64: logo_base64 || '',
    });
    // Salva credenciais do admin na tabela saas para consulta posterior
    await saasRun(
      `UPDATE saas.tenants SET admin_email=$1, admin_password_plain=$2 WHERE slug=$3`,
      [finalAdminEmail, finalAdminPassword, cleanSlug]
    );
    const tenant = await saasGet('SELECT * FROM saas.tenants WHERE slug=$1', [cleanSlug]);
    sendJson(res, { ok: true, tenant }, 201);
  } catch (e) {
    sendJson(res, { error: e.message }, 500);
  }
});

addRoute('GET', '/api/superadmin/tenants/:slug/credentials', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const slug = ctx.params.slug;
  const row = await saasGet(
    `SELECT admin_email, admin_password_plain FROM saas.tenants WHERE slug=$1`,
    [slug]
  );
  if (!row) return sendJson(res, { error: 'Tenant não encontrado' }, 404);

  let email    = row.admin_email         || '';
  let password = row.admin_password_plain || '';

  // Fallback: busca admin direto na schema do tenant quando não há credenciais salvas
  if (!email) {
    try {
      const { dbGet } = createDbHelpers(slug);
      const admin = await dbGet(
        "SELECT email FROM users WHERE role='admin' ORDER BY id LIMIT 1", []
      );
      if (admin) email = admin.email;
    } catch {}
  }

  // Persiste o e-mail encontrado para não buscar novamente
  if (email && !row.admin_email) {
    await saasRun(
      'UPDATE saas.tenants SET admin_email=$1 WHERE slug=$2',
      [email, slug]
    ).catch(() => {});
  }

  sendJson(res, {
    admin_email:    email,
    admin_password: password,
  });
});

addRoute('PUT', '/api/superadmin/tenants/:slug', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { name, plan, active } = ctx.body || {};
  await saasRun(
    'UPDATE saas.tenants SET name=COALESCE($1,name), plan=COALESCE($2,plan), active=COALESCE($3,active) WHERE slug=$4',
    [name||null, plan||null, active !== undefined ? active : null, ctx.params.slug]
  );
  sendJson(res, { ok: true });
});

addRoute('POST', '/api/superadmin/tenants/:slug/reset-admin-password', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const slug = ctx.params.slug;
  const { email, new_password } = ctx.body || {};
  if (!new_password || new_password.length < 6)
    return sendJson(res, { error: 'Senha deve ter pelo menos 6 caracteres' }, 400);
  try {
    const { dbRun: tRun, dbGet: tGet } = createDbHelpers(slug);
    // Se e-mail fornecido, reseta só esse admin; senão, o primeiro admin
    const user = email
      ? await tGet('SELECT id FROM users WHERE email=? AND role=?', [email.toLowerCase(), 'admin'])
      : await tGet("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1", []);
    if (!user) return sendJson(res, { error: 'Admin não encontrado' }, 404);
    await tRun('UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?',
               [sha256(new_password), user.id]);
    // Persiste nova senha no registro saas
    await saasRun(
      'UPDATE saas.tenants SET admin_password_plain=$1 WHERE slug=$2',
      [new_password, slug]
    );
    sendJson(res, { ok: true });
  } catch (e) {
    sendJson(res, { error: e.message }, 500);
  }
});

addRoute('PUT', '/api/superadmin/tenants/:slug/logo', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { logo_base64 = '' } = ctx.body || {};
  try {
    const { dbRun: tRun } = createDbHelpers(ctx.params.slug);
    await tRun(
      `INSERT INTO settings(key,value) VALUES('marina_logo',?)
       ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,
      [logo_base64]
    );
    sendJson(res, { ok: true });
  } catch (e) {
    sendJson(res, { error: e.message }, 500);
  }
});

addRoute('GET', '/api/superadmin/tenants/:slug/stats', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { dbAll: tAll, dbGet: tGet } = createDbHelpers(ctx.params.slug);
    const ms = monthStart();
    const [clients, vessels, users, revenue, revenue_month,
           contracts, spots_seca, spots_molhada, settings_rows] = await Promise.all([
      tGet('SELECT COUNT(*) as n FROM clients WHERE active=1'),
      tGet('SELECT COUNT(*) as n FROM vessels WHERE active=1'),
      tGet('SELECT COUNT(*) as n FROM users WHERE active=1'),
      tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid'`),
      tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`, [ms]),
      tGet(`SELECT COUNT(*) as n FROM contracts WHERE status='active'`),
      tGet(`SELECT COUNT(*) as n FROM spots WHERE type='seca'`),
      tGet(`SELECT COUNT(*) as n FROM spots WHERE type='molhada'`),
      tAll(`SELECT key, value FROM settings WHERE key IN ('marina_logo','marina_name','marina_email','marina_phone','marina_cnpj','marina_city','marina_state','license_plan','license_valid_until')`),
    ]);
    const sett = {};
    for (const r of (settings_rows || [])) sett[r.key] = r.value;
    sendJson(res, {
      slug:            ctx.params.slug,
      clients:         Number(clients?.n       || 0),
      vessels:         Number(vessels?.n       || 0),
      users:           Number(users?.n         || 0),
      contracts:       Number(contracts?.n     || 0),
      spots_seca:      Number(spots_seca?.n    || 0),
      spots_molhada:   Number(spots_molhada?.n || 0),
      revenue:         Number(revenue?.v       || 0),
      revenue_month:   Number(revenue_month?.v || 0),
      marina_logo:     sett.marina_logo    || '',
      marina_name:     sett.marina_name    || '',
      marina_email:    sett.marina_email   || '',
      marina_phone:    sett.marina_phone   || '',
      marina_cnpj:     sett.marina_cnpj    || '',
      marina_city:     sett.marina_city    || '',
      marina_state:    sett.marina_state   || '',
      license_plan:    sett.license_plan   || '',
      license_until:   sett.license_valid_until || '',
    });
  } catch (e) {
    sendJson(res, { error: e.message }, 500);
  }
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — AUTH (por tenant)
// ═════════════════════════════════════════════════════════════════════
addRoute('POST', '/api/auth/login', async (req, res, ctx) => {
  const { email = '', password = '' } = ctx.body;
  const { dbGet: tGet, dbAll: tAll } = ctx.db;
  const user = await tGet('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
  if (!user || !verifyPassword(password, user.password_hash))
    return sendJson(res, { error: 'Credenciais inválidas' }, 401);
  if (user.active === 0) return sendJson(res, { error: 'Usuário desativado' }, 403);
  const permissions = await loadPermissionsAll(user.role, tAll);
  const mustChange = user.must_change_password === 1 || user.must_change_password === true;
  const token = jwtSign({
    user_id:     user.id,
    email:       user.email,
    name:        user.name,
    role:        user.role,
    client_id:   user.client_id || null,
    tenant_id:   ctx.tenant?.id,
    tenant_slug: ctx.tenantSlug,
  });
  sendJson(res, { token, must_change_password: mustChange, user: { id: user.id, name: user.name, email: user.email, role: user.role, client_id: user.client_id || null, permissions } });
});

// ── Esqueci minha senha — reset para o CPF do usuário ──────────────
addRoute('POST', '/api/auth/forgot-password', async (req, res, ctx) => {
  const { email = '', cpf = '' } = ctx.body || {};
  const { dbGet: tGet, dbRun: tRun } = ctx.db;

  const cleanCpf = cpf.replace(/\D/g, '');
  if (!email || cleanCpf.length < 11)
    return sendJson(res, { error: 'Informe e-mail e CPF válido (11 dígitos)' }, 400);

  const user = await tGet('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
  if (!user) return sendJson(res, { error: 'E-mail não encontrado' }, 404);

  // Salva o CPF no usuário (se ainda não tiver) e reseta a senha
  await tRun(
    'UPDATE users SET password_hash=?, must_change_password=1, cpf=COALESCE(NULLIF(cpf,\'\'), ?) WHERE id=?',
    [sha256(cleanCpf), cleanCpf, user.id]
  );
  sendJson(res, { ok: true, message: 'Senha redefinida para o seu CPF (somente números). Troque após o login.' });
});

// ── Trocar senha obrigatória ─────────────────────────────────────────
addRoute('POST', '/api/auth/change-password', async (req, res, ctx) => {
  const { new_password = '' } = ctx.body || {};
  if (new_password.length < 6)
    return sendJson(res, { error: 'Nova senha deve ter pelo menos 6 caracteres' }, 400);
  const { dbRun: tRun } = ctx.db;
  await tRun(
    'UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?',
    [sha256(new_password), ctx.user.user_id]
  );
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/auth/me', async (req, res, ctx) => {
  const { dbAll: tAll } = ctx.db;
  const permissions = await loadPermissionsAll(ctx.user.role, tAll);
  sendJson(res, { ...ctx.user, permissions });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — CONTROLE DE ACESSO
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/access/modules', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  sendJson(res, MODULES);
});

addRoute('GET', '/api/access/permissions', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { dbAll: tAll } = ctx.db;
  const out = {};
  for (const role of VALID_ROLES) out[role] = await loadPermissionsAll(role, tAll);
  sendJson(res, { roles: VALID_ROLES, modules: MODULES, permissions: out });
});

addRoute('PUT', '/api/access/permissions', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { role, module, can_view, can_create, can_edit, can_delete } = ctx.body || {};
  if (!VALID_ROLES.includes(role))    return sendJson(res, { error: 'Role inválido' }, 400);
  if (role === 'admin')               return sendJson(res, { error: 'Não é permitido alterar permissões do admin' }, 400);
  if (!MODULE_KEYS.includes(module))  return sendJson(res, { error: 'Módulo inválido' }, 400);
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const v = can_view?1:0, cr = can_create?1:0, e = can_edit?1:0, d = can_delete?1:0;
  const exists = await tGet('SELECT 1 FROM role_permissions WHERE role=? AND module=?', [role, module]);
  if (exists) {
    await tRun('UPDATE role_permissions SET can_view=?,can_create=?,can_edit=?,can_delete=? WHERE role=? AND module=?',
               [v, cr, e, d, role, module]);
  } else {
    await tRun('INSERT INTO role_permissions(role,module,can_view,can_create,can_edit,can_delete) VALUES(?,?,?,?,?,?)',
               [role, module, v, cr, e, d]);
  }
  await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
             [ctx.user.user_id, ctx.user.name, 'update_permissions', `${role}/${module}: v=${v} c=${cr} e=${e} d=${d}`]);
  sendJson(res, { ok: true });
});

addRoute('POST', '/api/access/permissions/reset', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const pool = getTenantPool(ctx.tenantSlug);
  await pool.unsafe(`DELETE FROM role_permissions WHERE role IN ('operador','loja','cliente')`);
  await seedDefaultPermissions(pool);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — USUÁRIOS
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/users', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { dbAll: tAll } = ctx.db;
  const rows = await tAll(`SELECT u.id,u.email,u.name,u.role,u.client_id,u.active,c.name as client_name
    FROM users u LEFT JOIN clients c ON u.client_id=c.id ORDER BY u.role, u.name`);
  sendJson(res, rows);
});

addRoute('POST', '/api/users', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const b = ctx.body || {};
  if (!b.email || !b.name || !b.password || !b.role)
    return sendJson(res, { error: 'Campos obrigatórios: email, name, password, role' }, 400);
  if (!VALID_ROLES.includes(b.role)) return sendJson(res, { error: 'Role inválido' }, 400);
  if (b.role === 'cliente' && !b.client_id)
    return sendJson(res, { error: 'Usuário do tipo cliente precisa de client_id' }, 400);
  const { dbRun: tRun } = ctx.db;
  try {
    const r = await tRun('INSERT INTO users(email,password_hash,name,role,client_id,active) VALUES(?,?,?,?,?,1)',
      [String(b.email).toLowerCase(), sha256(b.password), b.name, b.role, b.role==='cliente' ? b.client_id : null]);
    await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
               [ctx.user.user_id, ctx.user.name, 'create_user', `${b.email} (${b.role})`]);
    sendJson(res, { id: r.lastInsertRowid }, 201);
  } catch (e) {
    sendJson(res, { error: 'E-mail já cadastrado ou dados inválidos' }, 400);
  }
});

addRoute('PUT', '/api/users/:id', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const b = ctx.body || {};
  const id = Number(ctx.params.id);
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const u = await tGet('SELECT * FROM users WHERE id=?', [id]);
  if (!u) return sendJson(res, { error: 'Usuário não encontrado' }, 404);
  if (u.role === 'admin' && b.role && b.role !== 'admin') {
    const n = await tGet(`SELECT COUNT(*) as n FROM users WHERE role='admin' AND active=1`);
    if (Number(n?.n) <= 1) return sendJson(res, { error: 'Não pode remover o último administrador' }, 400);
  }
  const role = b.role && VALID_ROLES.includes(b.role) ? b.role : u.role;
  const cid  = role === 'cliente' ? (b.client_id || u.client_id) : null;
  const act  = b.active === undefined ? u.active : (b.active ? 1 : 0);
  await tRun('UPDATE users SET name=?,email=?,role=?,client_id=?,active=? WHERE id=?',
             [b.name || u.name, (b.email || u.email).toLowerCase(), role, cid, act, id]);
  if (b.password) await tRun('UPDATE users SET password_hash=? WHERE id=?', [sha256(b.password), id]);
  await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
             [ctx.user.user_id, ctx.user.name, 'update_user', `#${id}`]);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/users/:id', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const id = Number(ctx.params.id);
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const u = await tGet('SELECT * FROM users WHERE id=?', [id]);
  if (!u) return sendJson(res, { error: 'Usuário não encontrado' }, 404);
  if (u.role === 'admin') {
    const n = await tGet(`SELECT COUNT(*) as n FROM users WHERE role='admin' AND active=1`);
    if (Number(n?.n) <= 1) return sendJson(res, { error: 'Não pode excluir o último administrador' }, 400);
  }
  if (id === ctx.user.user_id) return sendJson(res, { error: 'Não pode excluir a si mesmo' }, 400);
  await tRun('DELETE FROM users WHERE id=?', [id]);
  await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
             [ctx.user.user_id, ctx.user.name, 'delete_user', `#${id} ${u.email}`]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — CLIENTES
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/clients', async (req, res, ctx) => {
  const { search = '', tier = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = `SELECT c.*,
    (SELECT COUNT(*) FROM vessels WHERE client_id=c.id AND active=1) as vessel_count,
    (SELECT u.id    FROM users u WHERE u.client_id=c.id AND u.role='cliente' LIMIT 1) as user_id,
    (SELECT u.email FROM users u WHERE u.client_id=c.id AND u.role='cliente' LIMIT 1) as user_email,
    (SELECT u.name  FROM users u WHERE u.client_id=c.id AND u.role='cliente' LIMIT 1) as user_name,
    (SELECT u.active FROM users u WHERE u.client_id=c.id AND u.role='cliente' LIMIT 1) as user_active
    FROM clients c WHERE c.active=1`;
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null) { sql += ' AND c.id=?'; a.push(scope); }
  if (search) { sql += ' AND (c.name LIKE ? OR c.email LIKE ? OR c.cpf LIKE ?)'; a.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (tier)   { sql += ' AND c.tier=?'; a.push(tier); }
  sendJson(res, await tAll(sql + ' ORDER BY c.name', a));
});

addRoute('GET', '/api/clients/:id', async (req, res, ctx) => {
  if (!canAccessClient(ctx.user, ctx.params.id)) return sendJson(res, { error: 'Sem permissão' }, 403);
  const { dbGet: tGet, dbAll: tAll } = ctx.db;
  const c = await tGet('SELECT * FROM clients WHERE id=?', [ctx.params.id]);
  if (!c) return sendJson(res, { error: 'Não encontrado' }, 404);
  c.vessels   = await tAll('SELECT * FROM vessels WHERE client_id=? AND active=1', [ctx.params.id]);
  c.contracts = await tAll('SELECT ct.*, s.number as spot_number FROM contracts ct LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.client_id=?', [ctx.params.id]);
  c.charges   = await tAll('SELECT * FROM financial_charges WHERE client_id=? ORDER BY due_date DESC LIMIT 10', [ctx.params.id]);
  c.user      = await tGet(`SELECT id,email,name,role,active FROM users WHERE client_id=? AND role='cliente' LIMIT 1`, [ctx.params.id]) || null;
  sendJson(res, c);
});

addRoute('POST', '/api/clients', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbRun: tRun } = ctx.db;
  const r = await tRun('INSERT INTO clients(name,email,phone,cpf,tier,address,notes) VALUES(?,?,?,?,?,?,?)',
                       [b.name, b.email, b.phone, b.cpf, b.tier || 'standard', b.address, b.notes]);
  const id   = r.lastInsertRowid;
  const sync = await syncClientUser(id, b, { mode: 'create' }, ctx.db);
  await addAlert('sistema', `Novo cliente: ${b.name}${sync.created ? ' (usuário de acesso criado)' : ''}`, 'info', null, null, tRun);
  if (sync.created) {
    await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
               [ctx.user.user_id, ctx.user.name, 'auto_create_user', `cliente=${b.name} email=${b.email}`]);
  }
  sendJson(res, { id, user_created: sync.created, initial_password: sync.initialPassword, warning: sync.warning }, 201);
});

addRoute('PUT', '/api/clients/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  await tRun('UPDATE clients SET name=?,email=?,phone=?,cpf=?,tier=?,address=?,notes=? WHERE id=?',
             [b.name, b.email, b.phone, b.cpf, b.tier || 'standard', b.address, b.notes, ctx.params.id]);
  await recalcLtv(ctx.params.id, tGet, tRun);
  const sync = await syncClientUser(Number(ctx.params.id), b, { mode: 'update' }, ctx.db);
  if (sync.created) {
    await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
               [ctx.user.user_id, ctx.user.name, 'auto_create_user', `cliente=${b.name}`]);
  }
  sendJson(res, { ok: true, user_created: sync.created, user_updated: sync.updated, warning: sync.warning });
});

addRoute('DELETE', '/api/clients/:id', async (req, res, ctx) => {
  const { dbRun: tRun } = ctx.db;
  await tRun('UPDATE clients SET active=0 WHERE id=?', [ctx.params.id]);
  const sync = await syncClientUser(Number(ctx.params.id), {}, { mode: 'delete' }, ctx.db);
  sendJson(res, { ok: true, user_deactivated: sync.deactivated });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — EMBARCAÇÕES
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/vessels', async (req, res, ctx) => {
  const { search = '', client_id = '', eligible_for = '' } = ctx.qs;
  const { dbAll: tAll, dbGet: tGet } = ctx.db;
  let sql = `SELECT v.*, c.name as client_name, c.tier as client_tier, s.number as spot_number, s.type as spot_type
    FROM vessels v JOIN clients c ON v.client_id=c.id
    LEFT JOIN contracts ct ON ct.vessel_id=v.id AND ct.status='active'
    LEFT JOIN spots s ON ct.spot_id=s.id WHERE v.active=1`;
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null) { sql += ' AND v.client_id=?'; a.push(scope); }
  else if (client_id) { sql += ' AND v.client_id=?'; a.push(client_id); }
  if (search)         { sql += ' AND (v.name LIKE ? OR v.registration LIKE ? OR c.name LIKE ?)'; a.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  let rows = await tAll(sql + ' ORDER BY v.name', a);
  rows = await Promise.all(rows.map(async r => ({ ...r, vessel_status: await vesselStatus(r.id, r.spot_type, tGet) })));
  if (eligible_for === 'descida') {
    rows = (await Promise.all(rows.map(async r => ({ r, ok: !(await isVesselInWater(r.id, r.spot_type, tGet)) })))).filter(x=>x.ok).map(x=>x.r);
    rows = (await Promise.all(rows.map(async r => ({ r, ok: !(await tGet(`SELECT id FROM queue_operations WHERE vessel_id=? AND status IN ('waiting','in_progress')`, [r.id])) })))).filter(x=>x.ok).map(x=>x.r);
  } else if (eligible_for === 'subida') {
    rows = (await Promise.all(rows.map(async r => ({ r, ok: await isVesselInWater(r.id, r.spot_type, tGet) })))).filter(x=>x.ok).map(x=>x.r);
    rows = (await Promise.all(rows.map(async r => ({ r, ok: !(await tGet(`SELECT id FROM queue_operations WHERE vessel_id=? AND status IN ('waiting','in_progress')`, [r.id])) })))).filter(x=>x.ok).map(x=>x.r);
  } else if (eligible_for === 'atracacao') {
    rows = (await Promise.all(rows.map(async r => ({ r, ok: !(await tGet(`SELECT id FROM queue_operations WHERE vessel_id=? AND status IN ('waiting','in_progress')`, [r.id])) })))).filter(x=>x.ok).map(x=>x.r);
  }
  sendJson(res, rows);
});

addRoute('GET', '/api/vessels/:id', async (req, res, ctx) => {
  const { dbGet: tGet, dbAll: tAll } = ctx.db;
  const v = await tGet(`SELECT v.*, c.name as client_name, s.type as spot_type FROM vessels v JOIN clients c ON v.client_id=c.id LEFT JOIN contracts ct ON ct.vessel_id=v.id AND ct.status='active' LEFT JOIN spots s ON ct.spot_id=s.id WHERE v.id=?`, [ctx.params.id]);
  if (!v) return sendJson(res, { error: 'Não encontrado' }, 404);
  v.vessel_status = await vesselStatus(v.id, v.spot_type, tGet);
  v.history       = await tAll(`SELECT * FROM queue_operations WHERE vessel_id=? ORDER BY requested_at DESC LIMIT 20`, [ctx.params.id]);
  v.maintenance   = await tAll(`SELECT * FROM maintenance_os WHERE vessel_id=? ORDER BY created_at DESC LIMIT 10`, [ctx.params.id]);
  v.contract      = await tGet(`SELECT ct.*, s.number as spot_number FROM contracts ct LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.vessel_id=? AND ct.status='active'`, [ctx.params.id]);
  // Vaga atribuída diretamente (via spots.vessel_id — fonte da verdade)
  v.direct_spot   = await tGet(`SELECT * FROM spots WHERE vessel_id=?`, [ctx.params.id]);
  sendJson(res, v);
});

addRoute('POST', '/api/vessels', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbRun: tRun } = ctx.db;
  const r = await tRun(
    `INSERT INTO vessels(client_id,name,type,size,length,beam,draft,year,registration,model,manufacturer,engine,notes,
      photo,available_for_rental,rental_passengers,rental_sailor,rental_days,rental_hours_start,rental_hours_end,
      rental_price_4h,rental_price_6h,rental_price_8h,rental_notes)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [b.client_id, b.name, b.type, b.size||'media', b.length||null, b.beam||null, b.draft||null, b.year||null,
     b.registration||'', b.model||'', b.manufacturer||'', b.engine||'', b.notes||'',
     b.photo||null, b.available_for_rental?1:0, b.rental_passengers||null, b.rental_sailor||1,
     b.rental_days||null, b.rental_hours_start||null, b.rental_hours_end||null,
     b.rental_price_4h||null, b.rental_price_6h||null, b.rental_price_8h||null, b.rental_notes||'']
  );
  sendJson(res, { id: r.lastInsertRowid }, 201);
});

addRoute('PUT', '/api/vessels/:id', async (req, res, ctx) => {
  const b = ctx.body;
  if (!b.name) return sendJson(res, { error: 'Nome obrigatório' }, 400);
  const { dbRun: tRun } = ctx.db;
  await tRun(
    `UPDATE vessels SET name=?,client_id=?,type=?,size=?,length=?,beam=?,draft=?,year=?,registration=?,model=?,
      manufacturer=?,engine=?,notes=?,photo=?,available_for_rental=?,rental_passengers=?,rental_sailor=?,
      rental_days=?,rental_hours_start=?,rental_hours_end=?,rental_price_4h=?,rental_price_6h=?,rental_price_8h=?,
      rental_notes=? WHERE id=?`,
    [b.name, b.client_id||null, b.type, b.size||'media', b.length||null, b.beam||null, b.draft||null, b.year||null,
     b.registration||'', b.model||'', b.manufacturer||'', b.engine||'', b.notes||'',
     b.photo||null, b.available_for_rental?1:0, b.rental_passengers||null, b.rental_sailor||1,
     b.rental_days||null, b.rental_hours_start||null, b.rental_hours_end||null,
     b.rental_price_4h||null, b.rental_price_6h||null, b.rental_price_8h||null, b.rental_notes||'',
     ctx.params.id]
  );
  sendJson(res, { ok: true });
});

// ── Atribuição direta de vaga a embarcação (admin) ───────────────────
addRoute('PUT', '/api/vessels/:id/spot', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const vesselId = ctx.params.id;
  const { spot_id } = ctx.body; // null = desatribuir

  if (!spot_id) {
    // DESATRIBUIR — libera a vaga atual da embarcação
    const curSpot = await tGet('SELECT * FROM spots WHERE vessel_id=?', [vesselId]);
    if (!curSpot) return sendJson(res, { ok: true }); // já sem vaga
    // Bloqueia se há contrato ativo vinculando esta vaga
    const activeContract = await tGet(
      `SELECT id FROM contracts WHERE spot_id=? AND status='active'`, [curSpot.id]);
    if (activeContract)
      return sendJson(res, { error: 'Esta vaga possui contrato ativo. Cancele o contrato antes de desatribuir a vaga.' }, 400);
    await tRun(`UPDATE spots SET status='available', vessel_id=NULL WHERE id=?`, [curSpot.id]);
    return sendJson(res, { ok: true });
  }

  // ATRIBUIR — valida e ocupa a vaga
  const spot = await tGet('SELECT * FROM spots WHERE id=?', [spot_id]);
  if (!spot) return sendJson(res, { error: 'Vaga não encontrada' }, 404);
  if (spot.vessel_id && String(spot.vessel_id) !== String(vesselId))
    return sendJson(res, { error: `Vaga ${spot.number} já está ocupada por outra embarcação.` }, 400);

  // Embarcação já tem outra vaga? Desatribui automaticamente antes de atribuir a nova
  const existing = await tGet('SELECT * FROM spots WHERE vessel_id=? AND id!=?', [vesselId, spot_id]);
  if (existing) {
    const activeContract = await tGet(
      `SELECT id FROM contracts WHERE spot_id=? AND status='active'`, [existing.id]);
    if (activeContract)
      return sendJson(res, { error: `A vaga atual ${existing.number} possui contrato ativo. Cancele o contrato antes de trocar de vaga.` }, 400);
    // Libera a vaga anterior automaticamente
    await tRun(`UPDATE spots SET status='available', vessel_id=NULL WHERE id=?`, [existing.id]);
  }

  await tRun(`UPDATE spots SET status='occupied', vessel_id=? WHERE id=?`, [vesselId, spot_id]);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/vessels/:id', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE vessels SET active=0 WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — VAGAS
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/spots/summary', async (req, res, ctx) => {
  const { dbAll: tAll } = ctx.db;
  const rows = await tAll('SELECT type, status, COUNT(*) as count FROM spots GROUP BY type, status');
  const r = { seca: { total:0,available:0,occupied:0,maintenance:0 }, molhada: { total:0,available:0,occupied:0,maintenance:0 } };
  for (const row of rows) {
    r[row.type].total += Number(row.count);
    if (row.status in r[row.type]) r[row.type][row.status] += Number(row.count);
  }
  sendJson(res, r);
});

addRoute('GET', '/api/spots', async (req, res, ctx) => {
  const { type = '', status = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT s.*, v.name as vessel_name, c.name as client_name FROM spots s LEFT JOIN vessels v ON s.vessel_id=v.id LEFT JOIN clients c ON v.client_id=c.id WHERE 1=1';
  const a = [];
  if (type)   { sql += ' AND s.type=?';   a.push(type); }
  if (status) { sql += ' AND s.status=?'; a.push(status); }
  sendJson(res, await tAll(sql + ' ORDER BY s.number', a));
});

addRoute('POST', '/api/spots', async (req, res, ctx) => {
  const b = ctx.body;
  if (!b.number || !b.type) return sendJson(res, { error: 'Número e tipo obrigatórios' }, 400);
  const r = await ctx.db.dbRun('INSERT INTO spots(number,type,status) VALUES(?,?,?)', [b.number, b.type, 'available']);
  sendJson(res, { id: r.lastInsertRowid }, 201);
});

addRoute('POST', '/api/spots/batch', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { prefix = '', start, end, type, padding = 2 } = ctx.body || {};
  const s = parseInt(start, 10), e = parseInt(end, 10);
  if (!type || isNaN(s) || isNaN(e) || s < 1 || e < s)
    return sendJson(res, { error: 'Parâmetros inválidos: tipo, início e fim são obrigatórios e início ≤ fim' }, 400);
  if ((e - s + 1) > 500)
    return sendJson(res, { error: 'Máximo de 500 vagas por lote' }, 400);

  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  let created = 0, skipped = 0;
  const pad = parseInt(padding, 10) || 2;

  for (let i = s; i <= e; i++) {
    const number = prefix + String(i).padStart(pad, '0');
    const exists = await tGet('SELECT 1 FROM spots WHERE number=?', [number]);
    if (exists) { skipped++; continue; }
    await tRun('INSERT INTO spots(number,type,status) VALUES(?,?,?)', [number, type, 'available']);
    created++;
  }
  sendJson(res, { ok: true, created, skipped }, 201);
});

addRoute('PUT', '/api/spots/:id', async (req, res, ctx) => {
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const spot = await tGet('SELECT * FROM spots WHERE id=?', [ctx.params.id]);
  if (!spot) return sendJson(res, { error: 'Vaga não encontrada' }, 404);
  const newStatus = ctx.body.status;

  // Regras de negócio:
  // 'occupied' só via rota /vessels/:id/spot — nunca manualmente
  if (newStatus === 'occupied')
    return sendJson(res, { error: 'Status "ocupado" só pode ser definido ao atribuir uma embarcação à vaga.' }, 400);
  // Não pode liberar vaga que tem embarcação atribuída
  if (newStatus === 'available' && spot.vessel_id)
    return sendJson(res, { error: 'A vaga possui embarcação atribuída. Desatribua a embarcação antes de liberar a vaga.' }, 400);
  // Não pode colocar em manutenção vaga ocupada
  if (newStatus === 'maintenance' && spot.vessel_id)
    return sendJson(res, { error: 'A vaga está ocupada. Desatribua a embarcação antes de colocar em manutenção.' }, 400);

  await tRun('UPDATE spots SET status=? WHERE id=?', [newStatus, ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/spots/:id', async (req, res, ctx) => {
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const spot = await tGet('SELECT * FROM spots WHERE id=?', [ctx.params.id]);
  if (!spot) return sendJson(res, { error: 'Vaga não encontrada' }, 404);
  if (spot.vessel_id) return sendJson(res, { error: 'Vaga com embarcação — remova o contrato primeiro' }, 400);
  if (spot.status === 'occupied') return sendJson(res, { error: 'Vaga ocupada — cancele o contrato primeiro' }, 400);
  await tRun('DELETE FROM spots WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — CONTRATOS
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/contracts', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = `SELECT ct.*, c.name as client_name, c.tier as client_tier,
    v.name as vessel_name, s.number as spot_number
    FROM contracts ct JOIN clients c ON ct.client_id=c.id
    JOIN vessels v ON ct.vessel_id=v.id LEFT JOIN spots s ON ct.spot_id=s.id WHERE 1=1`;
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null) { sql += ' AND ct.client_id=?'; a.push(scope); }
  if (status) { sql += ' AND ct.status=?'; a.push(status); }
  sendJson(res, await tAll(sql + ' ORDER BY ct.start_date DESC', a));
});

addRoute('GET', '/api/contracts/:id', async (req, res, ctx) => {
  const { dbGet: tGet } = ctx.db;
  const ct = await tGet(`SELECT ct.*, c.name as client_name, c.tier as client_tier,
    v.name as vessel_name, s.number as spot_number
    FROM contracts ct JOIN clients c ON ct.client_id=c.id
    JOIN vessels v ON ct.vessel_id=v.id LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.id=?`, [ctx.params.id]);
  if (!ct) return sendJson(res, { error: 'Não encontrado' }, 404);
  sendJson(res, ct);
});

addRoute('POST', '/api/contracts', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbRun: tRun } = ctx.db;
  const r = await tRun('INSERT INTO contracts(client_id,vessel_id,spot_id,type,start_date,end_date,monthly_value,status,notes,contract_file,contract_file_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       [b.client_id, b.vessel_id, b.spot_id || null, b.type, b.start_date, b.end_date || null, b.monthly_value, b.status || 'active', b.notes || null, b.contract_file || null, b.contract_file_name || null]);
  if (b.spot_id) await tRun(`UPDATE spots SET status='occupied',vessel_id=? WHERE id=?`, [b.vessel_id, b.spot_id]);

  // Gera mensalidades mensais:
  // - Sem término: até 31/12 do ano corrente
  // - Com término: do início até a data de término (máx. 60 parcelas)
  const contractId = r.lastInsertRowid;
  const startDt    = new Date(b.start_date + 'T12:00:00Z');
  const endLimit   = b.end_date
    ? new Date(b.end_date + 'T12:00:00Z')
    : new Date(Date.UTC(new Date().getFullYear(), 11, 31)); // 31/12 ano atual

  const cur = new Date(startDt);
  let chargesGenerated = 0;
  while (cur <= endLimit && chargesGenerated < 60) {
    const ds    = cur.toISOString().slice(0, 10);
    const month = cur.toLocaleDateString('pt-BR', { month: '2-digit', year: 'numeric' });
    await tRun(`INSERT INTO financial_charges(client_id,contract_id,description,amount,due_date,status) VALUES(?,?,?,?,?,'pending')`,
               [b.client_id, contractId, `Mensalidade ${b.type} - ${month}`, b.monthly_value, ds]);
    cur.setUTCMonth(cur.getUTCMonth() + 1);
    chargesGenerated++;
  }
  sendJson(res, { id: contractId }, 201);
});

addRoute('GET', '/api/contracts/:id/cancel-info', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { dbGet: tGet, dbAll: tAll } = ctx.db;
  const contract = await tGet('SELECT * FROM contracts WHERE id=?', [ctx.params.id]);
  if (!contract) return sendJson(res, { error: 'Contrato não encontrado' }, 404);
  if (contract.status !== 'active') return sendJson(res, { error: 'Contrato não está ativo' }, 400);

  // Parcelas vencidas (overdue ou pending com vencimento no passado/hoje)
  const today = todayStr();
  const overdueCharges = await tAll(
    `SELECT * FROM financial_charges WHERE contract_id=? AND status IN ('overdue','pending') AND due_date<=? ORDER BY due_date ASC`,
    [ctx.params.id, today]
  );
  // Parcelas futuras pendentes
  const futureCharges = await tAll(
    `SELECT * FROM financial_charges WHERE contract_id=? AND status='pending' AND due_date>? ORDER BY due_date ASC`,
    [ctx.params.id, today]
  );

  const overdue_amount = overdueCharges.reduce((s, c) => s + Number(c.amount), 0);
  const notice_amount  = Number(contract.monthly_value); // 1 mês aviso prévio

  sendJson(res, {
    contract_id:      Number(contract.id),
    monthly_value:    Number(contract.monthly_value),
    overdue_count:    overdueCharges.length,
    overdue_amount,
    notice_amount,
    total_due:        overdue_amount + notice_amount,
    future_count:     futureCharges.length,
    overdue_charges:  overdueCharges.map(c => ({ ...c, amount: Number(c.amount) })),
  });
});

addRoute('PUT', '/api/contracts/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbGet: tGet, dbAll: tAll, dbRun: tRun } = ctx.db;
  const old = await tGet('SELECT * FROM contracts WHERE id=?', [ctx.params.id]);
  if (!old) return sendJson(res, { error: 'Contrato não encontrado' }, 404);

  // Cancelamento com validações
  if (b.status === 'cancelled' && old.status === 'active') {
    const today = todayStr();
    // Bloqueia se houver parcelas vencidas não pagas
    const overdueCount = await tGet(
      `SELECT COUNT(*) as n FROM financial_charges WHERE contract_id=? AND status IN ('overdue','pending') AND due_date<=?`,
      [ctx.params.id, today]
    );
    if (Number(overdueCount?.n) > 0)
      return sendJson(res, { error: `Há ${overdueCount.n} parcela(s) vencida(s) em aberto. Dê baixa nelas antes de cancelar o contrato.` }, 400);
    if (!b.justification || !b.justification.trim())
      return sendJson(res, { error: 'Justificativa é obrigatória para cancelamento.' }, 400);

    // Cancela parcelas futuras pendentes
    await tRun(
      `UPDATE financial_charges SET status='cancelled' WHERE contract_id=? AND status='pending' AND due_date>?`,
      [ctx.params.id, today]
    );
    // Libera vaga
    if (old.spot_id)
      await tRun(`UPDATE spots SET status='available',vessel_id=NULL WHERE id=?`, [old.spot_id]);
    // Atualiza contrato
    await tRun(
      'UPDATE contracts SET status=?,notes=?,contract_file=?,contract_file_name=? WHERE id=?',
      ['cancelled',
       `${old.notes ? old.notes + '\n' : ''}[CANCELADO] ${b.justification}`.trim(),
       b.contract_file !== undefined ? (b.contract_file || null) : old.contract_file,
       b.contract_file_name !== undefined ? (b.contract_file_name || null) : old.contract_file_name,
       ctx.params.id]
    );
    // Registra no log do sistema
    await tRun(
      `INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
      [ctx.user?.user_id || null, ctx.user?.name || null, 'contract_cancelled',
       JSON.stringify({ contract_id: Number(ctx.params.id), justification: b.justification.trim(), cancelled_by: ctx.user?.name || '—' })]
    );
    return sendJson(res, { ok: true });
  }

  // Atualização normal
  await tRun('UPDATE contracts SET status=?,monthly_value=?,end_date=?,notes=?,contract_file=?,contract_file_name=? WHERE id=?',
             [b.status || old.status, b.monthly_value || old.monthly_value, b.end_date || old.end_date, b.notes || old.notes,
              b.contract_file !== undefined ? (b.contract_file || null) : old.contract_file,
              b.contract_file_name !== undefined ? (b.contract_file_name || null) : old.contract_file_name,
              ctx.params.id]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — FILA DE OPERAÇÕES
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/queue/history', async (req, res, ctx) => {
  const { dbAll: tAll, dbGet: tGet } = ctx.db;
  const scope = clientScope(ctx.user);
  let sql = `SELECT q.*, v.name as vessel_name, v.type as vessel_type, v.size as vessel_size, c.name as client_name, c.tier as client_tier
    FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id JOIN clients c ON q.client_id=c.id
    WHERE q.status IN ('completed','cancelled')`;
  const a = [];
  if (scope !== null) { sql += ' AND q.client_id=?'; a.push(scope); }
  const settings = await getSettings(tAll);
  const rows     = await tAll(sql + ' ORDER BY q.requested_at DESC LIMIT 50', a);
  const enriched = await Promise.all(rows.map(q => enrichQueueRow(q, settings, tGet)));
  sendJson(res, enriched);
});

addRoute('GET', '/api/queue/calendar', async (req, res, ctx) => {
  const { dbAll: tAll, dbGet: tGet } = ctx.db;
  const today    = todayStr();
  const settings = await getSettings(tAll);
  const done     = await tAll(`SELECT q.*, v.name as vessel_name, v.type as vessel_type, v.size as vessel_size, c.name as client_name, c.tier as client_tier
    FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id JOIN clients c ON q.client_id=c.id
    WHERE q.status IN ('completed','cancelled') AND DATE(q.requested_at)=? ORDER BY COALESCE(q.started_at, q.requested_at) ASC`, [today]);
  const active   = await tAll(`SELECT q.*, v.name as vessel_name, v.type as vessel_type, v.size as vessel_size, c.name as client_name, c.tier as client_tier
    FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id JOIN clients c ON q.client_id=c.id
    WHERE q.status NOT IN ('completed','cancelled') ORDER BY q.queue_order ASC, q.priority DESC, q.requested_at ASC`);
  const activeEnriched = await Promise.all(active.map(q => enrichQueueRow(q, settings, tGet)));
  const doneEnriched   = await Promise.all(done.map(q => enrichQueueRow(q, settings, tGet)));
  applyEstimatedTimes(activeEnriched, getManeuverTime(settings));
  sendJson(res, { today, done: doneEnriched, active: activeEnriched, maneuver_time_min: getManeuverTime(settings) });
});

addRoute('GET', '/api/queue', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  const { dbAll: tAll, dbGet: tGet } = ctx.db;
  let sql = `SELECT q.*, v.name as vessel_name, v.type as vessel_type, v.size as vessel_size, v.length as vessel_length, c.name as client_name, c.tier as client_tier
    FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id JOIN clients c ON q.client_id=c.id WHERE 1=1`;
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null) { sql += ' AND q.client_id=?'; a.push(scope); }
  if (status) {
    const ss = status.split(',');
    sql += ` AND q.status IN (${ss.map(() => '?').join(',')})`;
    a.push(...ss);
  } else {
    sql += ` AND q.status NOT IN ('completed','cancelled')`;
  }
  const settings = await getSettings(tAll);
  const rows     = await tAll(sql + ' ORDER BY q.queue_order ASC, q.priority DESC, q.requested_at ASC', a);
  const enriched = await Promise.all(rows.map(q => enrichQueueRow(q, settings, tGet)));
  applyEstimatedTimes(enriched, getManeuverTime(settings));
  sendJson(res, enriched);
});

addRoute('POST', '/api/queue', async (req, res, ctx) => {
  const { dbGet: tGet, dbAll: tAll, dbRun: tRun } = ctx.db;
  const vessel = await tGet('SELECT * FROM vessels WHERE id=?', [ctx.body.vessel_id]);
  if (!vessel) return sendJson(res, { error: 'Embarcação não encontrada' }, 404);
  if (ctx.user && ctx.user.role === 'cliente' && Number(vessel.client_id) !== Number(ctx.user.client_id))
    return sendJson(res, { error: 'Você só pode solicitar operações de suas próprias embarcações' }, 403);
  const opType   = ctx.body.operation_type;
  const spot     = await tGet(`SELECT s.type FROM spots s JOIN contracts ct ON ct.spot_id=s.id WHERE ct.vessel_id=? AND ct.status='active'`, [ctx.body.vessel_id]);
  const spotType = spot?.type || null;
  if (opType === 'descida' && (await isVesselInWater(ctx.body.vessel_id, spotType, tGet)))
    return sendJson(res, { error: 'A embarcação já está na água.' }, 400);
  if (opType === 'subida' && !(await isVesselInWater(ctx.body.vessel_id, spotType, tGet)))
    return sendJson(res, { error: 'A embarcação não está na água.' }, 400);
  const activeOp = await tGet(`SELECT id FROM queue_operations WHERE vessel_id=? AND status IN ('waiting','in_progress')`, [ctx.body.vessel_id]);
  if (activeOp) return sendJson(res, { error: 'Esta embarcação já possui operação ativa na fila.' }, 400);

  const settings  = await getSettings(tAll);
  const opsStart  = settings['ops_start_time']  || '07:00';
  const opsEnd    = settings['ops_end_time']    || '18:00';
  const maneuverMin = parseInt(settings['maneuver_time_min']) || 0;
  const hhmm2min  = s => { const [h, m] = (s||'00:00').split(':').map(Number); return h*60+m; };
  const fmtMin    = m => `${String(Math.floor(m/60)%24).padStart(2,'0')}:${String(m%60).padStart(2,'0')}`;
  const now       = new Date();
  const nowMin    = now.getHours()*60 + now.getMinutes();
  const startMin  = hhmm2min(opsStart), endMin = hhmm2min(opsEnd);
  let cursorMin   = Math.max(nowMin, startMin);
  const queuedActive = await tAll(`SELECT q.*, v.size as vessel_size FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id WHERE q.status NOT IN ('completed','cancelled') ORDER BY q.queue_order ASC, q.priority DESC, q.requested_at ASC`);
  for (const op of queuedActive) {
    const dur = getAvgDurationSync(settings, op.vessel_size, op.operation_type);
    if (op.status === 'in_progress' && op.started_at) {
      const sa = new Date(String(op.started_at).replace(' ', 'T'));
      const estimatedEnd = new Date(sa);
      estimatedEnd.setMinutes(estimatedEnd.getMinutes() + dur);
      if (!isNaN(estimatedEnd) && estimatedEnd > now) {
        const opEndMin = estimatedEnd.getHours()*60 + estimatedEnd.getMinutes();
        if (opEndMin > cursorMin) cursorMin = opEndMin;
      }
    } else if (op.status === 'waiting') { cursorMin += dur; }
    cursorMin += maneuverMin;
  }
  const newDur = getAvgDurationSync(settings, vessel.size, opType);
  if (cursorMin + newDur > endMin)
    return sendJson(res, { error: `Operação não pode ser incluída: previsão de término às ${fmtMin(cursorMin + newDur)}, após ${opsEnd}.` }, 400);
  let warning = null;
  if (nowMin < startMin) warning = `Solicitação recebida antes do horário de início (${opsStart}).`;

  const client    = await tGet('SELECT * FROM clients WHERE id=?', [vessel.client_id]);
  const priority  = client && ['gold', 'vip'].includes(client.tier) ? 1 : 0;
  const maxOrder  = await tGet(`SELECT MAX(queue_order) as mo FROM queue_operations WHERE status='waiting'`);
  const queueOrder = (Number(maxOrder?.mo) || 0) + 1;
  const r = await tRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,priority,notes,queue_order,requested_at) VALUES(?,?,?,'waiting',?,?,?,?)`,
                       [ctx.body.vessel_id, vessel.client_id, opType, priority, ctx.body.notes || null, queueOrder, nowStr()]);
  sendJson(res, { id: r.lastInsertRowid, warning }, 201);
});

addRoute('PUT', '/api/queue/:id/reorder', async (req, res, ctx) => {
  const { direction, justification } = ctx.body || {};
  if (!justification?.trim()) return sendJson(res, { error: 'Justificativa obrigatória.' }, 400);
  if (!['up','down'].includes(direction)) return sendJson(res, { error: 'Direção inválida.' }, 400);
  const { dbGet: tGet, dbAll: tAll, dbRun: tRun } = ctx.db;
  const op = await tGet(`SELECT * FROM queue_operations WHERE id=? AND status='waiting'`, [ctx.params.id]);
  if (!op) return sendJson(res, { error: 'Operação não encontrada.' }, 404);
  const waitingOps = await tAll(`SELECT id, queue_order FROM queue_operations WHERE status='waiting' ORDER BY queue_order ASC`);
  const idx = waitingOps.findIndex(o => o.id == ctx.params.id);
  const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
  if (swapIdx < 0 || swapIdx >= waitingOps.length)
    return sendJson(res, { error: direction === 'up' ? 'Já é o primeiro.' : 'Já é o último.' }, 400);
  const other = waitingOps[swapIdx];
  await tRun(`UPDATE queue_operations SET queue_order=? WHERE id=?`, [other.queue_order, op.id]);
  await tRun(`UPDATE queue_operations SET queue_order=? WHERE id=?`, [op.queue_order, other.id]);
  const vessel = await tGet('SELECT name FROM vessels WHERE id=?', [op.vessel_id]);
  await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
    [ctx.user.user_id||null, ctx.user.name||'Sistema', 'queue_reorder',
     JSON.stringify({ op_id: op.id, vessel: vessel?.name, direction, justification: justification.trim() })]);
  sendJson(res, { ok: true });
});

addRoute('PUT', '/api/queue/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const old = await tGet('SELECT * FROM queue_operations WHERE id=?', [ctx.params.id]);
  const ns  = b.status || old.status;
  let started = old.started_at, completed = old.completed_at;
  if (ns === 'in_progress' && !started) started = nowStr();
  if (['completed','cancelled'].includes(ns) && !completed) completed = nowStr();
  await tRun('UPDATE queue_operations SET status=?,started_at=?,completed_at=?,operator=?,notes=? WHERE id=?',
             [ns, started || null, completed || null, b.operator || old.operator || null, b.notes || old.notes || null, ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/queue/:id', async (req, res, ctx) => {
  await ctx.db.dbRun(`UPDATE queue_operations SET status='cancelled' WHERE id=?`, [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — FINANCEIRO
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/financial/charges', async (req, res, ctx) => {
  const { status = '', client_id = '', contract_id = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT fc.*, c.name as client_name, c.tier as client_tier FROM financial_charges fc JOIN clients c ON fc.client_id=c.id WHERE 1=1';
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null)    { sql += ' AND fc.client_id=?'; a.push(scope); }
  else if (client_id)    { sql += ' AND fc.client_id=?'; a.push(client_id); }
  if (contract_id)       { sql += ' AND fc.contract_id=?'; a.push(contract_id); }
  if (status)            { sql += ' AND fc.status=?'; a.push(status); }
  const rows = await tAll(sql + ' ORDER BY fc.due_date ASC', a);
  sendJson(res, rows.map(r => ({ ...r, amount: Number(r.amount) })));
});

addRoute('POST', '/api/financial/charges', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbRun: tRun } = ctx.db;
  const r = await tRun(`INSERT INTO financial_charges(client_id,contract_id,description,amount,due_date,status,notes) VALUES(?,?,?,?,?,?,?)`,
                       [b.client_id, b.contract_id || null, b.description, b.amount, b.due_date, b.status || 'pending', b.notes || null]);
  sendJson(res, { id: r.lastInsertRowid }, 201);
});

addRoute('PUT', '/api/financial/charges/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const old = await tGet('SELECT * FROM financial_charges WHERE id=?', [ctx.params.id]);
  if (!old) return sendJson(res, { error: 'Cobrança não encontrada' }, 404);
  const ns       = b.status || old.status;
  const paid_date = (ns === 'paid' && !old.paid_date) ? todayStr() : (b.paid_date || old.paid_date || null);
  await tRun('UPDATE financial_charges SET status=?,paid_date=?,payment_method=?,notes=? WHERE id=?',
             [ns, paid_date, b.payment_method || old.payment_method || null, b.pay_notes || b.notes || old.notes || null, ctx.params.id]);
  if (ns === 'paid' && old.status !== 'paid') {
    const clientRow = old.client_id ? await tGet('SELECT name FROM clients WHERE id=?', [old.client_id]) : null;
    await tRun(`INSERT INTO payment_logs(charge_id,client_id,client_name,description,amount,payment_method,pay_notes,comprovante_data,comprovante_name,user_id,user_email,user_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
               [old.id, old.client_id, clientRow?.name||null, old.description, old.amount,
                b.payment_method||null, b.pay_notes||null, b.comprovante_data||null, b.comprovante_name||null,
                ctx.user?.user_id||null, ctx.user?.email||null, ctx.user?.name||null]);
    await recalcLtv(old.client_id, tGet, tRun);
  }
  await checkOverdue(tRun);
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/financial/summary', async (req, res, ctx) => {
  const { dbGet: tGet, dbAll: tAll } = ctx.db;
  await checkOverdue(ctx.db.dbRun);
  const ms = monthStart();
  sendJson(res, {
    total_paid_month: Number((await tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`, [ms]))?.v || 0),
    total_pending:    Number((await tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='pending'`))?.v || 0),
    total_overdue:    Number((await tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='overdue'`))?.v || 0),
    count_overdue:    Number((await tGet(`SELECT COUNT(*) as v FROM financial_charges WHERE status='overdue'`))?.v || 0),
    revenue_by_month: (await tAll(`SELECT TO_CHAR(paid_date,'YYYY-MM') as month, COALESCE(SUM(amount),0) as total FROM financial_charges WHERE status='paid' AND paid_date IS NOT NULL GROUP BY TO_CHAR(paid_date,'YYYY-MM') ORDER BY TO_CHAR(paid_date,'YYYY-MM') DESC LIMIT 6`)).map(r=>({...r,total:Number(r.total)})),
  });
});

addRoute('GET', '/api/financial/payment-logs', async (req, res, ctx) => {
  const { charge_id = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT * FROM payment_logs';
  const params = [];
  if (charge_id) { sql += ' WHERE charge_id=?'; params.push(charge_id); }
  sql += ' ORDER BY created_at DESC LIMIT 200';
  const logs = await tAll(sql, params);
  sendJson(res, logs.map(l => ({ ...l, comprovante_data: l.comprovante_data ? '[anexo]' : null })));
});

addRoute('GET', '/api/financial/payment-logs/:id/comprovante', async (req, res, ctx) => {
  const log = await ctx.db.dbGet(`SELECT comprovante_data, comprovante_name FROM payment_logs WHERE id=?`, [ctx.params.id]);
  if (!log || !log.comprovante_data) return sendJson(res, { error: 'Sem comprovante' }, 404);
  sendJson(res, log);
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — LOJA / PDV
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/store/items', async (req, res, ctx) => {
  const { category = '', low_stock = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT * FROM store_items WHERE active=1';
  const a = [];
  if (category)  { sql += ' AND category=?'; a.push(category); }
  if (low_stock) sql += ' AND stock<=min_stock';
  sendJson(res, await tAll(sql + ' ORDER BY category,name', a));
});

addRoute('POST', '/api/store/items', async (req, res, ctx) => {
  const b = ctx.body;
  const r = await ctx.db.dbRun('INSERT INTO store_items(name,category,price,cost,stock,min_stock,unit) VALUES(?,?,?,?,?,?,?)',
                               [b.name, b.category||'outros', b.price, b.cost||0, b.stock||0, b.min_stock||5, b.unit||'un']);
  sendJson(res, { id: r.lastInsertRowid }, 201);
});

addRoute('PUT', '/api/store/items/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  await tRun('UPDATE store_items SET name=?,category=?,price=?,cost=?,stock=?,min_stock=?,unit=? WHERE id=?',
             [b.name, b.category, b.price, b.cost||0, b.stock||0, b.min_stock||5, b.unit||'un', ctx.params.id]);
  await checkStock(tAll, tAll, tGet, tRun);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/store/items/:id', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE store_items SET active=0 WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/store/orders', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT o.*, v.name as vessel_name, c.name as client_name FROM store_orders o LEFT JOIN vessels v ON o.vessel_id=v.id LEFT JOIN clients c ON o.client_id=c.id WHERE 1=1';
  const a = [];
  if (status) { sql += ' AND o.status=?'; a.push(status); }
  const rows = await tAll(sql + ' ORDER BY o.created_at DESC LIMIT 100', a);
  for (const r of rows) { try { r.items = JSON.parse(r.items); } catch { /* keep raw */ } }
  sendJson(res, rows);
});

addRoute('POST', '/api/store/orders', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  const items    = b.items || [];
  const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
  const discount = b.discount || 0;
  const total    = subtotal - discount;
  const forcedStatus = b.payment_method === 'ficha' ? 'pending_payment' : (b.status || 'open');
  const r = await tRun('INSERT INTO store_orders(vessel_id,client_id,items,subtotal,discount,total,status,payment_method,notes) VALUES(?,?,?,?,?,?,?,?,?)',
                       [b.vessel_id||null, b.client_id||null, JSON.stringify(items), subtotal, discount, total, forcedStatus, b.payment_method||null, b.notes||null]);
  for (const item of items) await tRun('UPDATE store_items SET stock=GREATEST(0,stock-?) WHERE id=?', [item.qty, item.item_id]);
  await checkStock(tAll, tAll, tGet, tRun);
  sendJson(res, { id: r.lastInsertRowid, total }, 201);
});

addRoute('PUT', '/api/store/orders/:id', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE store_orders SET status=?,payment_method=?,notes=? WHERE id=?',
                     [ctx.body.status, ctx.body.payment_method||null, ctx.body.notes||null, ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('PUT', '/api/store/orders/:id/delivery', async (req, res, ctx) => {
  const { delivery_status, status } = ctx.body;
  const updates = [], params = [];
  if (delivery_status !== undefined) { updates.push('delivery_status=?'); params.push(delivery_status); }
  if (status !== undefined)          { updates.push('status=?'); params.push(status); }
  if (!updates.length) { sendJson(res, { ok: true }); return; }
  params.push(ctx.params.id);
  await ctx.db.dbRun(`UPDATE store_orders SET ${updates.join(',')} WHERE id=?`, params);
  sendJson(res, { ok: true });
});

addRoute('PUT', '/api/store/orders/:id/confirm-payment', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const b = ctx.body || {};
  await ctx.db.dbRun(`UPDATE store_orders SET
    status='paid', delivery_status='preparando',
    payment_method=COALESCE(?,payment_method),
    pay_notes=?, paid_date=COALESCE(CAST(? AS DATE),CURRENT_DATE),
    comprovante_data=?, comprovante_name=?
    WHERE id=?`,
    [b.payment_method||null, b.pay_notes||null, b.paid_date||null,
     b.comprovante_data||null, b.comprovante_name||null, ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/store/client-accounts', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;
  const rows = await tAll(`SELECT o.*, c.name as client_name, c.phone as client_phone, c.tier as client_tier, v.name as vessel_name
    FROM store_orders o LEFT JOIN clients c ON o.client_id=c.id LEFT JOIN vessels v ON o.vessel_id=v.id
    WHERE o.status='pending_payment' ORDER BY o.created_at ASC`);
  for (const r of rows) { try { r.items = JSON.parse(r.items); } catch {} }
  const map = {};
  for (const o of rows) {
    const key = o.client_id || 0;
    if (!map[key]) map[key] = { client_id: o.client_id, client_name: o.client_name||'Balcão', client_phone: o.client_phone, client_tier: o.client_tier, orders: [], total: 0 };
    map[key].orders.push(o);
    map[key].total += Number(o.total);
  }
  const accounts   = Object.values(map).sort((a, b) => b.total - a.total);
  const grand_total = accounts.reduce((s, a) => s + a.total, 0);
  sendJson(res, { accounts, grand_total });
});

addRoute('GET', '/api/store/stats', async (req, res, ctx) => {
  const { dbAll: tAll, dbGet: tGet } = ctx.db;
  const td  = todayStr();
  const g1  = (sql, a = []) => tGet(sql, a);
  const n   = v => Number(v || 0);
  const vendas_hoje   = n((await g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='paid' AND DATE(created_at)=?`,[td]))?.v);
  const receita_hoje  = n((await g1(`SELECT COALESCE(SUM(total),0) as v FROM store_orders WHERE status='paid' AND DATE(created_at)=?`,[td]))?.v);
  const aguardando    = n((await g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='pending_payment'`))?.v);
  const preparando    = n((await g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='paid' AND delivery_status='preparando'`))?.v);
  const entregando    = n((await g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='paid' AND delivery_status='entregando'`))?.v);
  const entregue_hoje = n((await g1(`SELECT COUNT(*) as v FROM store_orders WHERE delivery_status='entregue' AND DATE(created_at)=?`,[td]))?.v);
  const estoque_baixo = n((await g1(`SELECT COUNT(*) as v FROM store_items WHERE active=1 AND stock<=min_stock`))?.v);
  const abertos       = n((await g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='open'`))?.v);
  const ticket_medio  = vendas_hoje > 0 ? receita_hoje / vendas_hoje : 0;
  const parse = rows => { for (const r of rows) { try { r.items = JSON.parse(r.items); } catch {} } return rows; };
  const pipeBase = `SELECT o.*,c.name as client_name FROM store_orders o LEFT JOIN clients c ON o.client_id=c.id WHERE `;
  const [pa, pp, pe, pee] = await Promise.all([
    tAll(pipeBase+`o.status='pending_payment' ORDER BY o.created_at ASC LIMIT 10`),
    tAll(pipeBase+`o.status='paid' AND o.delivery_status='preparando' ORDER BY o.created_at ASC LIMIT 10`),
    tAll(pipeBase+`o.status='paid' AND o.delivery_status='entregando' ORDER BY o.created_at ASC LIMIT 10`),
    tAll(pipeBase+`o.delivery_status='entregue' AND DATE(o.created_at)=? ORDER BY o.created_at DESC LIMIT 10`,[td]),
  ]);
  const recent       = parse(await tAll(`SELECT o.*,c.name as client_name FROM store_orders o LEFT JOIN clients c ON o.client_id=c.id WHERE o.status='paid' ORDER BY o.created_at DESC LIMIT 8`));
  const vendas_semana = (await tAll(`SELECT DATE(created_at) as day,COUNT(*) as count,COALESCE(SUM(total),0) as total FROM store_orders WHERE status='paid' AND DATE(created_at)>=? GROUP BY DATE(created_at) ORDER BY DATE(created_at)`,[daysAgo(6)])).map(r=>({...r,count:Number(r.count),total:Number(r.total)}));
  sendJson(res,{vendas_hoje,receita_hoje,aguardando,preparando,entregando,entregue_hoje,estoque_baixo,abertos,ticket_medio,
    pipeline_aguardando:parse(pa),pipeline_preparando:parse(pp),pipeline_entregando:parse(pe),pipeline_entregue:parse(pee),recent,vendas_semana});
});

addRoute('GET', '/api/store/stock-stats', async (req, res, ctx) => {
  const { dbAll: tAll } = ctx.db;
  const items   = await tAll(`SELECT * FROM store_items WHERE active=1`);
  const ago30   = daysAgo(30);
  const total_itens      = items.length;
  const total_skus_zero  = items.filter(i => i.stock <= 0).length;
  const total_skus_baixo = items.filter(i => i.stock > 0 && i.stock <= i.min_stock).length;
  const total_skus_ok    = items.filter(i => i.stock > i.min_stock).length;
  const valor_custo      = items.reduce((s, i) => s + (Number(i.stock)||0) * (Number(i.cost)||0), 0);
  const valor_venda      = items.reduce((s, i) => s + (Number(i.stock)||0) * (Number(i.price)||0), 0);
  const cats = {};
  items.forEach(i => {
    if (!cats[i.category]) cats[i.category] = { category: i.category, itens:0, stock_total:0, valor_venda:0, valor_custo:0, baixo:0, zero:0 };
    cats[i.category].itens++;
    cats[i.category].stock_total += Number(i.stock)||0;
    cats[i.category].valor_venda += (Number(i.stock)||0)*(Number(i.price)||0);
    cats[i.category].valor_custo += (Number(i.stock)||0)*(Number(i.cost)||0);
    if (i.stock<=0) cats[i.category].zero++; else if (i.stock<=i.min_stock) cats[i.category].baixo++;
  });
  const por_categoria = Object.values(cats).sort((a, b) => b.valor_venda - a.valor_venda);
  const orders_recentes = await tAll(`SELECT items FROM store_orders WHERE status != 'cancelled' AND DATE(created_at) >= ?`, [ago30]);
  const qtd_vendida = {};
  for (const o of orders_recentes) {
    let its; try { its = JSON.parse(o.items); } catch { its = []; }
    for (const i of its) { qtd_vendida[i.item_id] = (qtd_vendida[i.item_id]||0) + i.qty; }
  }
  const top_vendidos = items.map(i => ({ ...i, qtd_vendida_30d: qtd_vendida[i.id]||0, receita_30d: (qtd_vendida[i.id]||0)*Number(i.price) })).sort((a,b)=>b.qtd_vendida_30d-a.qtd_vendida_30d).slice(0,10);
  const criticos = items.filter(i=>i.stock<=i.min_stock).map(i=>({ ...i, qtd_vendida_30d:qtd_vendida[i.id]||0, dias_cobertura: qtd_vendida[i.id] ? Math.round((i.stock/(qtd_vendida[i.id]/30))*10)/10 : null })).sort((a,b)=>(a.stock/Math.max(a.min_stock,1))-(b.stock/Math.max(b.min_stock,1)));
  const coberturas = items.filter(i=>qtd_vendida[i.id]&&i.stock>0).map(i=>i.stock/(qtd_vendida[i.id]/30));
  const cobertura_media = coberturas.length ? Math.round(coberturas.reduce((s,v)=>s+v,0)/coberturas.length) : null;
  sendJson(res,{total_itens,total_skus_zero,total_skus_baixo,total_skus_ok,valor_custo,valor_venda,margem_potencial:valor_venda-valor_custo,cobertura_media,por_categoria,top_vendidos,criticos});
});

addRoute('GET', '/api/store/pix-config', async (req, res, ctx) => {
  sendJson(res, await ctx.db.dbGet(`SELECT * FROM store_pix_config WHERE active=1 ORDER BY id DESC`) || {});
});

addRoute('POST', '/api/store/pix-config', async (req, res, ctx) => {
  const { dbRun: tRun } = ctx.db;
  await tRun(`UPDATE store_pix_config SET active=0`);
  await tRun(`INSERT INTO store_pix_config(key,key_type,merchant_name,city,active) VALUES(?,?,?,?,1)`,
             [ctx.body.key, ctx.body.key_type, ctx.body.merchant_name, ctx.body.city]);
  sendJson(res, { ok: true });
});

addRoute('POST', '/api/store/pix-qrcode', async (req, res, ctx) => {
  const cfg = await ctx.db.dbGet(`SELECT * FROM store_pix_config WHERE active=1 ORDER BY id DESC`);
  if (!cfg) return sendJson(res, { error: 'PIX não configurado' }, 400);
  const amount = parseFloat(ctx.body.amount) || 0;
  const txid   = crypto.randomBytes(12).toString('hex').toUpperCase().slice(0, 25);
  sendJson(res, { payload: buildPix(cfg.key, cfg.merchant_name, cfg.city, amount, txid), txid, amount });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — MANUTENÇÃO
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/maintenance', async (req, res, ctx) => {
  const { status = '', vessel_id = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = `SELECT m.*, v.name as vessel_name, c.name as client_name
    FROM maintenance_os m LEFT JOIN vessels v ON m.vessel_id=v.id LEFT JOIN clients c ON v.client_id=c.id WHERE 1=1`;
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null) { sql += ' AND v.client_id=?'; a.push(scope); }
  if (status)         { sql += ' AND m.status=?';    a.push(status); }
  if (vessel_id)      { sql += ' AND m.vessel_id=?'; a.push(vessel_id); }
  sql += ` ORDER BY CASE m.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, m.created_at DESC`;
  sendJson(res, await tAll(sql, a));
});

addRoute('POST', '/api/maintenance', async (req, res, ctx) => {
  const b      = ctx.body;
  const { dbRun: tRun } = ctx.db;
  const os_num = `OS-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${Math.floor(Math.random()*900)+100}`;
  const r = await tRun('INSERT INTO maintenance_os(vessel_id,os_number,type,description,status,priority,scheduled_date,estimated_hours,cost,technician,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       [b.vessel_id||null, os_num, b.type, b.description, b.status||'open', b.priority||'normal', b.scheduled_date||null, b.estimated_hours||null, b.cost||0, b.technician||null, b.notes||null]);
  if (['urgent','high'].includes(b.priority))
    await addAlert('manutencao', `OS urgente: ${b.description.slice(0,50)}`, 'warning', null, null, tRun);
  sendJson(res, { id: r.lastInsertRowid, os_number: os_num }, 201);
});

addRoute('PUT', '/api/maintenance/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const old = await tGet('SELECT * FROM maintenance_os WHERE id=?', [ctx.params.id]);
  const ns  = b.status || old.status;
  const completed_date = (ns === 'completed' && !old.completed_date) ? todayStr() : (b.completed_date || old.completed_date || null);
  await tRun('UPDATE maintenance_os SET status=?,priority=?,scheduled_date=?,completed_date=?,actual_hours=?,cost=?,technician=?,notes=? WHERE id=?',
             [ns, b.priority||old.priority, b.scheduled_date||old.scheduled_date||null, completed_date,
              b.actual_hours||old.actual_hours||null, b.cost!==undefined ? b.cost : old.cost,
              b.technician||old.technician||null, b.notes||old.notes||null, ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/maintenance/:id', async (req, res, ctx) => {
  await ctx.db.dbRun(`UPDATE maintenance_os SET status='cancelled' WHERE id=?`, [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — ALERTAS
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/alerts', async (req, res, ctx) => {
  const { unread = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT * FROM alerts WHERE 1=1';
  if (unread) sql += ' AND read_at IS NULL';
  sendJson(res, await tAll(sql + ' ORDER BY created_at DESC LIMIT 50'));
});

addRoute('PUT', '/api/alerts/read-all', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE alerts SET read_at=? WHERE read_at IS NULL', [nowStr()]);
  sendJson(res, { ok: true });
});

addRoute('PUT', '/api/alerts/:id/read', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE alerts SET read_at=? WHERE id=?', [nowStr(), ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('PUT', '/api/alerts/:id/unread', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE alerts SET read_at=NULL WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — ANALYTICS
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/analytics/kpis', async (req, res, ctx) => {
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  await checkOverdue(tRun);
  const ms = monthStart(), td = todayStr(), ago30 = daysAgo(30);
  const g1 = (sql, a=[]) => tGet(sql, a);
  const n  = v => Number(v || 0);
  const [vt, vo, vst, vso, vmt, vmo] = await Promise.all([
    g1('SELECT COUNT(*) as v FROM spots'),
    g1(`SELECT COUNT(*) as v FROM spots WHERE status='occupied'`),
    g1(`SELECT COUNT(*) as v FROM spots WHERE type='seca'`),
    g1(`SELECT COUNT(*) as v FROM spots WHERE type='seca' AND status='occupied'`),
    g1(`SELECT COUNT(*) as v FROM spots WHERE type='molhada'`),
    g1(`SELECT COUNT(*) as v FROM spots WHERE type='molhada' AND status='occupied'`),
  ]);
  const vagas_total=n(vt?.v), vagas_ocupadas=n(vo?.v), vagas_seca_total=n(vst?.v), vagas_seca_ocupadas=n(vso?.v), vagas_molhada_total=n(vmt?.v), vagas_molhada_ocupadas=n(vmo?.v);
  const [rm,inad,pend,tctv,rs,rmol,lm,tc,vc,tv,ca,qh,qa,osab,osurg,cm,anl,tmed,ltv,sla] = await Promise.all([
    g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`,[ms]),
    g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='overdue'`),
    g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='pending'`),
    g1(`SELECT COALESCE(SUM(monthly_value),0) as v FROM contracts WHERE status='active'`),
    g1(`SELECT COALESCE(SUM(fc.amount),0) as v FROM financial_charges fc JOIN contracts ct ON fc.contract_id=ct.id WHERE fc.status='paid' AND fc.paid_date>=? AND ct.type='seca'`,[ms]),
    g1(`SELECT COALESCE(SUM(fc.amount),0) as v FROM financial_charges fc JOIN contracts ct ON fc.contract_id=ct.id WHERE fc.status='paid' AND fc.paid_date>=? AND ct.type='molhada'`,[ms]),
    g1(`SELECT COALESCE(SUM(total),0) as v FROM store_orders WHERE status='paid' AND DATE(created_at)>=?`,[ms]),
    g1(`SELECT COUNT(*) as v FROM clients WHERE active=1`),
    g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier IN ('gold','vip')`),
    g1(`SELECT COUNT(*) as v FROM vessels WHERE active=1`),
    g1(`SELECT COUNT(*) as v FROM contracts WHERE status='active'`),
    g1(`SELECT COUNT(*) as v FROM queue_operations WHERE DATE(requested_at)=? AND status!='cancelled'`,[td]),
    g1(`SELECT COUNT(*) as v FROM queue_operations WHERE status IN ('waiting','in_progress')`),
    g1(`SELECT COUNT(*) as v FROM maintenance_os WHERE status IN ('open','in_progress')`),
    g1(`SELECT COUNT(*) as v FROM maintenance_os WHERE status IN ('open','in_progress') AND priority IN ('urgent','high')`),
    g1(`SELECT COALESCE(SUM(cost),0) as v FROM maintenance_os WHERE completed_date>=?`,[ms]),
    g1(`SELECT COUNT(*) as v FROM alerts WHERE read_at IS NULL`),
    g1(`SELECT AVG(total) as v FROM store_orders WHERE status='paid'`),
    g1(`SELECT AVG(ltv) as v FROM clients WHERE active=1`),
    g1(`SELECT AVG(EXTRACT(EPOCH FROM (completed_at-requested_at))/60) as avg_min FROM queue_operations WHERE status='completed' AND DATE(completed_at)>=?`,[ms]),
  ]);
  const ops_por_tipo = (await tAll(`SELECT operation_type, COUNT(*) as count FROM queue_operations WHERE DATE(requested_at)>=? GROUP BY operation_type`, [ago30])).map(r=>({...r,count:Number(r.count)}));
  sendJson(res, {
    ocupacao_total:   vagas_total    ? Math.round(vagas_ocupadas      /vagas_total    *1000)/10 : 0,
    ocupacao_seca:    vagas_seca_total    ? Math.round(vagas_seca_ocupadas    /vagas_seca_total    *1000)/10 : 0,
    ocupacao_molhada: vagas_molhada_total ? Math.round(vagas_molhada_ocupadas /vagas_molhada_total *1000)/10 : 0,
    vagas_total, vagas_ocupadas, vagas_seca_total, vagas_seca_ocupadas, vagas_molhada_total, vagas_molhada_ocupadas,
    receita_mes: n(rm?.v), inadimplencia: n(inad?.v), pendente: n(pend?.v), receita_seca: n(rs?.v), receita_molhada: n(rmol?.v), receita_loja: n(lm?.v),
    taxa_inadimplencia: n(tctv?.v) ? Math.round(n(inad?.v)/n(tctv?.v)*1000)/10 : 0,
    total_clientes: n(tc?.v), vip_count: n(vc?.v), total_vessels: n(tv?.v), contratos_ativos: n(ca?.v),
    queue_hoje: n(qh?.v), queue_aguardando: n(qa?.v),
    sla_avg_min: Math.round((n(sla?.avg_min))*10)/10,
    os_abertas: n(osab?.v), os_urgentes: n(osurg?.v), custo_manutencao_mes: n(cm?.v),
    alertas_nao_lidos: n(anl?.v),
    ticket_medio_loja: Math.round((n(tmed?.v))*100)/100,
    ltv_medio: Math.round((n(ltv?.v))*100)/100,
    ops_por_tipo,
  });
});

addRoute('GET', '/api/analytics/revenue-chart', async (req, res, ctx) => {
  const rows = await ctx.db.dbAll(`SELECT TO_CHAR(paid_date,'YYYY-MM') as month, COALESCE(SUM(amount),0) as total FROM financial_charges WHERE status='paid' AND paid_date IS NOT NULL GROUP BY TO_CHAR(paid_date,'YYYY-MM') ORDER BY TO_CHAR(paid_date,'YYYY-MM') DESC LIMIT 12`);
  sendJson(res, rows.reverse().map(r => ({ ...r, total: Number(r.total) })));
});

addRoute('GET', '/api/analytics/top-clients', async (req, res, ctx) => {
  const rows = await ctx.db.dbAll(`SELECT c.id, c.name, c.tier, c.ltv,
    COUNT(DISTINCT v.id) as vessels, COUNT(DISTINCT ct.id) as contracts
    FROM clients c
    LEFT JOIN vessels v ON v.client_id=c.id AND v.active=1
    LEFT JOIN contracts ct ON ct.client_id=c.id AND ct.status='active'
    WHERE c.active=1
    GROUP BY c.id, c.name, c.tier, c.ltv
    ORDER BY c.ltv DESC LIMIT 10`);
  sendJson(res, rows.map(r => ({ ...r, ltv: Number(r.ltv), vessels: Number(r.vessels), contracts: Number(r.contracts) })));
});

addRoute('GET', '/api/analytics/occupancy-trend', async (req, res, ctx) => {
  const rows = await ctx.db.dbAll(`SELECT TO_CHAR(start_date,'YYYY-MM-DD') as d, COUNT(*) as new_contracts FROM contracts GROUP BY TO_CHAR(start_date,'YYYY-MM-DD') ORDER BY d DESC LIMIT 30`);
  sendJson(res, rows.map(r => ({ ...r, new_contracts: Number(r.new_contracts) })));
});

addRoute('GET', '/api/analytics/forecast', async (req, res, ctx) => {
  const { dbAll: tAll, dbGet: tGet } = ctx.db;
  const currentYear = new Date().getFullYear();
  const year = parseInt(ctx.qs.year || currentYear, 10);
  const yStr = String(year);
  const from = `${yStr}-01`, to = `${yStr}-12`;

  // Anos disponíveis (union de due_date e paid_date)
  const [yDue, yPaid] = await Promise.all([
    tAll(`SELECT DISTINCT TO_CHAR(due_date,'YYYY') as y FROM financial_charges WHERE due_date IS NOT NULL ORDER BY y`),
    tAll(`SELECT DISTINCT TO_CHAR(paid_date,'YYYY') as y FROM financial_charges WHERE paid_date IS NOT NULL ORDER BY y`),
  ]);
  const yearsSet = new Set([...yDue, ...yPaid].map(r => parseInt(r.y)).filter(Boolean));
  yearsSet.add(currentYear);
  yearsSet.add(currentYear + 1); // próximo ano sempre disponível para planejamento
  const years = [...yearsSet].sort();

  // Previsto: todas as cobranças (não canceladas) agrupadas por due_date no ano
  const plannedRaw = await tAll(
    `SELECT TO_CHAR(due_date,'YYYY-MM') as month, COALESCE(SUM(amount),0) as total
     FROM financial_charges
     WHERE status != 'cancelled'
       AND TO_CHAR(due_date,'YYYY-MM') >= ? AND TO_CHAR(due_date,'YYYY-MM') <= ?
     GROUP BY TO_CHAR(due_date,'YYYY-MM') ORDER BY month ASC`,
    [from, to]
  );

  // Realizado: cobranças pagas agrupadas por paid_date no ano
  const actualRaw = await tAll(
    `SELECT TO_CHAR(paid_date,'YYYY-MM') as month, COALESCE(SUM(amount),0) as total
     FROM financial_charges
     WHERE status='paid' AND paid_date IS NOT NULL
       AND TO_CHAR(paid_date,'YYYY-MM') >= ? AND TO_CHAR(paid_date,'YYYY-MM') <= ?
     GROUP BY TO_CHAR(paid_date,'YYYY-MM') ORDER BY month ASC`,
    [from, to]
  );

  // Baseline de contratos ativos (valor mensal a ser faturado nos meses sem cobranças)
  const baselineRow = await tGet(`SELECT COALESCE(SUM(monthly_value),0) as v FROM contracts WHERE status='active'`);
  const baseline = Number(baselineRow?.v || 0);

  // Mapas mês → valor
  const plannedMap = {};
  for (const r of plannedRaw) plannedMap[r.month] = Number(r.total);
  const actualMap = {};
  for (const r of actualRaw) actualMap[r.month] = Number(r.total);

  const today = new Date();
  const currentYM = `${today.getFullYear()}-${String(today.getMonth()+1).padStart(2,'0')}`;
  const MONTHS_PT = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];

  const months = Array.from({length: 12}, (_, i) => {
    const m = `${yStr}-${String(i+1).padStart(2,'0')}`;
    const hasPrevisto = plannedMap[m] !== undefined;
    // Para meses futuros sem cobranças lançadas, usa o baseline de contratos
    const previsto = hasPrevisto ? plannedMap[m] : (m > currentYM ? baseline : 0);
    return {
      month:     m,
      label:     MONTHS_PT[i],
      label_short: MONTHS_PT[i].slice(0,3),
      previsto,
      realizado: actualMap[m] || 0,
      is_baseline: !hasPrevisto && m > currentYM,
      is_past:    m < currentYM,
      is_current: m === currentYM,
      is_future:  m > currentYM,
    };
  });

  const totalPrevisto  = months.reduce((s, m) => s + m.previsto, 0);
  const totalRealizado = months.reduce((s, m) => s + m.realizado, 0);
  const taxa = totalPrevisto > 0 ? Math.round(totalRealizado / totalPrevisto * 100) : 0;
  const avgPrevisto = totalPrevisto / 12;

  sendJson(res, { year, years, baseline, months, total_previsto: totalPrevisto, total_realizado: totalRealizado, taxa_realizacao: taxa, avg_mensal: avgPrevisto });
});

addRoute('GET', '/api/analytics/extended', async (req, res, ctx) => {
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  await checkOverdue(tRun);
  const ms = monthStart(), ago3m = daysAgo(90), ago6m = daysAgo(180);
  const g1 = (sql, a=[]) => tGet(sql, a);
  const n  = v => Number(v || 0);
  const [r3m,r6m,rtot,dm,cv30,cv7,vcar,cnm,ltxm,pm,pp,ot,om,ocm,ost,osc,ssl,sml] = await Promise.all([
    g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`,[ago3m]),
    g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`,[ago6m]),
    g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid'`),
    g1(`SELECT COALESCE(SUM(cost),0) as v FROM maintenance_os WHERE status='completed'`),
    g1(`SELECT COUNT(*) as v FROM contracts WHERE status='active' AND end_date<=?`,[daysAhead(30)]),
    g1(`SELECT COUNT(*) as v FROM contracts WHERE status='active' AND end_date<=?`,[daysAhead(7)]),
    g1(`SELECT COALESCE(SUM(monthly_value),0) as v FROM contracts WHERE status='active'`),
    g1(`SELECT COUNT(*) as v FROM clients WHERE DATE(created_at)>=?`,[ms]),
    g1(`SELECT MAX(ltv) as v FROM clients WHERE active=1`),
    g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='paid' AND DATE(created_at)>=?`,[ms]),
    g1(`SELECT COUNT(*) as v FROM store_orders WHERE status IN ('open','pending_payment')`),
    g1(`SELECT COUNT(*) as v FROM queue_operations`),
    g1(`SELECT COUNT(*) as v FROM queue_operations WHERE DATE(requested_at)>=?`,[ms]),
    g1(`SELECT COUNT(*) as v FROM queue_operations WHERE status='completed' AND DATE(completed_at)>=?`,[ms]),
    g1(`SELECT COUNT(*) as v FROM maintenance_os`),
    g1(`SELECT COUNT(*) as v FROM maintenance_os WHERE status='completed'`),
    g1(`SELECT COUNT(*) as v FROM spots WHERE type='seca' AND status='available'`),
    g1(`SELECT COUNT(*) as v FROM spots WHERE type='molhada' AND status='available'`),
  ]);
  const [_rmp,_lmp,_opt,_omp,_mpt,_cps,_tcl,vip,gold,silv,std] = await Promise.all([
    tAll(`SELECT TO_CHAR(paid_date,'YYYY-MM') as month, COALESCE(SUM(amount),0) as total, COUNT(*) as count FROM financial_charges WHERE status='paid' AND paid_date IS NOT NULL GROUP BY TO_CHAR(paid_date,'YYYY-MM') ORDER BY TO_CHAR(paid_date,'YYYY-MM') DESC LIMIT 12`),
    tAll(`SELECT TO_CHAR(created_at,'YYYY-MM') as month, COALESCE(SUM(total),0) as total, COUNT(*) as count FROM store_orders WHERE status='paid' GROUP BY TO_CHAR(created_at,'YYYY-MM') ORDER BY TO_CHAR(created_at,'YYYY-MM') DESC LIMIT 12`),
    tAll(`SELECT operation_type, COUNT(*) as count FROM queue_operations GROUP BY operation_type ORDER BY count DESC`),
    tAll(`SELECT TO_CHAR(requested_at,'YYYY-MM') as month, COUNT(*) as count FROM queue_operations GROUP BY TO_CHAR(requested_at,'YYYY-MM') ORDER BY TO_CHAR(requested_at,'YYYY-MM') DESC LIMIT 12`),
    tAll(`SELECT type, COUNT(*) as count, COALESCE(SUM(cost),0) as total FROM maintenance_os GROUP BY type`),
    tAll(`SELECT status, COUNT(*) as count, COALESCE(SUM(amount),0) as total FROM financial_charges GROUP BY status`),
    tAll(`SELECT c.name, c.tier, COALESCE(SUM(o.total),0) as total_loja, COUNT(o.id) as pedidos FROM clients c LEFT JOIN store_orders o ON o.client_id=c.id AND o.status='paid' WHERE c.active=1 GROUP BY c.id, c.name, c.tier ORDER BY total_loja DESC LIMIT 10`),
    g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='vip'`),
    g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='gold'`),
    g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='silver'`),
    g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='standard'`),
  ]);
  // Coerção numérica dos arrays com aggregates
  const rmp = _rmp.map(r=>({...r, total:Number(r.total), count:Number(r.count)}));
  const lmp = _lmp.map(r=>({...r, total:Number(r.total), count:Number(r.count)}));
  const opt = _opt.map(r=>({...r, count:Number(r.count)}));
  const omp = _omp.map(r=>({...r, count:Number(r.count)}));
  const mpt = _mpt.map(r=>({...r, count:Number(r.count), total:Number(r.total)}));
  const cps = _cps.map(r=>({...r, count:Number(r.count), total:Number(r.total)}));
  const tcl = _tcl.map(r=>({...r, total_loja:Number(r.total_loja), pedidos:Number(r.pedidos)}));

  const om_n = n(om?.v);
  sendJson(res, {
    receita_3m:n(r3m?.v), receita_6m:n(r6m?.v), receita_total:n(rtot?.v), despesas_manut:n(dm?.v),
    margem_bruta:n(rtot?.v)-n(dm?.v),
    contratos_vencendo_30d:n(cv30?.v), contratos_vencendo_7d:n(cv7?.v),
    valor_carteira:n(vcar?.v), valor_carteira_anual:n(vcar?.v)*12,
    clientes_novos_mes:n(cnm?.v), ltv_max:n(ltxm?.v),
    pedidos_mes:n(pm?.v), pedidos_pendentes:n(pp?.v),
    ops_total:n(ot?.v), ops_mes:om_n, ops_completed_mes:n(ocm?.v),
    taxa_conclusao: om_n>0 ? Math.round(n(ocm?.v)/om_n*100) : 0,
    os_total:n(ost?.v), os_concluidas:n(osc?.v),
    taxa_resolucao_os: n(ost?.v)>0 ? Math.round(n(osc?.v)/n(ost?.v)*100) : 0,
    spots_seca_livre:n(ssl?.v), spots_mol_livre:n(sml?.v),
    receita_por_mes: rmp.reverse(), loja_por_mes: lmp.reverse(), ops_por_tipo: opt, ops_por_mes: omp.reverse(),
    manut_por_tipo: mpt, charges_por_status: cps, top_clientes_loja: tcl,
    vip_count:n(vip?.v), gold_count:n(gold?.v), silver_count:n(silv?.v), std_count:n(std?.v),
  });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — CONFIGURAÇÕES + SYSTEM LOGS
// ═════════════════════════════════════════════════════════════════════
addRoute('GET', '/api/settings', async (req, res, ctx) => {
  const s = await getSettings(ctx.db.dbAll);
  // Garante que license_marina_id está sempre preenchido com o slug do tenant
  if (!s.license_marina_id && ctx.tenantSlug) s.license_marina_id = ctx.tenantSlug;
  sendJson(res, s);
});

addRoute('PUT', '/api/settings', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbRun: tRun } = ctx.db;
  for (const [k, v] of Object.entries(ctx.body || {})) {
    await tRun(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,NOW())
                ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
               [k, String(v)]);
  }
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/system-logs', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { limit: lim = '100', action = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT * FROM system_logs WHERE 1=1';
  const a = [];
  if (action) { sql += ' AND action=?'; a.push(action); }
  sql += ` ORDER BY created_at DESC LIMIT ${Math.min(parseInt(lim)||100, 500)}`;
  sendJson(res, await tAll(sql, a));
});

// ═════════════════════════════════════════════════════════════════════
//  SERVIDOR HTTP
// ═════════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const urlpath = (req.url || '/').split('?')[0];

  // ── Serve frontend ─────────────────────────────────────────────────
  if (req.method === 'GET' && (urlpath === '/' || urlpath === '/index.html' || urlpath === '/frontend.html')) {
    try {
      let html = fs.readFileSync(path.join(__dirname, 'frontend.html'), 'utf8');
      // Injeta variáveis de ambiente no frontend para resolução de subdomínio
      const inject = `<script>
window.BASE_DOMAIN="${(process.env.BASE_DOMAIN||'').replace(/"/g,'')}";
window.APP_ENV="${process.env.NODE_ENV||'development'}";
window.APP_VERSION="${APP_VERSION}";
</script>`;
      html = html.replace('</head>', inject + '</head>');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch { res.writeHead(404); return res.end('Not found'); }
  }

  // ── Rotas da API ────────────────────────────────────────────────────
  if (!urlpath.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }

  try {
    const body = req.method !== 'GET' ? await parseBody(req) : {};
    const qs   = getQS(req.url || '');

    // Contexto base
    const ctx = { body, qs, params: {}, user: null, tenantSlug: null, tenant: null, db: null };

    // ── Middleware: tenant ───────────────────────────────────────────
    let tenantResolved = false;
    await tenantMiddleware(req, res, () => { tenantResolved = true; });
    if (!tenantResolved) return; // tenant middleware já respondeu

    ctx.tenantSlug = req.tenantSlug;
    ctx.tenant     = req.tenant;

    // Cria helpers DB específicos do tenant (exceto rotas sem tenant)
    if (ctx.tenantSlug) {
      ctx.db = createDbHelpers(ctx.tenantSlug);
    }

    // ── Middleware: auth ─────────────────────────────────────────────
    let authResolved = false;
    authMiddleware(req, res, () => { authResolved = true; });
    if (!authResolved) return;
    ctx.user = req.user;

    // ── Despacha rota ────────────────────────────────────────────────
    const match = matchRoute(req.method, urlpath);
    if (!match) {
      return sendJson(res, { error: 'Rota não encontrada' }, 404);
    }
    ctx.params = match.params;
    await match.fn(req, res, ctx);

  } catch (err) {
    console.error('[server] Erro:', err.message, err.stack);
    sendJson(res, { error: 'Erro interno do servidor' }, 500);
  }
});

// ═════════════════════════════════════════════════════════════════════
//  BOOT
// ═════════════════════════════════════════════════════════════════════
async function boot() {
  console.log(`\n🚢  Marina One v${APP_VERSION} (SaaS Multi-Tenant)`);
  console.log('    Node.js:', process.version);
  console.log('    Banco:   PostgreSQL (via postgres.js)');

  // 1. Inicializa schema global saas
  await initSaasSchema();

  // 2. Se SINGLE_TENANT_SLUG definido, garante que o tenant existe e está migrado
  if (process.env.SINGLE_TENANT_SLUG) {
    const slug = process.env.SINGLE_TENANT_SLUG;
    const name = process.env.SINGLE_TENANT_NAME || slug;
    console.log(`\n    Modo single-tenant: ${slug}`);
    await provisionTenant(slug, {
      marinaName:    name,
      adminEmail:    process.env.ADMIN_EMAIL    || 'admin@marina.com',
      adminPassword: process.env.ADMIN_PASSWORD || 'marina123',
    });
  }

  server.listen(PORT, () => {
    console.log(`\n✅  Servidor iniciado em http://localhost:${PORT}`);
    if (GIT_HASH) console.log(`    Commit: ${GIT_HASH}`);
    console.log('');
  });
}

boot().catch(err => {
  console.error('❌  Falha no boot:', err);
  process.exit(1);
});
