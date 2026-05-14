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
const { jwtSign, bcryptHash, verifyPassword, checkRateLimit, resetRateLimit, authMiddleware } = require('./src/middleware/auth');

// ── Constantes ───────────────────────────────────────────────────────
const MODULES = [
  { key: 'dashboard',   label: 'Dashboard',         group: 'Principal' },
  { key: 'queue',       label: 'Fila de Operações', group: 'Principal' },
  { key: 'clients',     label: 'Clientes',          group: 'Gestão'    },
  { key: 'vessels',     label: 'Embarcações',       group: 'Gestão'    },
  { key: 'spots',       label: 'Vagas',             group: 'Gestão'    },
  { key: 'contracts',   label: 'Contratos',         group: 'Gestão'    },
  { key: 'financial',   label: 'Financeiro',        group: 'Operações' },
  { key: 'store',        label: 'Loja / PDV',        group: 'Operações' },
  { key: 'conveniencia', label: 'Conveniência',      group: 'Operações' },
  { key: 'totem',        label: 'Totem',             group: 'Operações' },
  { key: 'maintenance',  label: 'Manutenção',        group: 'Operações' },
  { key: 'analytics',   label: 'Analytics',         group: 'Análise'   },
  { key: 'alerts',      label: 'Alertas',           group: 'Análise'   },
  { key: 'copilot',     label: 'Co-piloto IA',      group: 'IA'        },
  { key: 'settings',    label: 'Configurações',     group: 'Sistema'   },
];
const MODULE_KEYS  = MODULES.map(m => m.key);
const VALID_ROLES  = ['admin', 'operador', 'loja', 'cliente', 'totem'];
// Roles que recebem alertas (totem é kiosk — sem dashboard de alertas)
const ALERT_ROLES  = VALID_ROLES.filter(r => r !== 'totem');

// Carrega roles do banco; fallback para VALID_ROLES se tabela ainda não existir
async function getAllRoles(tAll) {
  try {
    return await tAll(`SELECT key, label, description, color, icon, is_system, active FROM roles WHERE active=TRUE ORDER BY is_system DESC, key ASC`);
  } catch { return VALID_ROLES.map(k => ({ key: k, label: k, is_system: true, active: true })); }
}
async function isValidRole(role, tAll) {
  const roles = await getAllRoles(tAll);
  return roles.some(r => r.key === role);
}
// Definição canônica de todos os tipos de alerta do sistema
const ALERT_TYPE_DEFS = [
  { key: 'queue_warning',      label: 'Operação próxima do início',       description: 'Faltam ≤20% do tempo até o início agendado',                module: 'Fila',       sort: 1 },
  { key: 'queue_overdue',      label: 'Operação não iniciada no horário', description: 'Horário previsto passou sem a operação ser iniciada',          module: 'Fila',       sort: 2 },
  { key: 'queue_inconsistent', label: 'Operação inconsistente',           description: 'Operação inválida para o estado atual da embarcação',          module: 'Fila',       sort: 3 },
  { key: 'queue_delayed',      label: 'Operação em atraso',               description: 'Operação em andamento ultrapassou a duração estimada',         module: 'Fila',       sort: 4 },
  { key: 'financial_overdue',  label: 'Parcela vencida',                  description: 'Cobrança com vencimento passado sem pagamento registrado',     module: 'Financeiro', sort: 5 },
  { key: 'stock_zero',         label: 'Estoque zerado',                   description: 'Item da loja com estoque igual a zero',                       module: 'Loja',       sort: 6 },
  { key: 'stock_low',          label: 'Estoque abaixo do mínimo',         description: 'Item com estoque abaixo do nível mínimo configurado',          module: 'Loja',       sort: 7 },
];

// Sub-módulos por módulo (abas internas com controle granular)
const SUBMODULES = {
  queue: [
    { key: 'ativa',        label: 'Fila Ativa',       actions: ['view','create','edit','delete'] },
    { key: 'calendario',   label: 'Calendário',        actions: ['view'] },
    { key: 'historico',    label: 'Histórico',         actions: ['view'] },
  ],
  store: [
    { key: 'dashboard',    label: 'Dashboard',         actions: ['view'] },
    { key: 'pdv',          label: 'PDV',               actions: ['view','create'] },
    { key: 'orders',       label: 'Pedidos',           actions: ['view','edit'] },
    { key: 'contas',       label: 'Contas / Fiados',   actions: ['view','create','edit'] },
    { key: 'estoque',      label: 'Estoque',           actions: ['view','create','edit','delete'] },
    { key: 'gestao',       label: 'Gestão',            actions: ['view','create','edit','delete'] },
  ],
  analytics: [
    { key: 'visao',        label: 'Visão Geral',       actions: ['view'] },
    { key: 'financeiro',   label: 'Financeiro',        actions: ['view'] },
    { key: 'previsao',     label: 'Previsão',          actions: ['view'] },
    { key: 'ocupacao',     label: 'Ocupação',          actions: ['view'] },
    { key: 'operacoes',    label: 'Operações',         actions: ['view'] },
    { key: 'clientes',     label: 'Clientes',          actions: ['view'] },
  ],
  copilot: [
    { key: 'chat',         label: 'Chat IA',                 actions: ['view','create'] },
  ],
  settings: [
    { key: 'marina',       label: 'Marina',                  actions: ['view','edit'] },
    { key: 'financeiro',   label: 'Financeiro',              actions: ['view','edit'] },
    { key: 'notificacoes', label: 'Notificações',            actions: ['view','edit'] },
    { key: 'operacoes',    label: 'Operações',               actions: ['view','edit'] },
    { key: 'alertas',      label: 'Configuração de Alertas', actions: ['view','edit'] },
    { key: 'perfis',       label: 'Gestão de Perfis',        actions: ['view','create','edit','delete'] },
    { key: 'logs',         label: 'Logs do Sistema',         actions: ['view'] },
    { key: 'licenca',      label: 'Licença',                 actions: ['view'] },
  ],
};
// Mapa invertido sub-key → module (para validação)
const SUBMODULE_KEYS = {};
for (const [mod, subs] of Object.entries(SUBMODULES)) {
  for (const s of subs) SUBMODULE_KEYS[`${mod}.${s.key}`] = true;
}

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

// ── Date helpers (BRT = UTC-3, Brasil sem horário de verão desde 2019) ──
const _pad = n => String(n).padStart(2, '0');
const BRT_OFFSET_MS = -3 * 60 * 60 * 1000; // UTC-3 fixo
const _brt = (d = new Date()) => new Date(d.getTime() + BRT_OFFSET_MS);

const _localDate = (d = new Date()) => {
  const b = _brt(d);
  return `${b.getUTCFullYear()}-${_pad(b.getUTCMonth()+1)}-${_pad(b.getUTCDate())}`;
};
const _localDateTime = (d = new Date()) => {
  const b = _brt(d);
  return `${b.getUTCFullYear()}-${_pad(b.getUTCMonth()+1)}-${_pad(b.getUTCDate())} ${_pad(b.getUTCHours())}:${_pad(b.getUTCMinutes())}:${_pad(b.getUTCSeconds())}`;
};
const nowStr   = () => _localDateTime();
const todayStr = () => _localDate();
function monthStart() { const b = _brt(); return `${b.getUTCFullYear()}-${_pad(b.getUTCMonth()+1)}-01`; }
function daysAgo(n)   { return _localDate(new Date(Date.now() - n * 86400000)); }
function daysAhead(n) { return _localDate(new Date(Date.now() + n * 86400000)); }

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
  const row = await dbGet("SELECT * FROM role_permissions WHERE role=? AND module=? AND submodule=''", [user.role, module]);
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
    for (const m of MODULE_KEYS) {
      out[m] = { view: true, create: true, edit: true, delete: true, subs: {} };
      if (SUBMODULES[m]) for (const s of SUBMODULES[m]) out[m].subs[s.key] = { view: true, create: true, edit: true, delete: true };
    }
    return out;
  }
  const rows = await dbAll('SELECT * FROM role_permissions WHERE role=?', [role]);
  const out = {};
  for (const m of MODULE_KEYS) {
    out[m] = { view: false, create: false, edit: false, delete: false, subs: {} };
    if (SUBMODULES[m]) for (const s of SUBMODULES[m]) out[m].subs[s.key] = null; // null = não seeded
  }
  const hasSubs = {};
  for (const r of rows) {
    const entry = { view: r.can_view === 1, create: r.can_create === 1, edit: r.can_edit === 1, delete: r.can_delete === 1 };
    if (!r.submodule) {
      if (out[r.module] !== undefined) out[r.module] = { ...out[r.module], ...entry };
    } else {
      if (out[r.module]) { out[r.module].subs[r.submodule] = entry; hasSubs[r.module] = true; }
    }
  }
  // Fallback: sem linhas de sub-módulo → herda permissão do módulo
  for (const m of MODULE_KEYS) {
    if (!SUBMODULES[m]) continue;
    const modPerm = out[m];
    for (const s of SUBMODULES[m]) {
      if (out[m].subs[s.key] === null) {
        out[m].subs[s.key] = hasSubs[m]
          ? { view: false, create: false, edit: false, delete: false }
          : { view: modPerm.view, create: modPerm.create, edit: modPerm.edit, delete: modPerm.delete };
      }
    }
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
                [email, await bcryptHash(initialPwd), b.name, 'cliente', clientId]);
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
function applyEstimatedTimes(enriched, maneuver, opsStart, opsEnd, lastCompletedAt) {
  const now = new Date();

  // Converte "HH:MM" para minutos desde meia-noite
  const hhmm2min = s => { const [h, m] = (s || '00:00').split(':').map(Number); return h * 60 + m; };

  // Minutos desde meia-noite em BRT (independente do TZ do servidor)
  const brtMinOfDay = (date) => { const b = _brt(date); return b.getUTCHours() * 60 + b.getUTCMinutes(); };

  // Define hora BRT em um objeto Date (converte BRT→UTC: +3h)
  const setBrtHhmm = (date, totalBrtMin) => {
    const r = new Date(date);
    r.setUTCHours(Math.floor(totalBrtMin / 60) + 3, totalBrtMin % 60, 0, 0);
    return r;
  };

  // Garante que o cursor respeita o horário de início das operações
  const clampToOpsStart = (date) => {
    if (!opsStart) return date;
    const startMin = hhmm2min(opsStart);
    const dateMin  = brtMinOfDay(date);
    if (dateMin < startMin) return setBrtHhmm(date, startMin);
    return date;
  };

  // Cursor inicial: agora + 1min (buffer mínimo) ou horário de início das operações (o que for maior)
  const nowPlus1 = new Date(now.getTime() + 60000);

  const endMin  = hhmm2min(opsEnd);

  // Garante que o cursor não passa do horário de encerramento
  const clampToOpsEnd = (date) => {
    if (!opsEnd) return date;
    const dateMin = brtMinOfDay(date);
    if (dateMin > endMin) return setBrtHhmm(date, endMin);
    return date;
  };

  // Piso mínimo considerando última op concluída + manobra (evita regressão e garante intervalo após conclusão)
  let minCursor = clampToOpsStart(nowPlus1);
  if (lastCompletedAt) {
    const lc = lastCompletedAt instanceof Date ? lastCompletedAt : new Date(lastCompletedAt);
    if (!isNaN(lc)) {
      const afterLast = clampToOpsStart(new Date(lc.getTime() + maneuver * 60000));
      if (afterLast > minCursor) minCursor = afterLast;
    }
  }

  const inProg = enriched.find(r => r.status === 'in_progress');
  if (inProg && inProg.started_at) {
    // started_at vem como ISO Z string do compat.js (ex: "2026-05-05T12:30:00.000Z")
    // new Date() de string ISO com Z é sempre UTC — correto
    const startedAt = inProg.started_at instanceof Date
      ? inProg.started_at
      : new Date(inProg.started_at);
    const endTime = new Date(startedAt.getTime() + (inProg.estimated_duration_min || 0) * 60000);
    const effectiveEnd = isNaN(endTime) || endTime < now ? new Date(now) : endTime;
    inProg.estimated_end_at = clampToOpsEnd(effectiveEnd).toISOString();
    let cur = new Date(effectiveEnd);
    cur.setMinutes(cur.getMinutes() + maneuver);
    cur = clampToOpsStart(clampToOpsEnd(cur));
    minCursor = cur > minCursor ? cur : minCursor;
  } else {
    // Sem op em andamento: âncora no requested_at da primeira waiting + manobra
    // → horário fica FIXO enquanto agora < agendado; quando passa, mantém minCursor (lastCompleted+manobra ou now+1min)
    const firstWaiting = enriched.find(r => r.status === 'waiting');
    if (firstWaiting && firstWaiting.requested_at) {
      const reqAt    = new Date(firstWaiting.requested_at);
      const base     = clampToOpsStart(new Date(reqAt.getTime() + 60000));
      const anchored = clampToOpsStart(new Date(base.getTime() + maneuver * 60000));
      // Se o agendamento ainda está no futuro: usa âncora fixa; senão mantém minCursor (sem re-somar manobra)
      if (anchored > minCursor) minCursor = anchored;
    }
  }
  let cursor = minCursor;

  for (const row of enriched) {
    if (row.status === 'in_progress') continue;
    if (row.status === 'waiting') {
      if (brtMinOfDay(cursor) >= endMin) break; // sem espaço após horário limite
      row.estimated_start_at = cursor.toISOString();
      const end = new Date(cursor);
      end.setMinutes(end.getMinutes() + (row.estimated_duration_min || 0));
      row.estimated_end_at = clampToOpsEnd(end).toISOString();
      cursor = new Date(end);
      cursor.setMinutes(cursor.getMinutes() + maneuver);
      cursor = clampToOpsStart(clampToOpsEnd(cursor));
    }
  }
}
// Auto-conclui ops in_progress de dias anteriores para evitar "preso no calendário"
async function cleanupStaleQueueOps(tAll, tRun) {
  try {
    const stale = await tAll(
      `SELECT id FROM queue_operations WHERE status='in_progress' AND started_at IS NOT NULL AND DATE(started_at) < CURRENT_DATE`
    );
    for (const op of stale) {
      await tRun(
        `UPDATE queue_operations SET status='completed', completed_at=?, notes=COALESCE(notes,'') || ' [Auto-concluído: operação não finalizada no dia]' WHERE id=?`,
        [nowStr(), op.id]
      );
      console.log(`[queue] Auto-concluída op stale id=${op.id} (in_progress de dia anterior)`);
    }
  } catch (e) {
    console.error('[queue] cleanupStaleQueueOps:', e.message);
  }
}

// Formata Date em HH:MM no fuso BRT
function fmtTimeBrt(date) {
  const b = _brt(date);
  return `${String(b.getUTCHours()).padStart(2,'0')}:${String(b.getUTCMinutes()).padStart(2,'0')}`;
}

// Calcula horários âncora fixos (baseados em requested_at, não em now)
// para uso na detecção de alertas — evita falsos positivos durante o shift de display
function computeAnchoredTimes(enriched, maneuver, opsStart, opsEnd) {
  const hhmm2min    = s => { const [h, m] = (s||'00:00').split(':').map(Number); return h*60+m; };
  const brtMinOfDay = d => { const b = _brt(d); return b.getUTCHours()*60 + b.getUTCMinutes(); };
  const setBrtHhmm  = (d, min) => { const r = new Date(d); r.setUTCHours(Math.floor(min/60)+3, min%60, 0, 0); return r; };
  const clampS = d => { const sm = hhmm2min(opsStart); const dm = brtMinOfDay(d); return dm < sm ? setBrtHhmm(d, sm) : d; };
  const clampE = d => { if (!opsEnd) return d; const em = hhmm2min(opsEnd); const dm = brtMinOfDay(d); return dm > em ? setBrtHhmm(d, em) : d; };

  const anchors = {};
  const inProg  = enriched.find(r => r.status === 'in_progress');
  let cursor;

  if (inProg && inProg.started_at) {
    const sa  = inProg.started_at instanceof Date ? inProg.started_at : new Date(inProg.started_at);
    const end = new Date(sa.getTime() + (inProg.estimated_duration_min || 0) * 60000);
    cursor = clampS(clampE(new Date(end.getTime() + maneuver * 60000)));
  } else {
    const first = enriched.find(r => r.status === 'waiting');
    if (!first || !first.requested_at) return anchors;
    const reqAt = new Date(first.requested_at);
    const base  = clampS(new Date(reqAt.getTime() + 60000));
    cursor = clampS(new Date(base.getTime() + maneuver * 60000));
  }

  for (const row of enriched) {
    if (row.status !== 'waiting') continue;
    anchors[row.id] = new Date(cursor);
    const end = new Date(cursor.getTime() + (row.estimated_duration_min || 0) * 60000);
    cursor = clampS(clampE(new Date(end.getTime() + maneuver * 60000)));
  }
  return anchors;
}

// Gera alertas de fila: yellow (20% do tempo restante) e red (atraso)
async function checkQueueAlerts(enriched, settings, tAll, tRun) {
  const now      = new Date();
  const maneuver = getManeuverTime(settings);
  const opsStart = settings['ops_start_time'] || '07:00';
  const opsEnd   = settings['ops_end_time']   || '18:00';
  const anchors  = computeAnchoredTimes(enriched, maneuver, opsStart, opsEnd);

  for (const op of enriched) {
    if (op.status !== 'waiting') continue;
    const anchor = anchors[op.id];
    if (!anchor) continue;

    const reqAt        = new Date(op.requested_at);
    const totalWindow  = anchor - reqAt;        // ms
    const timeUntil    = anchor - now;           // ms

    if (timeUntil <= 0) {
      await tRun(
        `INSERT OR IGNORE INTO queue_alerts(operation_id, vessel_name, client_name, operation_type, alert_type, message)
         VALUES(?,?,?,?,'overdue',?)`,
        [op.id, op.vessel_name, op.client_name, op.operation_type,
         `Operação não iniciada: ${op.vessel_name} (${op.operation_type}) prevista para ${fmtTimeBrt(anchor)}`]
      );
    } else if (totalWindow > 0 && timeUntil / totalWindow <= 0.20) {
      await tRun(
        `INSERT OR IGNORE INTO queue_alerts(operation_id, vessel_name, client_name, operation_type, alert_type, message)
         VALUES(?,?,?,?,'warning',?)`,
        [op.id, op.vessel_name, op.client_name, op.operation_type,
         `Próxima operação: ${op.vessel_name} (${op.operation_type}) em ${Math.ceil(timeUntil/60000)}min (${fmtTimeBrt(anchor)})`]
      );
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

// Marca da plataforma SA — pública, sem auth (usada na tela de login SA)
addRoute('GET', '/api/sa-brand', async (req, res) => {
  const { saasGet: sGet } = createSaasHelpers();
  const name = (await sGet(`SELECT value FROM saas.settings WHERE key='general_system_name'`))?.value || 'Marina One';
  const logo = (await sGet(`SELECT value FROM saas.settings WHERE key='general_logo'`))?.value || '';
  sendJson(res, { name, logo });
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — SUPER-ADMIN (/api/superadmin/*)
// ═════════════════════════════════════════════════════════════════════
const { saasAll, saasGet, saasRun } = createSaasHelpers();

// OTPs de recuperação em memória: email → { otp, expires }
const _saOtps = new Map();

addRoute('POST', '/api/superadmin/auth/login', async (req, res, ctx) => {
  if (!checkRateLimit(req)) return sendJson(res, { error: 'Muitas tentativas. Aguarde 15 minutos.' }, 429);
  const { email = '', password = '' } = ctx.body;
  const admin = await saasGet('SELECT * FROM saas.super_admins WHERE email=$1', [email.toLowerCase()]);
  const { ok, needsRehash } = await verifyPassword(password, admin?.password_hash || '');
  if (!admin || !ok) return sendJson(res, { error: 'Credenciais inválidas' }, 401);
  resetRateLimit(req);
  if (needsRehash) {
    await saasRun('UPDATE saas.super_admins SET password_hash=$1 WHERE id=$2', [await bcryptHash(password), admin.id]);
  }
  const token = jwtSign({ super_admin_id: admin.id, email: admin.email, name: admin.name, role: 'superadmin' }, 86400);
  sendJson(res, { token, admin: { id: admin.id, name: admin.name, email: admin.email } });
});

addRoute('POST', '/api/superadmin/auth/forgot', async (req, res) => {
  const { email = '' } = req.body || {};
  const admin = await saasGet('SELECT id, email FROM saas.super_admins WHERE email=$1', [email.toLowerCase()]);
  if (!admin) return sendJson(res, { ok: true }); // não revelar se email existe
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  _saOtps.set(admin.email, { otp, expires: Date.now() + 10 * 60 * 1000 });
  console.log(`\n⚠️  SUPER-ADMIN RESET OTP para ${admin.email}: ${otp}  (válido 10 min)\n`);
  sendJson(res, { ok: true });
});

addRoute('POST', '/api/superadmin/auth/reset', async (req, res) => {
  const { email = '', otp = '', new_password = '' } = req.body || {};
  if (!new_password || new_password.length < 6) return sendJson(res, { error: 'Nova senha muito curta (mín. 6 caracteres)' }, 400);
  const admin = await saasGet('SELECT id, email FROM saas.super_admins WHERE email=$1', [email.toLowerCase()]);
  const entry = _saOtps.get(email.toLowerCase());
  if (!admin || !entry || entry.otp !== otp || Date.now() > entry.expires) {
    return sendJson(res, { error: 'Código inválido ou expirado' }, 401);
  }
  _saOtps.delete(email.toLowerCase());
  await saasRun('UPDATE saas.super_admins SET password_hash=$1 WHERE id=$2', [await bcryptHash(new_password), admin.id]);
  sendJson(res, { ok: true });
});

function requireSuperAdmin(ctx, res) {
  if (!ctx.user || ctx.user.role !== 'superadmin') {
    sendJson(res, { error: 'Acesso restrito ao super-admin' }, 403);
    return false;
  }
  return true;
}

addRoute('PUT', '/api/superadmin/profile', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { new_email, current_password, new_password } = ctx.body || {};
  if (!current_password) return sendJson(res, { error: 'Senha atual obrigatória' }, 400);
  const admin = await saasGet('SELECT * FROM saas.super_admins WHERE id=$1', [ctx.user.super_admin_id]);
  if (!admin) return sendJson(res, { error: 'Admin não encontrado' }, 404);
  const { ok } = await verifyPassword(current_password, admin.password_hash);
  if (!ok) return sendJson(res, { error: 'Senha atual incorreta' }, 422);
  if (new_email) {
    const dup = await saasGet('SELECT id FROM saas.super_admins WHERE email=$1 AND id<>$2', [new_email.toLowerCase(), admin.id]);
    if (dup) return sendJson(res, { error: 'E-mail já em uso' }, 409);
    await saasRun('UPDATE saas.super_admins SET email=$1 WHERE id=$2', [new_email.toLowerCase(), admin.id]);
  }
  if (new_password) {
    await saasRun('UPDATE saas.super_admins SET password_hash=$1 WHERE id=$2', [await bcryptHash(new_password), admin.id]);
  }
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/superadmin/tenants', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const tenants = await saasAll(`
    SELECT t.*,
           lx.license_name,
           lx.license_slug,
           lx.license_status,
           (EXISTS(
             SELECT 1 FROM saas.license_contracts lc
             WHERE lc.tenant_slug = t.slug AND lc.status = 'active'
           )) AS has_active_contract
    FROM saas.tenants t
    LEFT JOIN LATERAL (
      SELECT lt.name AS license_name, lt.slug AS license_slug, tl.status AS license_status
      FROM saas.tenant_licenses tl
      JOIN saas.license_types lt ON lt.id = tl.license_type_id
      WHERE tl.tenant_id = t.id
        AND tl.status = 'active'
        AND (tl.ends_at IS NULL OR tl.ends_at >= CURRENT_DATE)
      ORDER BY tl.created_at DESC
      LIMIT 1
    ) lx ON TRUE
    ORDER BY t.created_at DESC
  `);
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
    const planSlug = plan || 'starter';
    await provisionTenant(cleanSlug, {
      marinaName: name, plan: planSlug,
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
    // Cria licença técnica correspondente ao plano — sem isso todos os módulos ficam liberados
    await _syncTenantLicense(cleanSlug, planSlug, null);
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

addRoute('DELETE', '/api/superadmin/tenants/:slug', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { slug } = ctx.params;
  const { confirm_slug } = ctx.body || {};
  if (confirm_slug !== slug) return sendJson(res, { error: 'Confirmação incorreta' }, 400);
  const tenant = await saasGet('SELECT * FROM saas.tenants WHERE slug=$1', [slug]);
  if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);
  if (tenant.active) return sendJson(res, { error: 'Desative o tenant antes de excluí-lo' }, 409);
  const { slugToSchema, evictTenantPool } = require('./src/db/pool');
  const schemaName = slugToSchema(slug);
  await evictTenantPool(slug);
  await getGlobalPool().unsafe(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`);
  await saasRun('DELETE FROM saas.tenants WHERE slug=$1', [slug]);
  console.log(`[superadmin] Tenant "${slug}" excluído por ${ctx.user.email}`);
  sendJson(res, { ok: true });
});

addRoute('PUT', '/api/superadmin/tenants/:slug', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { name, plan, active, cnpj, address, city_state,
          representative_name, representative_cpf, representative_role } = ctx.body || {};
  await saasRun(
    `UPDATE saas.tenants SET
       name                = COALESCE($1, name),
       plan                = COALESCE($2, plan),
       active              = COALESCE($3, active),
       cnpj                = COALESCE($4, cnpj),
       address             = COALESCE($5, address),
       city_state          = COALESCE($6, city_state),
       representative_name = COALESCE($7, representative_name),
       representative_cpf  = COALESCE($8, representative_cpf),
       representative_role = COALESCE($9, representative_role)
     WHERE slug = $10`,
    [name||null, plan||null, active !== undefined ? active : null,
     cnpj||null, address||null, city_state||null,
     representative_name||null, representative_cpf||null, representative_role||null,
     ctx.params.slug]
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
               [await bcryptHash(new_password), user.id]);
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

addRoute('PUT', '/api/superadmin/tenants/:slug/change-admin-email', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const slug = ctx.params.slug;
  const { old_email, new_email } = ctx.body || {};
  if (!new_email || !new_email.includes('@'))
    return sendJson(res, { error: 'E-mail inválido' }, 400);
  try {
    const { dbRun: tRun, dbGet: tGet } = createDbHelpers(slug);
    // Encontra o admin pelo e-mail antigo ou pelo primeiro admin do tenant
    const user = old_email
      ? await tGet('SELECT id FROM users WHERE email=? AND role=?', [old_email.toLowerCase(), 'admin'])
      : await tGet("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1", []);
    if (!user) return sendJson(res, { error: 'Admin não encontrado' }, 404);
    // Verifica se o novo e-mail já está em uso
    const conflict = await tGet('SELECT id FROM users WHERE email=? AND id!=?', [new_email.toLowerCase(), user.id]);
    if (conflict) return sendJson(res, { error: 'Esse e-mail já está em uso por outro usuário' }, 409);
    await tRun('UPDATE users SET email=? WHERE id=?', [new_email.toLowerCase(), user.id]);
    // Atualiza também no registro saas
    await saasRun('UPDATE saas.tenants SET admin_email=$1 WHERE slug=$2', [new_email.toLowerCase(), slug]);
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
           contracts, spots_seca, spots_molhada, settings_rows, licenseRow] = await Promise.all([
      tGet('SELECT COUNT(*) as n FROM clients WHERE active=1'),
      tGet('SELECT COUNT(*) as n FROM vessels WHERE active=1'),
      tGet('SELECT COUNT(*) as n FROM users WHERE active=1'),
      tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid'`),
      tGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`, [ms]),
      tGet(`SELECT COUNT(*) as n FROM contracts WHERE status='active'`),
      tGet(`SELECT COUNT(*) as n FROM spots WHERE type='seca'`),
      tGet(`SELECT COUNT(*) as n FROM spots WHERE type='molhada'`),
      tAll(`SELECT key, value FROM settings WHERE key IN ('marina_logo','marina_name','marina_email','marina_phone','marina_cnpj','marina_city','marina_state')`),
      // Fonte única de licença: saas.tenant_licenses → saas.license_types
      saasGet(
        `SELECT lt.name AS license_name, lt.slug AS license_slug,
                tl.status AS license_status, tl.ends_at AS license_until
         FROM saas.tenant_licenses tl
         JOIN saas.license_types lt ON lt.id = tl.license_type_id
         JOIN saas.tenants t ON t.id = tl.tenant_id
         WHERE t.slug = $1
           AND tl.status = 'active'
           AND (tl.ends_at IS NULL OR tl.ends_at >= CURRENT_DATE)
         ORDER BY tl.created_at DESC
         LIMIT 1`,
        [ctx.params.slug]
      ),
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
      // Licença vem exclusivamente de saas.tenant_licenses
      license_plan:    licenseRow?.license_name  || '',
      license_slug:    licenseRow?.license_slug  || '',
      license_status:  licenseRow?.license_status || '',
      license_until:   licenseRow?.license_until  || '',
    });
  } catch (e) {
    sendJson(res, { error: e.message }, 500);
  }
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — SUPER-ADMIN: CONTRATOS + FINANCEIRO SAAS
// ═════════════════════════════════════════════════════════════════════

// Marcar parcelas vencidas automaticamente
async function saasCheckOverdue() {
  const today = todayStr();
  await saasRun(
    `UPDATE saas.license_charges SET status='overdue'
     WHERE status='pending' AND due_date < $1`,
    [today]
  );
}

// Gerar parcelas mensais para um contrato
async function generateLicenseCharges(contractId, tenantSlug, plan, amount, startDate, endDate) {
  const start  = new Date(startDate + 'T12:00:00Z');
  const end    = endDate ? new Date(endDate + 'T12:00:00Z') : null;
  const planLabel = { starter:'Starter', pro:'Pro', professional:'Pro', enterprise:'Enterprise', custom:'Custom' };
  const label  = planLabel[plan] || plan;
  const charges = [];
  let cur = new Date(start);
  const max = 120;
  while (charges.length < max) {
    if (end && cur > end) break;
    const mm = String(cur.getUTCMonth() + 1).padStart(2, '0');
    const yyyy = cur.getUTCFullYear();
    const dd = String(cur.getUTCDate()).padStart(2, '0');
    charges.push({
      due_date:    `${yyyy}-${mm}-${dd}`,
      description: `Licença ${label} — ${mm}/${yyyy}`,
    });
    // próximo mês
    const nextMonth = cur.getUTCMonth() + 1;
    const nextYear  = nextMonth === 12 ? cur.getUTCFullYear() + 1 : cur.getUTCFullYear();
    cur = new Date(Date.UTC(nextYear, nextMonth % 12, cur.getUTCDate()));
    if (!end && charges.length >= 12) break;
  }
  for (const c of charges) {
    await saasRun(
      `INSERT INTO saas.license_charges(contract_id,tenant_slug,description,amount,due_date,status)
       VALUES($1,$2,$3,$4,$5,'pending')`,
      [contractId, tenantSlug, c.description, amount, c.due_date]
    );
  }
  return charges.length;
}

// GET /api/superadmin/contracts
addRoute('GET', '/api/superadmin/contracts', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const rows = await saasAll(
      `SELECT lc.*, t.name AS tenant_name,
              (SELECT COUNT(*) FROM saas.license_charges lch WHERE lch.contract_id=lc.id) AS total_charges,
              (SELECT COUNT(*) FROM saas.license_charges lch WHERE lch.contract_id=lc.id AND lch.status='paid') AS paid_charges,
              (SELECT COALESCE(SUM(amount),0) FROM saas.license_charges lch WHERE lch.contract_id=lc.id AND lch.status='paid') AS total_paid,
              tl.id AS tech_lic_id, tl.status AS tech_lic_status, tl.starts_at AS tech_lic_starts,
              lt2.name AS tech_lic_name, lt2.slug AS tech_lic_slug
       FROM saas.license_contracts lc
       JOIN saas.tenants t ON t.slug = lc.tenant_slug
       LEFT JOIN saas.tenant_licenses tl ON tl.contract_id = lc.id AND tl.status = 'active'
       LEFT JOIN saas.license_types lt2 ON lt2.id = tl.license_type_id
       ORDER BY lc.created_at DESC`
    );
    sendJson(res, rows);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/contracts
addRoute('POST', '/api/superadmin/contracts', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { tenant_slug, plan, monthly_value, start_date, end_date, notes,
          contract_file_data, contract_file_name, generate_charges } = ctx.body || {};
  if (!tenant_slug || !plan || !monthly_value || !start_date)
    return sendJson(res, { error: 'tenant_slug, plan, monthly_value e start_date são obrigatórios' }, 400);
  try {
    const { proposal_id } = ctx.body;
    const row = await saasGet(
      `INSERT INTO saas.license_contracts(tenant_slug,plan,monthly_value,start_date,end_date,status,notes,contract_file_data,contract_file_name,proposal_id)
       VALUES($1,$2,$3,$4,$5,'active',$6,$7,$8,$9) RETURNING id`,
      [tenant_slug, plan, Number(monthly_value), start_date, end_date || null, notes || null,
       contract_file_data || null, contract_file_name || null, proposal_id || null]
    );
    const contractId = row.id;
    let chargesCreated = 0;
    if (generate_charges !== false) {
      chargesCreated = await generateLicenseCharges(contractId, tenant_slug, plan, Number(monthly_value), start_date, end_date || null);
    }
    // Atualiza plan do tenant
    await saasRun(`UPDATE saas.tenants SET plan=$1 WHERE slug=$2`, [plan, tenant_slug]);
    // Sincroniza tenant_licenses com o plano do contrato
    await _syncTenantLicense(tenant_slug, plan, contractId);
    sendJson(res, { ok: true, id: contractId, charges_created: chargesCreated });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/contracts/:id
addRoute('PUT', '/api/superadmin/contracts/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { plan, monthly_value, start_date, end_date, status, notes,
          contract_file_data, contract_file_name } = ctx.body || {};
  try {
    await saasRun(
      `UPDATE saas.license_contracts SET
         plan=COALESCE($1,plan), monthly_value=COALESCE($2,monthly_value),
         start_date=COALESCE($3,start_date), end_date=$4,
         status=COALESCE($5,status), notes=$6,
         contract_file_data=COALESCE($7,contract_file_data),
         contract_file_name=COALESCE($8,contract_file_name)
       WHERE id=$9`,
      [plan||null, monthly_value ? Number(monthly_value) : null, start_date||null,
       end_date||null, status||null, notes||null,
       contract_file_data||null, contract_file_name||null, ctx.params.id]
    );
    sendJson(res, { ok: true });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// DELETE /api/superadmin/contracts/:id  — cancela (soft)
addRoute('DELETE', '/api/superadmin/contracts/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    await saasRun(`UPDATE saas.license_contracts SET status='cancelled' WHERE id=$1`, [ctx.params.id]);
    await saasRun(
      `UPDATE saas.license_charges SET status='cancelled' WHERE contract_id=$1 AND status='pending'`,
      [ctx.params.id]
    );
    sendJson(res, { ok: true });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/contracts/:id/preview  — HTML para impressão/PDF (auth via ?token=)
addRoute('GET', '/api/superadmin/contracts/:id/preview', async (req, res, ctx) => {
  // Aceita token via query string para permitir window.open direto
  const { jwtVerify } = require('./src/middleware/auth');
  let user = ctx.user;
  if (!user) {
    const qToken = (ctx.qs || {}).token || '';
    try { user = qToken ? jwtVerify(qToken) : null; } catch { user = null; }
  }
  if (!user || user.role !== 'superadmin') {
    res.writeHead(403, { 'Content-Type': 'text/html' });
    return res.end('<h2>Acesso negado</h2>');
  }
  try {
    const contract = await saasGet(
      `SELECT lc.*, t.name AS tenant_name, t.admin_email AS tenant_email,
              t.cnpj AS tenant_cnpj, t.address AS tenant_address,
              t.city_state AS tenant_city_state,
              t.representative_name AS tenant_rep_name,
              t.representative_cpf  AS tenant_rep_cpf,
              t.representative_role AS tenant_rep_role
       FROM saas.license_contracts lc
       JOIN saas.tenants t ON t.slug = lc.tenant_slug
       WHERE lc.id = $1`, [ctx.params.id]
    );
    if (!contract) { res.writeHead(404); return res.end('Contrato não encontrado'); }

    const sRows = await saasAll('SELECT key, value FROM saas.settings');
    const cfg = {};
    sRows.forEach(r => { cfg[r.key] = r.value || ''; });

    const html = generateContractHtml(contract, cfg);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } catch (e) { res.writeHead(500); res.end(e.message); }
});

function generateContractHtml(c, cfg) {
  const fmtBRL  = v => 'R$ ' + Number(v||0).toLocaleString('pt-BR', { minimumFractionDigits: 2 });
  const fmtDate = d => d ? new Date(d + 'T12:00:00').toLocaleDateString('pt-BR') : '___/___/______';
  const blank   = v => v || '___________________________________';
  const blankS  = v => v || '___________';

  const contractNum = `MO-${String(c.id).padStart(4,'0')}/${new Date().getFullYear()}`;
  const today       = new Date().toLocaleDateString('pt-BR');
  const planLabels  = { starter: 'Starter', pro: 'Pro', professional: 'Pro', enterprise: 'Enterprise', custom: 'Custom' };
  const planLabel   = planLabels[c.plan] || c.plan || '';

  const planFeatures = {
    starter:      ['Gestão de vagas (até 50 unidades)', 'Cadastro de clientes e embarcações', 'Fila de operações de descida/subida', 'Financeiro básico (contratos e cobranças)', 'Suporte por e-mail em horário comercial'],
    pro:          ['Tudo do plano Starter', 'Gestão avançada de vagas sem limite', 'Módulo de loja de conveniência', 'Integração com API de previsão do tempo', 'Relatórios gerenciais completos', 'Suporte prioritário com tempo de resposta de 4h'],
    enterprise:   ['Tudo do plano Pro', 'Customizações de layout e marca', 'SLA garantido de 99,5% de disponibilidade', 'Suporte dedicado 24/7', 'Gestor de conta exclusivo', 'Integrações premium sob demanda'],
  };
  const features = planFeatures[c.plan] || planFeatures[c.plan === 'professional' ? 'pro' : 'starter'];

  const sla        = c.plan === 'enterprise' ? '99,5%' : '99,0%';
  const supportSLA = c.plan === 'enterprise' ? '4 horas (24/7)' : (c.plan === 'pro' || c.plan === 'professional') ? '8 horas úteis' : '48 horas úteis';

  const cityForForum = (cfg.company_city_state || 'São Paulo/SP').split('/')[0].trim();

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Contrato ${contractNum}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Georgia',serif;font-size:12pt;color:#1a1a2e;background:#fff;line-height:1.65}
  .print-bar{position:fixed;top:0;left:0;right:0;background:#1e293b;color:#fff;padding:10px 24px;display:flex;align-items:center;gap:12px;z-index:999;box-shadow:0 2px 10px rgba(0,0,0,.3)}
  .print-bar button{padding:7px 18px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600}
  .print-bar .btn-print{background:#6366f1;color:#fff}
  .print-bar .btn-close{background:rgba(255,255,255,.15);color:#fff}
  .print-bar span{font-size:13px;color:rgba(255,255,255,.7);margin-left:auto}
  .page{max-width:800px;margin:80px auto 60px;padding:0 40px}
  header{text-align:center;border-bottom:3px solid #1a1a2e;padding-bottom:24px;margin-bottom:30px}
  .co-name{font-size:24pt;font-weight:bold;letter-spacing:3px;text-transform:uppercase;color:#1a1a2e}
  .co-tagline{font-size:10pt;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-top:4px}
  .ct-title{font-size:14pt;font-weight:bold;text-transform:uppercase;margin-top:20px;color:#1a1a2e;letter-spacing:1px}
  .ct-subtitle{font-size:10pt;color:#475569;margin-top:6px}
  .ct-meta{display:flex;justify-content:center;gap:40px;margin-top:16px;font-size:10pt;color:#475569}
  .ct-meta strong{color:#1a1a2e}
  .parties{margin-bottom:28px}
  .parties-intro{font-size:11pt;margin-bottom:20px;text-align:justify}
  .party{border:1px solid #cbd5e1;border-radius:8px;padding:16px 20px;margin-bottom:16px;background:#f8fafc}
  .party-role{font-size:8.5pt;font-weight:bold;text-transform:uppercase;letter-spacing:2px;color:#6366f1;margin-bottom:12px}
  .party table{width:100%;border-collapse:collapse;font-size:10.5pt}
  .party table td{padding:3px 6px}
  .party table td:first-child{font-weight:bold;color:#475569;width:38%;white-space:nowrap}
  .party-label{margin-top:12px;font-size:10pt;font-style:italic;color:#475569;border-top:1px solid #e2e8f0;padding-top:10px}
  h2.clause{font-size:11pt;font-weight:bold;text-transform:uppercase;letter-spacing:.5px;color:#1a1a2e;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #e2e8f0}
  p.par{text-align:justify;margin-bottom:10px;font-size:11pt}
  p.par-indent{text-align:justify;margin:6px 0 6px 24px;font-size:10.5pt}
  ul.features{margin:8px 0 8px 28px;font-size:10.5pt}
  ul.features li{margin-bottom:4px}
  .highlight-box{background:#f0f4ff;border-left:4px solid #6366f1;padding:12px 16px;border-radius:4px;margin:12px 0;font-size:10.5pt}
  .highlight-box strong{color:#6366f1}
  .signatures{margin-top:50px;padding-top:28px;border-top:2px solid #1a1a2e;page-break-inside:avoid}
  .sig-title{text-align:center;font-size:10pt;font-weight:bold;text-transform:uppercase;letter-spacing:1px;margin-bottom:32px;color:#475569}
  .sig-grid{display:grid;grid-template-columns:1fr 1fr;gap:60px}
  .sig-block{text-align:center}
  .sig-line{border-bottom:1px solid #1a1a2e;margin-bottom:10px;height:50px}
  .sig-name{font-weight:bold;font-size:10.5pt}
  .sig-detail{font-size:9.5pt;color:#64748b;margin-top:2px}
  .witnesses{margin-top:40px;display:grid;grid-template-columns:1fr 1fr;gap:60px}
  .footer-note{margin-top:40px;font-size:9pt;color:#94a3b8;text-align:center;border-top:1px solid #e2e8f0;padding-top:12px;line-height:1.5}
  @media print{
    .print-bar{display:none}
    .page{margin:0;padding:0 20px}
    @page{margin:2.5cm;size:A4}
    h2.clause{page-break-after:avoid}
    .party{break-inside:avoid}
  }
</style>
</head>
<body>
<div class="print-bar">
  <button class="btn-print" onclick="window.print()">🖨️ Imprimir / Salvar como PDF</button>
  <button class="btn-close" onclick="window.close()">✕ Fechar</button>
  <span>Contrato ${contractNum} — ${planLabel} — ${fmtBRL(c.monthly_value)}/mês</span>
</div>
<div class="page">

<header>
  <div class="co-name">${cfg.general_system_name || 'Marina One'}</div>
  <div class="co-tagline">Plataforma de Gestão de Marinas — SaaS</div>
  <div class="ct-title">Contrato de Licença de Uso de Software</div>
  <div class="ct-subtitle">Modalidade Software como Serviço (SaaS) — Lei nº 9.609/98</div>
  <div class="ct-meta">
    <span><strong>Nº</strong> ${contractNum}</span>
    <span><strong>Plano</strong> ${planLabel}</span>
    <span><strong>Emissão</strong> ${today}</span>
  </div>
</header>

<section class="parties">
  <p class="parties-intro">Pelo presente instrumento particular e na melhor forma de direito, as partes a seguir qualificadas celebram o presente <strong>Contrato de Licença de Uso de Software na Modalidade SaaS</strong>, que se regerá pelas cláusulas e condições seguintes:</p>

  <div class="party">
    <div class="party-role">Contratante — Fornecedora da Plataforma</div>
    <table>
      <tr><td>Razão Social:</td><td>${blank(cfg.company_legal_name)}</td></tr>
      <tr><td>CNPJ:</td><td>${blank(cfg.company_cnpj)}</td></tr>
      <tr><td>Endereço:</td><td>${blank(cfg.company_address)}</td></tr>
      <tr><td>Cidade/Estado/CEP:</td><td>${blank(cfg.company_city_state)}</td></tr>
      <tr><td>Representante Legal:</td><td>${blank(cfg.company_representative_name)}</td></tr>
      <tr><td>Cargo:</td><td>${blank(cfg.company_representative_role)}</td></tr>
      <tr><td>CPF:</td><td>${blankS(cfg.company_representative_cpf)}</td></tr>
      <tr><td>E-mail:</td><td>${blank(cfg.general_support_email)}</td></tr>
    </table>
    <p class="party-label">Doravante denominada simplesmente <strong>"CONTRATANTE"</strong></p>
  </div>

  <div class="party">
    <div class="party-role">Licenciado — Beneficiário da Licença</div>
    <table>
      <tr><td>Razão Social / Nome:</td><td>${blank(c.tenant_name)}</td></tr>
      <tr><td>CNPJ / CPF:</td><td>${blank(c.tenant_cnpj)}</td></tr>
      <tr><td>Endereço:</td><td>${blank(c.tenant_address)}</td></tr>
      <tr><td>Cidade/Estado/CEP:</td><td>${blank(c.tenant_city_state)}</td></tr>
      <tr><td>Representante Legal:</td><td>${blank(c.tenant_rep_name)}</td></tr>
      <tr><td>Cargo:</td><td>${blank(c.tenant_rep_role)}</td></tr>
      <tr><td>CPF:</td><td>${blankS(c.tenant_rep_cpf)}</td></tr>
      <tr><td>E-mail:</td><td>${blank(c.tenant_email)}</td></tr>
    </table>
    <p class="party-label">Doravante denominada simplesmente <strong>"LICENCIADO"</strong></p>
  </div>
</section>

<h2 class="clause">Cláusula 1 — Do Objeto</h2>
<p class="par">O presente contrato tem por objeto a concessão, pela CONTRATANTE ao LICENCIADO, de licença de uso não exclusiva, intransferível e sem sublicença da plataforma de gestão de marinas denominada <strong>"${cfg.general_system_name || 'Marina One'}"</strong>, desenvolvida, operada e mantida pela CONTRATANTE, disponibilizada na modalidade Software como Serviço (SaaS), acessível via internet por interface web responsiva, nas condições previstas neste instrumento.</p>
<p class="par-indent">§1º A licença ora concedida é de caráter instrumental, destinando-se exclusivamente ao uso interno e operacional do LICENCIADO na gestão de sua marina, sendo vedado o uso para fins de revenda, sublicenciamento ou prestação de serviços a terceiros.</p>
<p class="par-indent">§2º A CONTRATANTE poderá, a seu exclusivo critério, adicionar novas funcionalidades à plataforma, sendo tais adições automaticamente incorporadas ao presente contrato sem ônus adicional ao LICENCIADO, desde que dentro do Plano contratado.</p>

<h2 class="clause">Cláusula 2 — Do Plano de Serviços</h2>
<p class="par">O LICENCIADO contrata o <strong>Plano ${planLabel}</strong>, que compreende as seguintes funcionalidades e recursos:</p>
<ul class="features">
${features.map(f => `  <li>${f}</li>`).join('\n')}
</ul>
<div class="highlight-box">
  <strong>Disponibilidade (SLA):</strong> ${sla} de uptime mensal, excluídas janelas de manutenção programada comunicadas com antecedência mínima de 24 horas.<br>
  <strong>Suporte técnico:</strong> Tempo máximo de primeira resposta de ${supportSLA} a partir do registro do chamado.
</div>

<h2 class="clause">Cláusula 3 — Do Valor e Forma de Pagamento</h2>
<p class="par">Pela licença de uso ora contratada, o LICENCIADO pagará à CONTRATANTE a importância mensal de <strong>${fmtBRL(c.monthly_value)} (${valorPorExtenso(Number(c.monthly_value))})</strong>, devida e exigível mensalmente, nos termos do calendário de cobranças gerado na data da assinatura deste instrumento.</p>
<p class="par-indent">§1º Os pagamentos deverão ser realizados até o vencimento de cada parcela, conforme cronograma previamente disponibilizado. O atraso no pagamento sujeitará o LICENCIADO à multa de 2% sobre o valor em atraso, acrescida de juros moratórios de 1% ao mês e atualização monetária pelo IGPM/FGV.</p>
<p class="par-indent">§2º A CONTRATANTE poderá reajustar o valor da mensalidade anualmente, com base na variação acumulada do IGPM/FGV ou índice substituto, mediante notificação ao LICENCIADO com antecedência mínima de 30 (trinta) dias.</p>
<p class="par-indent">§3º O inadimplemento superior a 30 (trinta) dias autoriza a CONTRATANTE a suspender o acesso à plataforma até a regularização, sem prejuízo das demais penalidades contratuais.</p>

<h2 class="clause">Cláusula 4 — Do Prazo de Vigência</h2>
<p class="par">O presente contrato entra em vigor na data de <strong>${fmtDate(c.start_date)}</strong>${c.end_date ? `, com vigência até <strong>${fmtDate(c.end_date)}</strong>` : ', com vigência por prazo indeterminado'}. ${c.end_date ? 'Ao término do prazo, o contrato poderá ser renovado mediante aditivo assinado pelas partes.' : 'Qualquer das partes poderá denunciar o contrato mediante notificação escrita com antecedência mínima de 30 (trinta) dias.'}</p>
<p class="par-indent">Parágrafo único. A renovação automática poderá ocorrer por iguais períodos, caso nenhuma das partes manifeste interesse contrário até 30 dias antes do vencimento.</p>

<h2 class="clause">Cláusula 5 — Das Obrigações da Contratante</h2>
<p class="par">São obrigações da CONTRATANTE:</p>
<p class="par-indent">I — Disponibilizar a plataforma em funcionamento, com o nível de serviço (SLA) estabelecido na Cláusula 2, durante toda a vigência contratual;</p>
<p class="par-indent">II — Manter a infraestrutura tecnológica necessária ao funcionamento do sistema, incluindo servidores, banco de dados e rede;</p>
<p class="par-indent">III — Disponibilizar atualizações, melhorias e correções de segurança no sistema sem custo adicional ao LICENCIADO;</p>
<p class="par-indent">IV — Manter rotinas de backup dos dados do LICENCIADO com frequência mínima diária, por período de 30 (trinta) dias;</p>
<p class="par-indent">V — Garantir a confidencialidade e segurança dos dados do LICENCIADO, em conformidade com a Lei Geral de Proteção de Dados (Lei nº 13.709/2018 — LGPD);</p>
<p class="par-indent">VI — Prestar suporte técnico conforme o nível estabelecido no Plano contratado.</p>

<h2 class="clause">Cláusula 6 — Das Obrigações do Licenciado</h2>
<p class="par">São obrigações do LICENCIADO:</p>
<p class="par-indent">I — Efetuar os pagamentos nas datas acordadas, sob pena das penalidades previstas neste contrato;</p>
<p class="par-indent">II — Utilizar a plataforma exclusivamente para os fins a que se destina, em conformidade com a legislação vigente e os termos deste instrumento;</p>
<p class="par-indent">III — Manter a confidencialidade das credenciais de acesso (usuário e senha), sendo responsável por todos os atos praticados sob seu login;</p>
<p class="par-indent">IV — Comunicar imediatamente à CONTRATANTE qualquer incidente de segurança, uso indevido ou acesso não autorizado à plataforma;</p>
<p class="par-indent">V — Não realizar engenharia reversa, descompilação, desmontagem ou qualquer tentativa de acesso ao código-fonte do software;</p>
<p class="par-indent">VI — Garantir a veracidade e atualização dos dados cadastrados na plataforma, sendo o único responsável pelas informações inseridas.</p>

<h2 class="clause">Cláusula 7 — Da Propriedade Intelectual</h2>
<p class="par">A plataforma ${cfg.general_system_name || 'Marina One'}, seu código-fonte, interface, algoritmos, banco de dados, documentação, marcas e demais elementos intelectuais são de propriedade exclusiva da CONTRATANTE, protegidos pela Lei nº 9.609/98 (Lei de Software), Lei nº 9.610/98 (Lei de Direitos Autorais) e demais normas aplicáveis.</p>
<p class="par-indent">§1º Este contrato não transfere ao LICENCIADO qualquer direito de propriedade intelectual sobre o software, constituindo-se exclusivamente como licença de uso.</p>
<p class="par-indent">§2º O LICENCIADO poderá fazer referência ao uso da plataforma em seus materiais de comunicação e marketing, mediante prévia e expressa autorização da CONTRATANTE.</p>

<h2 class="clause">Cláusula 8 — Da Proteção de Dados Pessoais (LGPD)</h2>
<p class="par">As partes comprometem-se a tratar os dados pessoais coletados e processados por meio da plataforma em estrita conformidade com a Lei Geral de Proteção de Dados Pessoais (LGPD — Lei nº 13.709/2018), observando os princípios da finalidade, adequação, necessidade, transparência, segurança e responsabilização.</p>
<p class="par-indent">§1º A CONTRATANTE atuará na qualidade de <strong>Operadora</strong> dos dados pessoais inseridos pelo LICENCIADO na plataforma, processando-os exclusivamente para a prestação dos serviços contratados.</p>
<p class="par-indent">§2º O LICENCIADO, na qualidade de <strong>Controlador</strong> dos dados de seus clientes e colaboradores, é o responsável pela coleta, tratamento e compartilhamento de tais dados, devendo obter as bases legais e consentimentos necessários conforme a LGPD.</p>
<p class="par-indent">§3º Em caso de incidente de segurança que possa afetar dados pessoais, a CONTRATANTE notificará o LICENCIADO em até 72 (setenta e duas) horas após a detecção.</p>

<h2 class="clause">Cláusula 9 — Da Confidencialidade</h2>
<p class="par">As partes obrigam-se a manter em sigilo todas as informações técnicas, comerciais, operacionais e financeiras a que tiverem acesso em razão deste contrato, não as divulgando a terceiros sem prévia autorização escrita da outra parte, durante a vigência contratual e por um período de 3 (três) anos após seu término.</p>
<p class="par-indent">Parágrafo único. Excetuam-se as informações que já eram de domínio público antes da data deste contrato, ou que se tornarem públicas sem culpa da parte obrigada ao sigilo.</p>

<h2 class="clause">Cláusula 10 — Da Limitação de Responsabilidade</h2>
<p class="par">A CONTRATANTE não será responsabilizada por danos indiretos, lucros cessantes, perda de dados por negligência do LICENCIADO ou por eventos fora de seu controle (caso fortuito ou força maior), incluindo falhas de provedores de internet, instabilidades de energia elétrica ou interrupções de serviços de terceiros.</p>
<p class="par-indent">§1º A responsabilidade total e agregada da CONTRATANTE, a qualquer título, fica limitada ao valor correspondente a 6 (seis) mensalidades efetivamente pagas pelo LICENCIADO nos 6 meses anteriores ao evento danoso.</p>

<h2 class="clause">Cláusula 11 — Da Rescisão</h2>
<p class="par">O presente contrato poderá ser rescindido, de pleno direito, pela parte inocente, independentemente de notificação judicial ou extrajudicial, nas seguintes hipóteses:</p>
<p class="par-indent">I — Descumprimento de qualquer cláusula por qualquer das partes, não sanado em 15 (quinze) dias após notificação formal;</p>
<p class="par-indent">II — Inadimplência do LICENCIADO superior a 30 (trinta) dias;</p>
<p class="par-indent">III — Insolvência, pedido de recuperação judicial ou falência de qualquer das partes;</p>
<p class="par-indent">IV — Por mútuo acordo, formalizado por escrito.</p>
<p class="par-indent">§1º Em caso de rescisão por iniciativa do LICENCIADO sem justa causa antes do término do prazo contratual, serão devidas as mensalidades remanescentes até o final do período, a título de cláusula penal compensatória.</p>
<p class="par-indent">§2º Na rescisão, o LICENCIADO terá prazo de 30 (trinta) dias para exportar seus dados. Após esse prazo, a CONTRATANTE poderá eliminar os dados de forma irreversível.</p>

<h2 class="clause">Cláusula 12 — Das Disposições Gerais</h2>
<p class="par-indent">I — O presente contrato é firmado em caráter irrevogável e irretratável, obrigando as partes e seus sucessores.</p>
<p class="par-indent">II — Quaisquer alterações a este instrumento somente serão válidas se formalizadas mediante aditivo contratual assinado por ambas as partes.</p>
<p class="par-indent">III — A tolerância de qualquer das partes quanto ao descumprimento de obrigações pela outra não importará novação, renúncia de direitos ou precedente.</p>
<p class="par-indent">IV — Se qualquer disposição deste contrato for considerada inválida ou inexequível, as demais cláusulas permanecerão em pleno vigor e efeito.</p>
<p class="par-indent">V — As partes elegem o Foro da Comarca de <strong>${cityForForum}</strong> para dirimir quaisquer controvérsias oriundas deste contrato, com renúncia expressa a qualquer outro, por mais privilegiado que seja.</p>

<div class="signatures">
  <p class="sig-title">Por estarem assim justas e contratadas, as partes assinam o presente instrumento em 2 (duas) vias de igual teor.</p>
  <p style="text-align:center;font-size:10pt;color:#475569;margin-bottom:28px">${cityForForum}, ${today}</p>
  <div class="sig-grid">
    <div class="sig-block">
      <div class="sig-line"></div>
      <div class="sig-name">${blank(cfg.company_legal_name)}</div>
      <div class="sig-detail">${blank(cfg.company_representative_name)}</div>
      <div class="sig-detail">${cfg.company_representative_role || 'Representante Legal'}</div>
      <div class="sig-detail" style="margin-top:2px">CONTRATANTE</div>
    </div>
    <div class="sig-block">
      <div class="sig-line"></div>
      <div class="sig-name">${blank(c.tenant_name)}</div>
      <div class="sig-detail">${blank(c.tenant_rep_name)}</div>
      <div class="sig-detail">${c.tenant_rep_role || 'Representante Legal'}</div>
      <div class="sig-detail" style="margin-top:2px">LICENCIADO</div>
    </div>
  </div>
  <div class="witnesses" style="margin-top:48px">
    <div class="sig-block">
      <div class="sig-line"></div>
      <div class="sig-detail">Testemunha 1 — Nome: ____________________________</div>
      <div class="sig-detail">CPF: ________________________</div>
    </div>
    <div class="sig-block">
      <div class="sig-line"></div>
      <div class="sig-detail">Testemunha 2 — Nome: ____________________________</div>
      <div class="sig-detail">CPF: ________________________</div>
    </div>
  </div>
  <p class="footer-note">Documento gerado eletronicamente pelo sistema ${cfg.general_system_name || 'Marina One'} · Contrato ${contractNum} · ${today}<br>
  Este documento tem valor jurídico nos termos da Lei nº 14.063/2020 e Medida Provisória nº 2.200-2/2001 quando assinado eletronicamente.</p>
</div>

</div>
</body>
</html>`;
}

function valorPorExtenso(v) {
  if (!v || isNaN(v)) return 'valor a definir';
  const n = Math.round(v * 100);
  const reais  = Math.floor(n / 100);
  const cents  = n % 100;
  const unid   = ['','um','dois','três','quatro','cinco','seis','sete','oito','nove','dez','onze','doze','treze','quatorze','quinze','dezesseis','dezessete','dezoito','dezenove'];
  const dez    = ['','','vinte','trinta','quarenta','cinquenta','sessenta','setenta','oitenta','noventa'];
  const cent   = ['','cem','duzentos','trezentos','quatrocentos','quinhentos','seiscentos','setecentos','oitocentos','novecentos'];
  function dezena(n) {
    if (n < 20) return unid[n];
    const d = Math.floor(n/10), u = n%10;
    return dez[d] + (u ? ' e ' + unid[u] : '');
  }
  function centena(n) {
    if (n === 100) return 'cem';
    const c = Math.floor(n/100), r = n%100;
    return (c ? cent[c] : '') + (c && r ? ' e ' + dezena(r) : r ? dezena(r) : '');
  }
  function milhar(n) {
    if (n < 1000) return centena(n);
    const m = Math.floor(n/1000), r = n%1000;
    const ms = m === 1 ? 'mil' : centena(m) + ' mil';
    return ms + (r ? ' e ' + centena(r) : '');
  }
  const parteReais  = reais  === 0 ? 'zero reais'  : milhar(reais)  + (reais  === 1 ? ' real'   : ' reais');
  const parteCents  = cents  === 0 ? ''             : ' e ' + dezena(cents) + (cents === 1 ? ' centavo' : ' centavos');
  return parteReais + parteCents;
}

// GET /api/superadmin/charges
addRoute('GET', '/api/superadmin/charges', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    await saasCheckOverdue();
    const { status, tenant, from, to } = ctx.qs || {};
    const conds = ['1=1'];
    const params = [];
    let p = 1;
    if (status)  { conds.push(`lch.status=$${p++}`);              params.push(status); }
    if (tenant)  { conds.push(`lch.tenant_slug=$${p++}`);         params.push(tenant); }
    if (from)    { conds.push(`lch.due_date>=$${p++}`);           params.push(from); }
    if (to)      { conds.push(`lch.due_date<=$${p++}`);           params.push(to); }
    const rows = await saasAll(
      `SELECT lch.*, t.name AS tenant_name, lc.plan AS contract_plan
       FROM saas.license_charges lch
       JOIN saas.tenants t ON t.slug=lch.tenant_slug
       LEFT JOIN saas.license_contracts lc ON lc.id=lch.contract_id
       WHERE ${conds.join(' AND ')}
       ORDER BY lch.due_date DESC
       LIMIT 500`,
      params
    );
    sendJson(res, rows);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/charges/:id
addRoute('PUT', '/api/superadmin/charges/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  const { status, paid_date, payment_method, amount, notes } = ctx.body || {};
  try {
    const old = await saasGet(`SELECT * FROM saas.license_charges WHERE id=$1`, [ctx.params.id]);
    if (!old) return sendJson(res, { error: 'Parcela não encontrada' }, 404);
    const ns       = status || old.status;
    const paidDate = (ns === 'paid' && !old.paid_date) ? todayStr() : (paid_date || old.paid_date || null);
    await saasRun(
      `UPDATE saas.license_charges SET status=$1, paid_date=$2, payment_method=$3,
       amount=COALESCE($4,amount), notes=$5 WHERE id=$6`,
      [ns, paidDate, payment_method || old.payment_method || null,
       amount ? Number(amount) : null, notes !== undefined ? notes : old.notes, ctx.params.id]
    );
    sendJson(res, { ok: true });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/financial/summary
addRoute('GET', '/api/superadmin/financial/summary', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    await saasCheckOverdue();
    const ms = monthStart();
    const year = parseInt(ctx.qs?.year || new Date().getFullYear(), 10);
    const [mrr, revMonth, revTotal, pending, overdue, tenantCount,
           activeContracts, revenueChart, statusBreakdown] = await Promise.all([
      saasGet(`SELECT COALESCE(SUM(monthly_value),0) AS v FROM saas.license_contracts WHERE status='active'`),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='paid' AND paid_date>=$1`, [ms]),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='paid'`),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='pending'`),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='overdue'`),
      saasGet(`SELECT COUNT(*) AS v FROM saas.tenants WHERE active=true`),
      saasGet(`SELECT COUNT(*) AS v FROM saas.license_contracts WHERE status='active'`),
      saasAll(
        `SELECT TO_CHAR(paid_date,'YYYY-MM') AS month, COALESCE(SUM(amount),0) AS total
         FROM saas.license_charges WHERE status='paid' AND paid_date IS NOT NULL
           AND EXTRACT(YEAR FROM paid_date) = $1
         GROUP BY TO_CHAR(paid_date,'YYYY-MM') ORDER BY month ASC`, [year]
      ),
      saasAll(
        `SELECT status, COUNT(*) AS count, COALESCE(SUM(amount),0) AS total
         FROM saas.license_charges GROUP BY status`
      ),
    ]);
    const mrrVal     = Number(mrr?.v     || 0);
    const revMVal    = Number(revMonth?.v || 0);
    const revTVal    = Number(revTotal?.v || 0);
    const pendingVal = Number(pending?.v  || 0);
    const overdueVal = Number(overdue?.v  || 0);
    const paidPlusOverdue = revTVal + overdueVal;
    const collectionRate = paidPlusOverdue > 0 ? Math.round((revTVal / paidPlusOverdue) * 100) : 100;
    sendJson(res, {
      mrr:             mrrVal,
      arr:             mrrVal * 12,
      revenue_month:   revMVal,
      revenue_total:   revTVal,
      pending:         pendingVal,
      overdue:         overdueVal,
      collection_rate: collectionRate,
      tenant_count:    Number(tenantCount?.v || 0),
      active_contracts:Number(activeContracts?.v || 0),
      revenue_chart:   revenueChart.reverse().map(r => ({ ...r, total: Number(r.total) })),
      status_breakdown:statusBreakdown.map(r => ({ ...r, count: Number(r.count), total: Number(r.total) })),
    });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/analytics
addRoute('GET', '/api/superadmin/analytics', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    await saasCheckOverdue();
    const months  = parseInt(ctx.qs?.months || '12', 10);
    const plan    = ctx.qs?.plan || '';
    const fromDt  = daysAgo(months * 31);

    const planCond = plan ? `AND lc.plan='${plan.replace(/'/g,"''")}'` : '';

    // --- Receita coletada por mês (tendência) ---
    const revTrend = await saasAll(
      `SELECT TO_CHAR(lch.paid_date,'YYYY-MM') AS month, COALESCE(SUM(lch.amount),0) AS total
       FROM saas.license_charges lch
       LEFT JOIN saas.license_contracts lc ON lc.id=lch.contract_id
       WHERE lch.status='paid' AND lch.paid_date IS NOT NULL
         AND lch.paid_date >= $1 ${planCond}
       GROUP BY TO_CHAR(lch.paid_date,'YYYY-MM')
       ORDER BY month ASC`, [fromDt]
    );

    // --- Novos tenants por mês ---
    const newTenants = await saasAll(
      `SELECT TO_CHAR(created_at,'YYYY-MM') AS month, COUNT(*) AS count
       FROM saas.tenants
       WHERE created_at >= $1
       GROUP BY TO_CHAR(created_at,'YYYY-MM')
       ORDER BY month ASC`, [fromDt]
    );

    // --- Distribuição por plano (contratos ativos) ---
    const planDist = await saasAll(
      `SELECT plan, COUNT(*) AS count, COALESCE(SUM(monthly_value),0) AS mrr
       FROM saas.license_contracts WHERE status='active'
       GROUP BY plan ORDER BY mrr DESC`
    );

    // --- Aging de inadimplência ---
    const today = todayStr();
    const [ag0, ag30, ag60, ag90] = await Promise.all([
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='overdue' AND due_date >= $1`, [daysAgo(30)]),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='overdue' AND due_date < $1 AND due_date >= $2`, [daysAgo(30), daysAgo(60)]),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='overdue' AND due_date < $1 AND due_date >= $2`, [daysAgo(60), daysAgo(90)]),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='overdue' AND due_date < $1`, [daysAgo(90)]),
    ]);

    // --- Top tenants por receita total ---
    const topTenants = await saasAll(
      `SELECT lch.tenant_slug, t.name AS tenant_name,
              COALESCE(SUM(CASE WHEN lch.status='paid' THEN lch.amount ELSE 0 END),0) AS paid_total,
              COALESCE(SUM(CASE WHEN lch.status IN ('pending','overdue') THEN lch.amount ELSE 0 END),0) AS pending_total,
              lc_act.plan AS active_plan
       FROM saas.license_charges lch
       JOIN saas.tenants t ON t.slug=lch.tenant_slug
       LEFT JOIN LATERAL (
         SELECT plan FROM saas.license_contracts WHERE tenant_slug=lch.tenant_slug AND status='active' ORDER BY created_at DESC LIMIT 1
       ) lc_act ON TRUE
       GROUP BY lch.tenant_slug, t.name, lc_act.plan
       ORDER BY paid_total DESC LIMIT 10`
    );

    // --- Tenants em risco (com valores vencidos) ---
    const atRisk = await saasAll(
      `SELECT lch.tenant_slug, t.name AS tenant_name,
              COALESCE(SUM(lch.amount),0) AS overdue_total,
              COUNT(*) AS overdue_count,
              MIN(lch.due_date) AS oldest_due
       FROM saas.license_charges lch
       JOIN saas.tenants t ON t.slug=lch.tenant_slug
       WHERE lch.status='overdue'
       GROUP BY lch.tenant_slug, t.name
       ORDER BY overdue_total DESC LIMIT 10`
    );

    // --- Contratos expirando em 60 dias ---
    const expiring = await saasAll(
      `SELECT lc.*, t.name AS tenant_name
       FROM saas.license_contracts lc
       JOIN saas.tenants t ON t.slug=lc.tenant_slug
       WHERE lc.status='active' AND lc.end_date IS NOT NULL
         AND lc.end_date BETWEEN $1 AND $2
       ORDER BY lc.end_date ASC`, [today, daysAhead(60)]
    );

    // --- KPIs globais ---
    const [mrrRow, arrTotalRow, pendRow, ovdRow, actTenRow, actConRow, churnRow, totalRevRow] = await Promise.all([
      saasGet(`SELECT COALESCE(SUM(monthly_value),0) AS v FROM saas.license_contracts WHERE status='active' ${planCond.replace('lc.','')}`),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='paid' ${planCond ? "AND contract_id IN (SELECT id FROM saas.license_contracts WHERE "+planCond.replace('lc.','').replace('AND ','')+")" : ''}`),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='pending'`),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='overdue'`),
      saasGet(`SELECT COUNT(*) AS v FROM saas.tenants WHERE active=true`),
      saasGet(`SELECT COUNT(*) AS v FROM saas.license_contracts WHERE status='active'`),
      saasGet(`SELECT COUNT(*) AS v FROM saas.license_contracts WHERE status='cancelled' AND created_at >= $1`, [fromDt]),
      saasGet(`SELECT COALESCE(SUM(amount),0) AS v FROM saas.license_charges WHERE status='paid'`),
    ]);

    const mrrVal  = Number(mrrRow?.v  || 0);
    const actTen  = Number(actTenRow?.v || 0);
    const arpu    = actTen > 0 ? mrrVal / actTen : 0;
    const totalRev= Number(totalRevRow?.v || 0);
    const ovdVal  = Number(ovdRow?.v || 0);
    const pdTotal = totalRev + ovdVal;
    const collRate= pdTotal > 0 ? Math.round((totalRev / pdTotal) * 100) : 100;

    // MoM growth — compara último mês completo vs penúltimo
    const last2 = revTrend.slice(-2);
    const momGrowth = last2.length === 2 && Number(last2[0].total) > 0
      ? Math.round(((Number(last2[1].total) - Number(last2[0].total)) / Number(last2[0].total)) * 100)
      : null;

    // LTV médio (receita total / tenants com pagamentos)
    const ltvRow = await saasGet(
      `SELECT COUNT(DISTINCT tenant_slug) AS tenants, COALESCE(SUM(amount),0) AS total
       FROM saas.license_charges WHERE status='paid'`
    );
    const avgLtv = Number(ltvRow?.tenants || 0) > 0
      ? Number(ltvRow.total) / Number(ltvRow.tenants) : 0;

    sendJson(res, {
      kpis: {
        mrr: mrrVal, arr: mrrVal * 12, arpu,
        active_tenants: actTen,
        active_contracts: Number(actConRow?.v || 0),
        churn_period: Number(churnRow?.v || 0),
        collection_rate: collRate,
        avg_ltv: avgLtv,
        mom_growth: momGrowth,
        total_revenue: totalRev,
        pending: Number(pendRow?.v || 0),
        overdue: ovdVal,
      },
      rev_trend:   revTrend.map(r => ({ ...r, total: Number(r.total) })),
      new_tenants: newTenants.map(r => ({ ...r, count: Number(r.count) })),
      plan_dist:   planDist.map(r => ({ ...r, count: Number(r.count), mrr: Number(r.mrr) })),
      aging: [
        { label: '1-30d',  value: Number(ag0?.v  || 0) },
        { label: '31-60d', value: Number(ag30?.v || 0) },
        { label: '61-90d', value: Number(ag60?.v || 0) },
        { label: '90d+',   value: Number(ag90?.v || 0) },
      ],
      top_tenants: topTenants.map(r => ({ ...r, paid_total: Number(r.paid_total), pending_total: Number(r.pending_total) })),
      at_risk:     atRisk.map(r => ({ ...r, overdue_total: Number(r.overdue_total), overdue_count: Number(r.overdue_count) })),
      expiring,
    });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/analytics/predict
addRoute('GET', '/api/superadmin/analytics/predict', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    await saasCheckOverdue();
    const today  = todayStr();
    const planF  = ctx.qs?.plan || '';
    const planCond = planF ? `AND lc.plan='${planF.replace(/'/g,"''")}'` : '';

    // ── 1. RECEITA FUTURA CONCRETA (parcelas pendentes agendadas) ─────
    const futureRevRows = await saasAll(
      `SELECT TO_CHAR(lch.due_date,'YYYY-MM') AS month,
              COALESCE(SUM(lch.amount),0)     AS expected,
              COALESCE(SUM(CASE WHEN t_risk.is_risky THEN lch.amount ELSE 0 END),0) AS at_risk
       FROM saas.license_charges lch
       LEFT JOIN LATERAL (
         SELECT EXISTS(
           SELECT 1 FROM saas.license_charges x
           WHERE x.tenant_slug=lch.tenant_slug AND x.status='overdue'
         ) AS is_risky
       ) t_risk ON TRUE
       LEFT JOIN saas.license_contracts lc ON lc.id=lch.contract_id
       WHERE lch.status='pending' AND lch.due_date >= $1 ${planCond}
       GROUP BY TO_CHAR(lch.due_date,'YYYY-MM')
       ORDER BY month ASC LIMIT 12`,
      [today]
    );

    // ── 2. HISTÓRICO (período selecionado, base para regressão) ──────
    const histMonths = Math.max(6, parseInt(ctx.qs?.months || '12', 10));
    const histRows = await saasAll(
      `SELECT TO_CHAR(paid_date,'YYYY-MM') AS month, COALESCE(SUM(amount),0) AS total
       FROM saas.license_charges WHERE status='paid' AND paid_date IS NOT NULL
         AND paid_date >= $1 ${planCond.replace('lc.plan','plan').replace('lc.','')}
       GROUP BY TO_CHAR(paid_date,'YYYY-MM') ORDER BY month ASC`,
      [daysAgo(histMonths * 31)]
    );

    // ── 3. SCORE DE RISCO POR TENANT ──────────────────────────────────
    const riskRows = await saasAll(
      `SELECT t.slug, t.name, t.active, t.plan,
              COALESCE(SUM(CASE WHEN lch.status='overdue' THEN lch.amount ELSE 0 END),0)  AS overdue_amt,
              COUNT(CASE WHEN lch.status='overdue' THEN 1 END)                             AS overdue_cnt,
              MAX(CASE WHEN lch.status='paid' THEN lch.paid_date END)                      AS last_payment,
              MIN(CASE WHEN lch.status='overdue' THEN lch.due_date END)                    AS oldest_overdue,
              lc_exp.end_date,
              lc_exp.monthly_value
       FROM saas.tenants t
       LEFT JOIN saas.license_charges lch ON lch.tenant_slug=t.slug
       LEFT JOIN LATERAL (
         SELECT end_date, monthly_value FROM saas.license_contracts
         WHERE tenant_slug=t.slug AND status='active' ORDER BY created_at DESC LIMIT 1
       ) lc_exp ON TRUE
       WHERE t.active=true
       GROUP BY t.slug, t.name, t.active, t.plan, lc_exp.end_date, lc_exp.monthly_value
       ORDER BY overdue_amt DESC`
    );

    // Calcula score de risco 0-100 para cada tenant
    const maxOverdue = riskRows.reduce((m, r) => Math.max(m, Number(r.overdue_amt||0)), 1);
    const riskScores = riskRows.map(r => {
      let score = 0;
      const ovdAmt  = Number(r.overdue_amt || 0);
      const ovdCnt  = Number(r.overdue_cnt || 0);
      const expDate = r.end_date ? new Date(r.end_date) : null;
      const lastPay = r.last_payment ? new Date(r.last_payment) : null;
      const oldestOverdue = r.oldest_overdue ? new Date(r.oldest_overdue) : null;

      // Inadimplência (0-40 pts)
      if (ovdAmt > 0) score += Math.min(40, Math.round((ovdAmt / maxOverdue) * 40));

      // Dias de atraso (0-25 pts)
      if (oldestOverdue) {
        const daysLate = Math.floor((Date.now() - oldestOverdue.getTime()) / 86400000);
        score += Math.min(25, Math.round((daysLate / 90) * 25));
      }

      // Contrato expirando em breve (0-20 pts)
      if (expDate) {
        const daysLeft = Math.ceil((expDate.getTime() - Date.now()) / 86400000);
        if (daysLeft < 0) score += 20;
        else if (daysLeft <= 15) score += 18;
        else if (daysLeft <= 30) score += 12;
        else if (daysLeft <= 60) score += 6;
      }

      // Sem pagamento nos últimos 60 dias (0-15 pts)
      if (!lastPay || (Date.now() - lastPay.getTime()) > 60 * 86400000) score += 15;

      score = Math.min(100, score);
      const level = score >= 70 ? 'critical' : score >= 40 ? 'warning' : 'ok';

      return {
        slug: r.slug, name: r.name, plan: r.plan,
        score, level,
        overdue_amt: ovdAmt, overdue_cnt: ovdCnt,
        monthly_value: Number(r.monthly_value || 0),
        days_overdue: oldestOverdue
          ? Math.floor((Date.now() - oldestOverdue.getTime()) / 86400000) : 0,
        contract_expires: r.end_date || null,
        last_payment: r.last_payment || null,
      };
    }).sort((a,b) => b.score - a.score);

    // ── 4. CHURN RATE MENSAL (últimos 6 meses) ────────────────────────
    const churnRows = await saasAll(
      `SELECT TO_CHAR(created_at,'YYYY-MM') AS month, COUNT(*) AS cancelled
       FROM saas.license_contracts WHERE status='cancelled' AND created_at >= $1
       GROUP BY TO_CHAR(created_at,'YYYY-MM') ORDER BY month ASC`, [daysAgo(180)]
    );
    const totalActive = Number((await saasGet(
      `SELECT COUNT(*) AS v FROM saas.license_contracts WHERE status='active'`
    ))?.v || 1);
    const avgChurn = churnRows.length
      ? churnRows.reduce((s,r) => s + Number(r.cancelled), 0) / churnRows.length / totalActive
      : 0;

    // ── 5. RETENÇÃO: % de tenants que pagaram no prazo (últimos 6m) ───
    const [onTime, total6m] = await Promise.all([
      saasGet(`SELECT COUNT(*) AS v FROM saas.license_charges WHERE status='paid' AND paid_date <= due_date AND due_date >= $1`, [daysAgo(180)]),
      saasGet(`SELECT COUNT(*) AS v FROM saas.license_charges WHERE status IN ('paid','overdue') AND due_date >= $1`, [daysAgo(180)]),
    ]);
    const onTimeRate = Number(total6m?.v||0) > 0
      ? Math.round((Number(onTime?.v||0) / Number(total6m.v)) * 100) : 100;

    sendJson(res, {
      future_rev:    futureRevRows.map(r => ({ ...r, expected: Number(r.expected), at_risk: Number(r.at_risk) })),
      hist_monthly:  histRows.map(r => ({ ...r, total: Number(r.total) })),
      risk_scores:   riskScores,
      monthly_churn_rate: Math.round(avgChurn * 100 * 10) / 10,
      on_time_rate:  onTimeRate,
    });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// ─────────────────────────────────────────────────────────────────────
//  ROTAS — CONFIGURAÇÕES SAAS
// ─────────────────────────────────────────────────────────────────────

// GET /api/superadmin/settings
addRoute('GET', '/api/superadmin/settings', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { saasAll: sAll } = createSaasHelpers();
    const rows = await sAll('SELECT key, value FROM saas.settings ORDER BY key');
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    sendJson(res, settings);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/settings
addRoute('PUT', '/api/superadmin/settings', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { saasRun: sRun } = createSaasHelpers();
    const entries = Object.entries(ctx.body || {});
    for (const [key, value] of entries) {
      await sRun(
        `INSERT INTO saas.settings(key, value, updated_at) VALUES($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, value ?? '']
      );
    }
    sendJson(res, { ok: true, updated: entries.length });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/settings/test-weather  (testa a chave configurada)
addRoute('GET', '/api/superadmin/settings/test-weather', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { saasGet: sGet } = createSaasHelpers();
    const keyRow      = await sGet(`SELECT value FROM saas.settings WHERE key='weather_api_key'`);
    const providerRow = await sGet(`SELECT value FROM saas.settings WHERE key='weather_provider'`);
    const apiKey  = keyRow?.value || '';
    const provider = providerRow?.value || 'openweathermap';
    if (!apiKey) return sendJson(res, { ok: false, error: 'API key não configurada' });
    const data = await fetchWeather(-23.5505, -46.6333, apiKey, provider); // São Paulo como teste
    sendJson(res, { ok: true, sample: data });
  } catch (e) { sendJson(res, { ok: false, error: e.message }); }
});

// GET /api/weather?lat=X&lon=Y  (proxy para tenant frontend — requer auth de tenant)
addRoute('GET', '/api/weather', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  try {
    const { saasGet: sGet } = createSaasHelpers();
    const keyRow      = await sGet(`SELECT value FROM saas.settings WHERE key='weather_api_key'`);
    const providerRow = await sGet(`SELECT value FROM saas.settings WHERE key='weather_provider'`);
    const apiKey  = keyRow?.value || '';
    const provider = providerRow?.value || 'openweathermap';
    if (!apiKey) return sendJson(res, { error: 'Integração de clima não configurada' }, 503);
    const lat = parseFloat(ctx.query?.lat || '-23.5505');
    const lon = parseFloat(ctx.query?.lon || '-46.6333');
    const data = await fetchWeather(lat, lon, apiKey, provider);
    sendJson(res, data);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

function fetchWeather(lat, lon, apiKey, provider) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    let url;
    if (provider === 'weatherapi') {
      url = `https://api.weatherapi.com/v1/current.json?key=${apiKey}&q=${lat},${lon}&lang=pt`;
    } else {
      url = `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${apiKey}&units=metric&lang=pt_br`;
    }
    https.get(url, r => {
      let body = '';
      r.on('data', d => body += d);
      r.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch(e) { reject(new Error('Resposta inválida da API de clima')); }
      });
    }).on('error', reject);
  });
}

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — MÓDULOS x LICENÇAS (Super Admin)
// ═════════════════════════════════════════════════════════════════════

// ── Módulos ──────────────────────────────────────────────────────────

// GET /api/superadmin/modules
addRoute('GET', '/api/superadmin/modules', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const rows = await saasAll(`SELECT * FROM saas.modules ORDER BY sort_order, id`);
    sendJson(res, rows);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/modules/:id — apenas metadados editáveis (slug/name gerenciados via código)
addRoute('PUT', '/api/superadmin/modules/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    const { description, category, has_ext_cost, active } = ctx.body;
    const row = await saasGet(
      `UPDATE saas.modules SET
         description=COALESCE($1,description),
         category=COALESCE($2,category),
         has_ext_cost=COALESCE($3,has_ext_cost),
         active=COALESCE($4,active)
       WHERE id=$5 RETURNING *`,
      [description, category, has_ext_cost, active, id]
    );
    if (!row) return sendJson(res, { error: 'Módulo não encontrado' }, 404);
    sendJson(res, row);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// ── Tipos de Licença ─────────────────────────────────────────────────

// GET /api/superadmin/license-types
addRoute('GET', '/api/superadmin/license-types', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const types = await saasAll(`SELECT * FROM saas.license_types ORDER BY sort_order, id`);
    const counts = await saasAll(
      `SELECT license_type_id, COUNT(*) AS tenant_count
       FROM saas.tenant_licenses
       WHERE status = 'active' AND (ends_at IS NULL OR ends_at >= CURRENT_DATE)
       GROUP BY license_type_id`
    );
    const countMap = Object.fromEntries(counts.map(r => [r.license_type_id, Number(r.tenant_count)]));
    for (const t of types) {
      t.tenant_count = countMap[t.id] || 0;
      t.modules = await saasAll(
        `SELECT m.id, m.slug, m.name, m.category, m.has_ext_cost, ltm.percent_share
         FROM saas.license_type_modules ltm
         JOIN saas.modules m ON m.id = ltm.module_id
         WHERE ltm.license_type_id = $1
         ORDER BY m.sort_order`,
        [t.id]
      );
    }
    sendJson(res, types);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/license-types
addRoute('POST', '/api/superadmin/license-types', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug, name, description = '', price_monthly = 0, price_yearly = 0, is_custom = false, sort_order = 0 } = ctx.body;
    if (!slug || !name) return sendJson(res, { error: 'slug e name obrigatórios' }, 400);
    const row = await saasGet(
      `INSERT INTO saas.license_types(slug,name,description,price_monthly,price_yearly,is_custom,sort_order)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [slug, name, description, price_monthly, price_yearly, !!is_custom, sort_order]
    );
    sendJson(res, row, 201);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/license-types/:id
addRoute('PUT', '/api/superadmin/license-types/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    const { name, description, price_monthly, price_yearly, active, sort_order } = ctx.body;
    const row = await saasGet(
      `UPDATE saas.license_types SET
         name=COALESCE($1,name), description=COALESCE($2,description),
         price_monthly=COALESCE($3,price_monthly), price_yearly=COALESCE($4,price_yearly),
         active=COALESCE($5,active), sort_order=COALESCE($6,sort_order)
       WHERE id=$7 RETURNING *`,
      [name, description, price_monthly, price_yearly, active, sort_order, id]
    );
    if (!row) return sendJson(res, { error: 'Tipo de licença não encontrado' }, 404);
    sendJson(res, row);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/license-types/:id/modules — redefine módulos + percentuais
addRoute('PUT', '/api/superadmin/license-types/:id/modules', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    // modules: [{ module_id, percent_share }]
    const { modules = [] } = ctx.body;
    const pool = getGlobalPool();
    // Remove todos os existentes e reinsere (replace completo)
    await pool.unsafe(`DELETE FROM saas.license_type_modules WHERE license_type_id=$1`, [id]);
    for (const m of modules) {
      await pool.unsafe(
        `INSERT INTO saas.license_type_modules(license_type_id, module_id, percent_share)
         VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
        [id, m.module_id, m.percent_share || 0]
      );
    }
    const updated = await saasAll(
      `SELECT m.id, m.slug, m.name, m.category, ltm.percent_share
       FROM saas.license_type_modules ltm
       JOIN saas.modules m ON m.id=ltm.module_id
       WHERE ltm.license_type_id=$1 ORDER BY m.sort_order`, [id]
    );
    _evictModulesCache(); // invalida cache de todos os tenants
    sendJson(res, updated);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// DELETE /api/superadmin/license-types/:id
addRoute('DELETE', '/api/superadmin/license-types/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    const lt = await saasGet(`SELECT * FROM saas.license_types WHERE id=$1`, [id]);
    if (!lt) return sendJson(res, { error: 'Tipo de licença não encontrado' }, 404);
    // Bloqueia se há tenant_licenses apontando para este tipo (qualquer status)
    const inUse = await saasGet(
      `SELECT COUNT(*) AS n FROM saas.tenant_licenses WHERE license_type_id=$1`, [id]
    );
    if (Number(inUse.n) > 0)
      return sendJson(res, { error: `Este tipo de licença está sendo usado por ${inUse.n} tenant(s) e não pode ser excluído. Revogue todas as licenças associadas primeiro.` }, 409);
    // Cascata: remove módulos associados e depois o tipo
    await saasRun(`DELETE FROM saas.license_type_modules WHERE license_type_id=$1`, [id]);
    await saasRun(`DELETE FROM saas.license_types WHERE id=$1`, [id]);
    sendJson(res, { ok: true });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// ── Licenças por Tenant ───────────────────────────────────────────────

// GET /api/superadmin/tenants/:slug/license
addRoute('GET', '/api/superadmin/tenants/:slug/license', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug } = ctx.params;
    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [slug]);
    if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);

    // Licença ativa
    const license = await saasGet(
      `SELECT tl.*, lt.slug AS plan_slug, lt.name AS plan_name, lt.price_monthly, lt.price_yearly
       FROM saas.tenant_licenses tl
       JOIN saas.license_types lt ON lt.id=tl.license_type_id
       WHERE tl.tenant_id=$1 AND tl.status='active'
       ORDER BY tl.created_at DESC LIMIT 1`,
      [tenant.id]
    );

    // Módulos do plano
    let planModules = [];
    if (license) {
      planModules = await saasAll(
        `SELECT m.id, m.slug, m.name, m.category, m.has_ext_cost, ltm.percent_share
         FROM saas.license_type_modules ltm
         JOIN saas.modules m ON m.id=ltm.module_id
         WHERE ltm.license_type_id=$1 AND m.active=TRUE ORDER BY m.sort_order`,
        [license.license_type_id]
      );
    }

    // Overrides individuais
    const overrides = await saasAll(
      `SELECT tmo.*, m.slug, m.name, m.category
       FROM saas.tenant_module_overrides tmo
       JOIN saas.modules m ON m.id=tmo.module_id
       WHERE tmo.tenant_id=$1
       ORDER BY m.sort_order`,
      [tenant.id]
    );

    // Módulos efetivos (plano + overrides)
    const effectiveModules = await _resolveEffectiveModules(tenant.id);

    sendJson(res, { license, plan_modules: planModules, overrides, effective_modules: effectiveModules });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/tenants/:slug/license — atribui ou troca licença
addRoute('POST', '/api/superadmin/tenants/:slug/license', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug } = ctx.params;
    const { license_type_id, billing_period = 'monthly', starts_at, ends_at, status = 'active', notes } = ctx.body;
    if (!license_type_id) return sendJson(res, { error: 'license_type_id obrigatório' }, 400);

    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [slug]);
    if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);

    // Suspende licença anterior ativa
    await saasRun(
      `UPDATE saas.tenant_licenses SET status='suspended'
       WHERE tenant_id=$1 AND status='active'`,
      [tenant.id]
    );

    const row = await saasGet(
      `INSERT INTO saas.tenant_licenses(tenant_id, license_type_id, billing_period, starts_at, ends_at, status, notes, created_by_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [tenant.id, license_type_id, billing_period,
       starts_at || new Date().toISOString().slice(0,10),
       ends_at || null, status, notes || null,
       ctx.user.super_admin_id]
    );
    sendJson(res, row, 201);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// DELETE /api/superadmin/tenants/:slug/license — revoga licença ativa
addRoute('DELETE', '/api/superadmin/tenants/:slug/license', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug } = ctx.params;
    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [slug]);
    if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);
    const updated = await saasGet(
      `UPDATE saas.tenant_licenses SET status='cancelled', ends_at=CURRENT_DATE
       WHERE tenant_id=$1 AND status='active'
       RETURNING id`,
      [tenant.id]
    );
    if (!updated) return sendJson(res, { error: 'Nenhuma licença ativa encontrada para este tenant' }, 404);
    sendJson(res, { ok: true });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/tenants/:slug/license/override — add/remove módulo individual
addRoute('POST', '/api/superadmin/tenants/:slug/license/override', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug } = ctx.params;
    const { module_id, granted, reason, expires_at } = ctx.body;
    if (module_id === undefined || granted === undefined) return sendJson(res, { error: 'module_id e granted obrigatórios' }, 400);

    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [slug]);
    if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);

    const row = await saasGet(
      `INSERT INTO saas.tenant_module_overrides(tenant_id, module_id, granted, reason, expires_at, granted_by)
       VALUES($1,$2,$3,$4,$5,$6)
       ON CONFLICT(tenant_id, module_id) DO UPDATE
         SET granted=$3, reason=$4, expires_at=$5, granted_by=$6, created_at=NOW()
       RETURNING *`,
      [tenant.id, module_id, !!granted, reason || null, expires_at || null, ctx.user.super_admin_id]
    );
    _evictModulesCache(tenant.id);
    sendJson(res, row, 201);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// DELETE /api/superadmin/tenants/:slug/license/override/:module_id
addRoute('DELETE', '/api/superadmin/tenants/:slug/license/override/:module_id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug, module_id } = ctx.params;
    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [slug]);
    if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);
    await saasRun(
      `DELETE FROM saas.tenant_module_overrides WHERE tenant_id=$1 AND module_id=$2`,
      [tenant.id, module_id]
    );
    _evictModulesCache(tenant.id);
    sendJson(res, { ok: true });
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/tenants/:slug/license/effective — módulos efetivos resolvidos
addRoute('GET', '/api/superadmin/tenants/:slug/license/effective', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { slug } = ctx.params;
    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [slug]);
    if (!tenant) return sendJson(res, { error: 'Tenant não encontrado' }, 404);
    const modules = await _resolveEffectiveModules(tenant.id);
    sendJson(res, modules);
  } catch (e) { sendJson(res, { error: e.message }, 500); }
});

// ── Cache de módulos por tenant (TTL 60s) ─────────────────────────────
const _modulesCache = new Map(); // tenantId → { mods, expiresAt }
const MODULES_CACHE_TTL = 60_000;

function _evictModulesCache(tenantId) {
  if (tenantId != null) _modulesCache.delete(tenantId);
  else _modulesCache.clear();
}

// ── Helper: resolve módulos efetivos de um tenant ─────────────────────
async function _resolveEffectiveModules(tenantId) {
  const hit = _modulesCache.get(tenantId);
  if (hit && Date.now() < hit.expiresAt) return hit.mods;

  // Módulos do plano ativo
  const planMods = await saasAll(
    `SELECT m.id, m.slug, m.name, m.category, m.has_ext_cost, 'plan' AS source
     FROM saas.tenant_licenses tl
     JOIN saas.license_type_modules ltm ON ltm.license_type_id=tl.license_type_id
     JOIN saas.modules m ON m.id=ltm.module_id
     WHERE tl.tenant_id=$1 AND tl.status='active' AND m.active=TRUE
       AND (tl.ends_at IS NULL OR tl.ends_at >= CURRENT_DATE)
     ORDER BY m.sort_order`,
    [tenantId]
  );

  // Overrides válidos
  const overrides = await saasAll(
    `SELECT tmo.module_id, tmo.granted, m.id, m.slug, m.name, m.category, m.has_ext_cost
     FROM saas.tenant_module_overrides tmo
     JOIN saas.modules m ON m.id=tmo.module_id
     WHERE tmo.tenant_id=$1 AND m.active=TRUE
       AND (tmo.expires_at IS NULL OR tmo.expires_at >= CURRENT_DATE)`,
    [tenantId]
  );

  const result = new Map(planMods.map(m => [m.id, { ...m }]));

  for (const ov of overrides) {
    if (ov.granted) {
      result.set(ov.module_id, { id: ov.id, slug: ov.slug, name: ov.name, category: ov.category, has_ext_cost: ov.has_ext_cost, source: 'override_add' });
    } else {
      result.delete(ov.module_id);
    }
  }

  const mods = Array.from(result.values());
  _modulesCache.set(tenantId, { mods, expiresAt: Date.now() + MODULES_CACHE_TTL });
  return mods;
}

// ── Sincroniza tenant_licenses com o plano do contrato/provisionamento ──
// Garante que tenant_licenses reflete o plano correto, criando ou trocando.
async function _syncTenantLicense(tenantSlug, planSlug, contractId) {
  try {
    const lt = await saasGet(`SELECT id FROM saas.license_types WHERE slug=$1`, [planSlug]);
    if (!lt) { console.warn(`[syncLicense] Tipo de licença não encontrado para slug="${planSlug}"`); return; }
    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [tenantSlug]);
    if (!tenant) return;
    // Suspende qualquer licença ativa anterior
    await saasRun(
      `UPDATE saas.tenant_licenses SET status='suspended' WHERE tenant_id=$1 AND status='active'`,
      [tenant.id]
    );
    // Cria nova licença ativa vinculada ao plano correto
    await saasGet(
      `INSERT INTO saas.tenant_licenses(tenant_id, license_type_id, contract_id, billing_period, starts_at, status)
       VALUES($1,$2,$3,'monthly',CURRENT_DATE,'active') RETURNING id`,
      [tenant.id, lt.id, contractId || null]
    );
  } catch(e) {
    console.error('[syncLicense] Erro:', e.message);
  }
}

// ── Middleware: requer módulo licenciado ──────────────────────────────
function requireModule(moduleSlug) {
  return async (req, res, ctx, next) => {
    try {
      // ctx.tenant vem do tenantMiddleware (já em cache) — evita query extra ao saas
      const tenantId = ctx.tenant?.id;
      if (!tenantId) return sendJson(res, { error: 'Tenant não encontrado' }, 404);
      const mods = await _resolveEffectiveModules(tenantId);
      if (!mods.some(m => m.slug === moduleSlug)) {
        return sendJson(res, { error: 'MODULE_NOT_LICENSED', module: moduleSlug }, 403);
      }
      return next();
    } catch (e) { return sendJson(res, { error: e.message }, 500); }
  };
}

// ═════════════════════════════════════════════════════════════════════
//  FASE 2 — PROPOSTAS COMERCIAIS
// ═════════════════════════════════════════════════════════════════════

// ── Motor de cálculo ─────────────────────────────────────────────────
function calcProposal(boats, params) {
  const { price_per_foot, dry_multiplier, covered_multiplier, wet_multiplier, setup_fee,
          volume_discount_pct, period_discount_pct } = params;
  let totalFeet = 0;
  const linesOut = boats.map(b => {
    const st = b.spot_type || 'seca_sol';
    const mult = st === 'molhada'    ? Number(wet_multiplier     || 1.2)
               : st === 'seca_coberta' ? Number(covered_multiplier || 1.1)
               : Number(dry_multiplier || 1);   // seca_sol + legado 'seca'
    const factor = Number(b.category_factor || 1);
    const feet = Number(b.eslora_feet || 0);
    const line = feet * Number(price_per_foot) * mult * factor;
    totalFeet += feet;
    return { ...b, line_value: Math.round(line * 100) / 100 };
  });
  const base = linesOut.reduce((s, b) => s + b.line_value, 0);
  const volDisc  = base * (Number(volume_discount_pct || 0) / 100);
  const perDisc  = base * (Number(period_discount_pct || 0) / 100);
  const discount = volDisc + perDisc;
  const final    = Math.max(0, base - discount) + Number(setup_fee || 0);
  return {
    boats: linesOut,
    total_feet:     Math.round(totalFeet * 100) / 100,
    total_boats:    linesOut.length,
    base_value:     Math.round(base * 100) / 100,
    discount_value: Math.round(discount * 100) / 100,
    final_value:    Math.round(final * 100) / 100,
  };
}

async function _getPricingDefaults() {
  const rows = await saasAll(
    `SELECT key, value FROM saas.settings WHERE key LIKE 'pricing_%'`
  );
  const cfg = {};
  rows.forEach(r => { cfg[r.key.replace('pricing_','')] = r.value; });
  return {
    price_per_foot:      Number(cfg.price_per_foot      || 5),
    dry_multiplier:      Number(cfg.dry_multiplier      || 1),
    covered_multiplier:  Number(cfg.covered_multiplier  || 1.1),
    wet_multiplier:      Number(cfg.wet_multiplier      || 1.2),
    setup_fee:           Number(cfg.setup_fee           || 0),
    valid_days:          Number(cfg.valid_days          || 30),
  };
}

async function _proposalSnapshot(id) {
  const p = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE id=$1`, [id]);
  if (!p) return null;
  const boats = await saasAll(`SELECT * FROM saas.pricing_proposal_boats WHERE proposal_id=$1 ORDER BY sort_order,id`, [id]);
  return { ...p, boats };
}

async function _logProposal(proposalId, action, opts = {}) {
  const { oldStatus, newStatus, notes, doneById, snapshot } = opts;
  await saasRun(
    `INSERT INTO saas.pricing_proposal_history(proposal_id,action,old_status,new_status,snapshot,notes,done_by_id)
     VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [proposalId, action, oldStatus||null, newStatus||null,
     snapshot ? JSON.stringify(snapshot) : null, notes||null, doneById||null]
  );
}

// GET /api/superadmin/proposals
addRoute('GET', '/api/superadmin/proposals', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const rows = await saasAll(
      `SELECT p.*, lt.name AS license_type_name,
              (SELECT COUNT(*) FROM saas.pricing_proposal_boats b WHERE b.proposal_id=p.id) AS boat_count,
              t.name AS tenant_name, t.active AS tenant_active
       FROM saas.pricing_proposals p
       LEFT JOIN saas.license_types lt ON lt.id=p.license_type_id
       LEFT JOIN saas.tenants t ON t.slug=p.tenant_slug
       ORDER BY p.updated_at DESC`
    );
    sendJson(res, rows);
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/proposals/implantacao — propostas aprovadas/convertidas p/ verificação
addRoute('GET', '/api/superadmin/proposals/implantacao', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const rows = await saasAll(`
      SELECT p.id, p.lead_name, p.lead_email, p.status, p.final_value,
             p.tenant_slug, p.approved_at, p.updated_at,
             t.id AS tenant_id, t.active AS tenant_active, t.name AS tenant_name,
             lc.id AS contract_id
      FROM saas.pricing_proposals p
      LEFT JOIN saas.tenants t       ON t.slug = p.tenant_slug
      LEFT JOIN saas.license_contracts lc ON lc.proposal_id = p.id
      WHERE p.status IN ('approved','converted')
      ORDER BY p.updated_at DESC
    `);
    sendJson(res, rows);
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/proposals/:id
addRoute('GET', '/api/superadmin/proposals/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const p = await _proposalSnapshot(ctx.params.id);
    if (!p) return sendJson(res, { error: 'Proposta não encontrada' }, 404);
    const mods = await saasAll(
      `SELECT ppm.*, m.name, m.slug, m.category FROM saas.pricing_proposal_modules ppm
       JOIN saas.modules m ON m.id=ppm.module_id WHERE ppm.proposal_id=$1`, [p.id]
    );
    const history = await saasAll(
      `SELECT h.*, sa.name AS done_by_name FROM saas.pricing_proposal_history h
       LEFT JOIN saas.super_admins sa ON sa.id=h.done_by_id
       WHERE h.proposal_id=$1 ORDER BY h.done_at DESC`, [p.id]
    );
    sendJson(res, { ...p, modules: mods, history, boats: p.boats || [] });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/proposals/calc — prévia de cálculo sem persistir
addRoute('POST', '/api/superadmin/proposals/calc', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { boats = [], params = {} } = ctx.body;
    const defs = await _getPricingDefaults();
    const merged = { ...defs, ...params };
    const result = calcProposal(boats, merged);
    sendJson(res, result);
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/proposals
addRoute('POST', '/api/superadmin/proposals', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { lead_name, lead_cnpj, lead_email, lead_phone, lead_city_state,
            lead_contact_name, lead_contact_role, license_type_id,
            billing_period = 'monthly', notes, boats = [], valid_until,
            price_per_foot, dry_multiplier, covered_multiplier, wet_multiplier, setup_fee,
            volume_discount_pct = 0, period_discount_pct = 0 } = ctx.body;
    if (!lead_name) return sendJson(res, { error: 'Nome da marina é obrigatório' }, 400);

    const defs = await _getPricingDefaults();
    const params = {
      price_per_foot:      Number(price_per_foot     ?? defs.price_per_foot),
      dry_multiplier:      Number(dry_multiplier     ?? defs.dry_multiplier),
      covered_multiplier:  Number(covered_multiplier ?? defs.covered_multiplier),
      wet_multiplier:      Number(wet_multiplier     ?? defs.wet_multiplier),
      setup_fee:           Number(setup_fee          ?? defs.setup_fee),
      volume_discount_pct: Number(volume_discount_pct),
      period_discount_pct: Number(period_discount_pct),
    };
    const calc = calcProposal(boats, params);
    const validUntilDate = valid_until || (() => {
      const d = new Date(); d.setDate(d.getDate() + defs.valid_days); return d.toISOString().slice(0,10);
    })();

    const row = await saasGet(
      `INSERT INTO saas.pricing_proposals(
         lead_name,lead_cnpj,lead_email,lead_phone,lead_city_state,
         lead_contact_name,lead_contact_role,license_type_id,
         price_per_foot,dry_multiplier,covered_multiplier,wet_multiplier,setup_fee,billing_period,
         volume_discount_pct,period_discount_pct,
         total_feet,total_boats,base_value,discount_value,final_value,
         valid_until,notes,created_by_id,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,'draft')
       RETURNING *`,
      [lead_name, lead_cnpj||null, lead_email||null, lead_phone||null, lead_city_state||null,
       lead_contact_name||null, lead_contact_role||null, license_type_id||null,
       params.price_per_foot, params.dry_multiplier, params.covered_multiplier, params.wet_multiplier, params.setup_fee,
       billing_period, params.volume_discount_pct, params.period_discount_pct,
       calc.total_feet, calc.total_boats, calc.base_value, calc.discount_value, calc.final_value,
       validUntilDate, notes||null, ctx.user.super_admin_id]
    );

    for (let i = 0; i < calc.boats.length; i++) {
      const b = calc.boats[i];
      await saasRun(
        `INSERT INTO saas.pricing_proposal_boats(proposal_id,name,boat_type,spot_type,eslora_feet,category_factor,line_value,sort_order)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [row.id, b.name, b.boat_type||'lancha', b.spot_type||'seca_sol',
         b.eslora_feet, b.category_factor||1, b.line_value, i]
      );
    }
    await _logProposal(row.id, 'created', { newStatus:'draft', doneById: ctx.user.super_admin_id, snapshot: await _proposalSnapshot(row.id) });
    sendJson(res, { ok: true, id: row.id }, 201);
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/proposals/:id  — atualiza dados e recalcula
addRoute('PUT', '/api/superadmin/proposals/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    const current = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE id=$1`, [id]);
    if (!current) return sendJson(res, { error: 'Proposta não encontrada' }, 404);
    if (['converted','signed'].includes(current.status))
      return sendJson(res, { error: 'Proposta já convertida/assinada não pode ser editada' }, 409);

    const { lead_name, lead_cnpj, lead_email, lead_phone, lead_city_state,
            lead_contact_name, lead_contact_role, license_type_id,
            billing_period, notes, boats,
            price_per_foot, dry_multiplier, covered_multiplier, wet_multiplier, setup_fee,
            volume_discount_pct, period_discount_pct } = ctx.body;

    const params = {
      price_per_foot:      Number(price_per_foot      ?? current.price_per_foot),
      dry_multiplier:      Number(dry_multiplier      ?? current.dry_multiplier),
      covered_multiplier:  Number(covered_multiplier  ?? current.covered_multiplier ?? 1.1),
      wet_multiplier:      Number(wet_multiplier      ?? current.wet_multiplier),
      setup_fee:           Number(setup_fee           ?? current.setup_fee),
      volume_discount_pct: Number(volume_discount_pct ?? current.volume_discount_pct),
      period_discount_pct: Number(period_discount_pct ?? current.period_discount_pct),
    };

    let calc = { total_feet: current.total_feet, total_boats: current.total_boats,
                 base_value: current.base_value, discount_value: current.discount_value,
                 final_value: current.final_value, boats: [] };

    if (boats !== undefined) {
      calc = calcProposal(boats, params);
      await saasRun(`DELETE FROM saas.pricing_proposal_boats WHERE proposal_id=$1`, [id]);
      for (let i = 0; i < calc.boats.length; i++) {
        const b = calc.boats[i];
        await saasRun(
          `INSERT INTO saas.pricing_proposal_boats(proposal_id,name,boat_type,spot_type,eslora_feet,category_factor,line_value,sort_order)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
          [id, b.name, b.boat_type||'lancha', b.spot_type||'seca_sol',
           b.eslora_feet, b.category_factor||1, b.line_value, i]
        );
      }
    }

    await saasRun(
      `UPDATE saas.pricing_proposals SET
         lead_name=COALESCE($1,lead_name), lead_cnpj=COALESCE($2,lead_cnpj),
         lead_email=COALESCE($3,lead_email), lead_phone=COALESCE($4,lead_phone),
         lead_city_state=COALESCE($5,lead_city_state),
         lead_contact_name=COALESCE($6,lead_contact_name),
         lead_contact_role=COALESCE($7,lead_contact_role),
         license_type_id=COALESCE($8,license_type_id),
         billing_period=COALESCE($9,billing_period), notes=COALESCE($10,notes),
         price_per_foot=$11, dry_multiplier=$12, covered_multiplier=$13, wet_multiplier=$14, setup_fee=$15,
         volume_discount_pct=$16, period_discount_pct=$17,
         total_feet=$18, total_boats=$19, base_value=$20, discount_value=$21, final_value=$22,
         updated_at=NOW()
       WHERE id=$23`,
      [lead_name||null, lead_cnpj||null, lead_email||null, lead_phone||null,
       lead_city_state||null, lead_contact_name||null, lead_contact_role||null,
       license_type_id||null, billing_period||null, notes||null,
       params.price_per_foot, params.dry_multiplier, params.covered_multiplier, params.wet_multiplier, params.setup_fee,
       params.volume_discount_pct, params.period_discount_pct,
       calc.total_feet, calc.total_boats, calc.base_value, calc.discount_value, calc.final_value,
       id]
    );
    await _logProposal(id, 'edited', { doneById: ctx.user.super_admin_id, snapshot: await _proposalSnapshot(id) });
    sendJson(res, { ok: true });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// PUT /api/superadmin/proposals/:id/status
addRoute('PUT', '/api/superadmin/proposals/:id/status', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    const { status, notes, sent_to, negotiation_notes, rejection_reason } = ctx.body;
    const allowed = ['draft','sent','negotiation','approved','rejected','converted'];
    if (!allowed.includes(status)) return sendJson(res, { error: 'Status inválido' }, 400);
    const current = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE id=$1`, [id]);
    if (!current) return sendJson(res, { error: 'Proposta não encontrada' }, 404);

    const fields = ['status=$1', 'updated_at=NOW()'];
    const vals   = [status];
    if (status === 'sent') {
      fields.push('sent_at=NOW()');
      if (sent_to) { fields.push(`sent_to=$${vals.length + 1}`); vals.push(sent_to); }
    }
    if (status === 'negotiation' && negotiation_notes) {
      fields.push(`negotiation_notes=$${vals.length + 1}`); vals.push(negotiation_notes);
    }
    if (status === 'approved') fields.push('approved_at=NOW()');
    if (status === 'rejected') {
      fields.push('rejected_at=NOW()');
      if (rejection_reason) { fields.push(`rejection_reason=$${vals.length + 1}`); vals.push(rejection_reason); }
    }
    if (status === 'converted') fields.push('approved_at=COALESCE(approved_at,NOW())');
    vals.push(id);
    await saasRun(`UPDATE saas.pricing_proposals SET ${fields.join(', ')} WHERE id=$${vals.length}`, vals);

    const logNotes = notes || negotiation_notes || rejection_reason || null;
    await _logProposal(id, 'status_changed', { oldStatus: current.status, newStatus: status, notes: logNotes, doneById: ctx.user.super_admin_id });

    let activated = false, tenant_slug = null;
    if (status === 'converted' && current.status !== 'converted') {
      // Se tenant e contrato já existem (criados manualmente), apenas atualiza status
      const contractExists = await saasGet(
        `SELECT id, tenant_slug FROM saas.license_contracts WHERE proposal_id=$1 LIMIT 1`, [id]
      );
      if (contractExists) {
        const tSlug = contractExists.tenant_slug;
        await saasRun(
          `UPDATE saas.pricing_proposals SET tenant_slug=$1, contract_id=$2, status='converted', updated_at=NOW() WHERE id=$3`,
          [tSlug, contractExists.id, id]
        );
        activated = false; tenant_slug = tSlug;
      } else {
        const fresh = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE id=$1`, [id]);
        const result = await _activateTenantFromProposal(fresh);
        activated = result.activated; tenant_slug = result.slug;
      }
    }
    sendJson(res, { ok: true, activated, tenant_slug });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// DELETE /api/superadmin/proposals/:id
addRoute('DELETE', '/api/superadmin/proposals/:id', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const p = await saasGet(`SELECT status FROM saas.pricing_proposals WHERE id=$1`, [ctx.params.id]);
    if (!p) return sendJson(res, { error: 'Proposta não encontrada' }, 404);
    if (['converted'].includes(p.status)) return sendJson(res, { error: 'Proposta convertida não pode ser excluída' }, 409);
    await saasRun(`DELETE FROM saas.pricing_proposals WHERE id=$1`, [ctx.params.id]);
    sendJson(res, { ok: true });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/superadmin/proposals/:id/send  — gera token + marca como sent
addRoute('POST', '/api/superadmin/proposals/:id/send', async (req, res, ctx) => {
  if (!requireSuperAdmin(ctx, res)) return;
  try {
    const { id } = ctx.params;
    const p = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE id=$1`, [id]);
    if (!p) return sendJson(res, { error: 'Proposta não encontrada' }, 404);
    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
    const { sent_to } = ctx.body || {};
    await saasRun(
      `UPDATE saas.pricing_proposals SET status='sent', sent_at=NOW(), sent_to=$1, signature_token=$2, updated_at=NOW() WHERE id=$3`,
      [sent_to || null, token, id]
    );
    await _logProposal(id, 'sent', { oldStatus: p.status, newStatus: 'sent', doneById: ctx.user.super_admin_id });
    sendJson(res, { ok: true, token, link: `/assinar/${token}` });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// GET /api/superadmin/proposals/:id/preview  — HTML imprimível
addRoute('GET', '/api/superadmin/proposals/:id/preview', async (req, res, ctx) => {
  const { jwtVerify } = require('./src/middleware/auth');
  let user = ctx.user;
  if (!user) {
    const qToken = (ctx.qs || {}).token || '';
    try { user = qToken ? jwtVerify(qToken) : null; } catch { user = null; }
  }
  if (!user || user.role !== 'superadmin') {
    res.writeHead(403, { 'Content-Type': 'text/html' });
    return res.end('<h2>Acesso negado</h2>');
  }
  try {
    const p = await _proposalSnapshot(ctx.params.id);
    if (!p) { res.writeHead(404); return res.end('Proposta não encontrada'); }
    const lt = p.license_type_id
      ? await saasGet(`SELECT name FROM saas.license_types WHERE id=$1`, [p.license_type_id])
      : null;
    const cfgRows = await saasAll(`SELECT key,value FROM saas.settings`);
    const cfg = {};
    cfgRows.forEach(r => { cfg[r.key] = r.value || ''; });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(generateProposalHtml(p, lt, cfg));
  } catch(e) { res.writeHead(500); res.end(e.message); }
});

// ── Assinatura pública ────────────────────────────────────────────────
// GET /api/public/proposals/:token  — dados para a página pública
addRoute('GET', '/api/public/proposals/:token', async (req, res) => {
  try {
    const p = await saasGet(
      `SELECT p.*, lt.name AS license_type_name
       FROM saas.pricing_proposals p
       LEFT JOIN saas.license_types lt ON lt.id=p.license_type_id
       WHERE p.signature_token=$1`, [ctx_token(req)]
    );
    if (!p) return sendJson(res, { error: 'Proposta não encontrada ou link inválido' }, 404);
    if (p.signed_at) return sendJson(res, { error: 'Esta proposta já foi assinada' }, 409);
    if (p.status === 'rejected') return sendJson(res, { error: 'Esta proposta foi rejeitada' }, 410);
    const boats = await saasAll(
      `SELECT * FROM saas.pricing_proposal_boats WHERE proposal_id=$1 ORDER BY sort_order,id`, [p.id]
    );
    sendJson(res, { ...p, boats, signature_token: undefined });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// POST /api/public/proposals/:token/sign  — assinar
addRoute('POST', '/api/public/proposals/:token/sign', async (req, res) => {
  try {
    const token = ctx_token(req);
    const { signed_name, signed_doc } = req._body || {};
    if (!signed_name) return sendJson(res, { error: 'Nome do signatário é obrigatório' }, 400);
    const p = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE signature_token=$1`, [token]);
    if (!p) return sendJson(res, { error: 'Link inválido' }, 404);
    if (p.signed_at) return sendJson(res, { error: 'Proposta já assinada' }, 409);

    const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';
    await saasRun(
      `UPDATE saas.pricing_proposals SET
         signed_at=NOW(), signed_name=$1, signed_doc=$2, signed_ip=$3,
         status='approved', updated_at=NOW()
       WHERE id=$4`,
      [signed_name, signed_doc||null, ip, p.id]
    );
    await _logProposal(p.id, 'signed', { oldStatus: p.status, newStatus: 'approved',
      notes: `Assinado por ${signed_name}`, snapshot: await _proposalSnapshot(p.id) });

    // Ativação automática do tenant
    const result = await _activateTenantFromProposal(p);
    sendJson(res, { ok: true, activated: result.activated, tenant_slug: result.slug });
  } catch(e) { sendJson(res, { error: e.message }, 500); }
});

// Helper: extrai token da URL /api/public/proposals/:token/*
function ctx_token(req) {
  const m = (req.url || '').match(/\/api\/public\/proposals\/([^\/\?]+)/);
  return m ? m[1] : '';
}

// Ativação automática do tenant após assinatura
async function _activateTenantFromProposal(p) {
  try {
    // Gera slug a partir do nome da marina
    let slug = (p.lead_name || 'marina')
      .toLowerCase()
      .normalize('NFD').replace(/[̀-ͯ]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 40);

    // Resolve o slug do plano a partir do license_type_id da proposta
    let planSlug = 'pro';
    if (p.license_type_id) {
      const lt = await saasGet(`SELECT slug FROM saas.license_types WHERE id=$1`, [p.license_type_id]);
      if (lt) planSlug = lt.slug;
    }

    // Verifica se já existe tenant
    const existing = await saasGet(`SELECT id, slug FROM saas.tenants WHERE slug=$1`, [slug]);
    let finalSlug = slug;
    if (existing) {
      finalSlug = existing.slug;
    } else {
      const adminEmail    = p.lead_email    || `admin@${slug}.marina`;
      const adminPassword = 'Marina@' + Math.random().toString(36).slice(2,8);
      await provisionTenant(finalSlug, {
        marinaName:    p.lead_name,
        plan:          planSlug,
        adminEmail,
        adminPassword,
        adminName:     p.lead_contact_name || 'Administrador',
        spots_seca:    0,
        spots_molhada: 0,
        logo_base64:   '',
      });
      await saasRun(
        `UPDATE saas.tenants SET
           admin_email=$1, admin_password_plain=$2,
           cnpj=$3, representative_name=$4
         WHERE slug=$5`,
        [adminEmail, adminPassword, p.lead_cnpj||null, p.lead_contact_name||null, finalSlug]
      );
    }

    // Verifica se contrato já existe para esta proposta (idempotência)
    const existingContract = await saasGet(
      `SELECT id FROM saas.license_contracts WHERE proposal_id=$1 LIMIT 1`, [p.id]
    );
    if (existingContract) {
      await saasRun(
        `UPDATE saas.pricing_proposals SET tenant_slug=$1, contract_id=$2, status='converted', updated_at=NOW() WHERE id=$3`,
        [finalSlug, existingContract.id, p.id]
      );
      return { activated: false, slug: finalSlug };
    }

    // Cria contrato de licença
    const contract = await saasGet(
      `INSERT INTO saas.license_contracts(
         tenant_slug, plan, monthly_value, start_date, status, notes, proposal_id)
       VALUES($1,$2,$3,CURRENT_DATE,'active',$4,$5) RETURNING id`,
      [finalSlug, planSlug, p.final_value, `Gerado automaticamente — Proposta #${p.id}`, p.id]
    );

    // Sincroniza licença técnica com o plano correto
    await _syncTenantLicense(finalSlug, planSlug, contract.id);

    // Atualiza proposta como convertida
    await saasRun(
      `UPDATE saas.pricing_proposals SET
         tenant_slug=$1, contract_id=$2, status='converted', updated_at=NOW()
       WHERE id=$3`,
      [finalSlug, contract.id, p.id]
    );
    await _logProposal(p.id, 'activated', { oldStatus: 'approved', newStatus: 'converted',
      notes: `Tenant ${finalSlug} ativado` });

    return { activated: true, slug: finalSlug };
  } catch(e) {
    console.error('[activation]', e.message);
    return { activated: false, slug: null };
  }
}

// Geração do HTML da proposta (imprimível)
function generateProposalHtml(p, lt, cfg) {
  const fmtBRL  = v => 'R$ ' + Number(v||0).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const fmtDate = d => d ? new Date(d + 'T12:00:00').toLocaleDateString('pt-BR') : '—';
  const propNum = `MOP-${String(p.id).padStart(4,'0')}/${new Date().getFullYear()}`;
  const company = cfg.company_legal_name || 'Marina One Tecnologia Ltda.';
  const boatTypeLabel = { lancha:'Lancha', veleiro:'Veleiro', iate:'Iate', jet_ski:'Jet Ski', outro:'Outro' };
  const spotLabel = { seca:'Seca', molhada:'Molhada' };
  const periodLabel = p.billing_period === 'yearly' ? 'anual' : 'mensal';

  const boatRows = (p.boats||[]).map((b,i) => `
    <tr>
      <td>${i+1}</td><td>${b.name||'—'}</td>
      <td>${boatTypeLabel[b.boat_type]||b.boat_type}</td>
      <td>${spotLabel[b.spot_type]||b.spot_type}</td>
      <td>${Number(b.eslora_feet).toFixed(1)} pés</td>
      <td>${Number(b.category_factor).toFixed(2)}×</td>
      <td style="text-align:right">${fmtBRL(b.line_value)}</td>
    </tr>`).join('');

  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>Proposta ${propNum}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Helvetica Neue',Arial,sans-serif;font-size:13px;color:#1a2332;background:#fff;padding:40px}
  h1{font-size:22px;font-weight:700;color:#1a8de6}
  h2{font-size:15px;font-weight:700;margin:24px 0 10px;color:#1a2332;border-bottom:2px solid #1a8de6;padding-bottom:6px}
  .header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px}
  .logo-area h1{margin-bottom:4px}.logo-area p{font-size:11px;color:#64748b}
  .prop-meta{text-align:right;font-size:12px;color:#64748b}
  .prop-meta strong{display:block;font-size:18px;color:#1a2332;margin-bottom:4px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:24px}
  .card{border:1px solid #e2e8f0;border-radius:8px;padding:16px}
  .card label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#94a3b8;display:block;margin-bottom:2px}
  .card span{font-size:13px;font-weight:500}
  table{width:100%;border-collapse:collapse;margin-bottom:16px}
  th{background:#f1f5f9;padding:9px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:#64748b}
  td{padding:9px 12px;border-bottom:1px solid #f1f5f9;font-size:13px}
  .totals{margin-left:auto;width:320px}
  .totals td{padding:7px 12px}
  .totals .label{color:#64748b}
  .totals .total-row{font-weight:700;font-size:15px;border-top:2px solid #1a8de6;color:#1a8de6}
  .badge{display:inline-block;padding:3px 10px;border-radius:100px;font-size:11px;font-weight:700}
  .badge-blue{background:#dbeafe;color:#1d4ed8}
  .footer{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;font-size:11px;color:#94a3b8;display:flex;justify-content:space-between}
  .sign-area{margin-top:48px;display:grid;grid-template-columns:1fr 1fr;gap:40px}
  .sign-line{border-top:1px solid #1a2332;margin-top:40px;padding-top:8px;font-size:11px;color:#64748b;text-align:center}
  @media print{body{padding:20px}button{display:none}}
</style></head><body>
<div style="text-align:right;margin-bottom:16px">
  <button onclick="window.print()" style="padding:8px 18px;background:#1a8de6;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px">🖨️ Imprimir / Salvar PDF</button>
</div>
<div class="header">
  <div class="logo-area"><h1>⚓ ${cfg.general_system_name||'Marina One'}</h1><p>${company}</p></div>
  <div class="prop-meta">
    <strong>Proposta ${propNum}</strong>
    Emitida em: ${new Date().toLocaleDateString('pt-BR')}<br>
    Válida até: ${fmtDate(p.valid_until)}<br>
    <span class="badge badge-blue">${lt ? lt.name : 'Plano personalizado'}</span>
  </div>
</div>

<h2>Dados da Marina</h2>
<div class="grid2">
  <div class="card">
    <label>Razão Social / Nome</label><span>${p.lead_name}</span><br><br>
    <label>CNPJ</label><span>${p.lead_cnpj||'—'}</span><br><br>
    <label>Cidade / Estado</label><span>${p.lead_city_state||'—'}</span>
  </div>
  <div class="card">
    <label>Representante</label><span>${p.lead_contact_name||'—'}</span><br><br>
    <label>Cargo</label><span>${p.lead_contact_role||'—'}</span><br><br>
    <label>E-mail</label><span>${p.lead_email||'—'}</span>
    ${p.lead_phone ? `<br><br><label>Telefone</label><span>${p.lead_phone}</span>` : ''}
  </div>
</div>

<h2>Embarcações Contempladas</h2>
<table>
  <thead><tr>
    <th>#</th><th>Embarcação</th><th>Tipo</th><th>Vaga</th>
    <th>Eslora</th><th>Fator</th><th style="text-align:right">Valor Mensal</th>
  </tr></thead>
  <tbody>${boatRows||'<tr><td colspan="7" style="text-align:center;color:#94a3b8">Nenhuma embarcação</td></tr>'}</tbody>
</table>

<table class="totals">
  <tr><td class="label">Total de pés (eslora)</td><td style="text-align:right">${Number(p.total_feet).toFixed(1)} pés</td></tr>
  <tr><td class="label">Valor/pé</td><td style="text-align:right">${fmtBRL(p.price_per_foot)}</td></tr>
  <tr><td class="label">Valor base</td><td style="text-align:right">${fmtBRL(p.base_value)}</td></tr>
  ${Number(p.discount_value)>0 ? `<tr><td class="label">Descontos</td><td style="text-align:right;color:#16a34a">- ${fmtBRL(p.discount_value)}</td></tr>` : ''}
  ${Number(p.setup_fee)>0 ? `<tr><td class="label">Taxa de implantação</td><td style="text-align:right">${fmtBRL(p.setup_fee)}</td></tr>` : ''}
  <tr class="total-row"><td>TOTAL ${periodLabel.toUpperCase()}</td><td style="text-align:right">${fmtBRL(p.final_value)}</td></tr>
</table>

${p.notes ? `<h2>Observações</h2><p style="padding:12px;background:#f8fafc;border-radius:6px;line-height:1.6">${p.notes}</p>` : ''}

<div class="sign-area">
  <div>
    <div class="sign-line">${p.lead_contact_name||'Representante da Marina'}<br>${p.lead_contact_role||'—'}</div>
  </div>
  <div>
    <div class="sign-line">${cfg.company_representative_name||'Representante Marina One'}<br>${cfg.company_representative_role||'Sócio-Administrador'}</div>
  </div>
</div>

<div class="footer">
  <span>${company} — ${cfg.company_cnpj||''}</span>
  <span>Proposta ${propNum} — ${new Date().toLocaleDateString('pt-BR')}</span>
</div>
</body></html>`;
}

// ── Página pública de assinatura (rota de conteúdo HTML) ─────────────
addRoute('GET', '/assinar/:token', async (req, res) => {
  const token = (req.url || '').split('/assinar/')[1]?.split('?')[0] || '';
  try {
    const p = await saasGet(
      `SELECT p.*, lt.name AS license_type_name
       FROM saas.pricing_proposals p
       LEFT JOIN saas.license_types lt ON lt.id=p.license_type_id
       WHERE p.signature_token=$1`, [token]
    );
    const boats = p ? await saasAll(
      `SELECT * FROM saas.pricing_proposal_boats WHERE proposal_id=$1 ORDER BY sort_order,id`, [p?.id]
    ) : [];
    const cfgRows = await saasAll(`SELECT key,value FROM saas.settings`);
    const cfg = {};
    cfgRows.forEach(r => { cfg[r.key] = r.value || ''; });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(generateSignaturePage(p, boats, cfg, token));
  } catch(e) { res.writeHead(500); res.end('<h2>Erro interno</h2>'); }
});

// POST /assinar/:token/confirmar
addRoute('POST', '/assinar/:token/confirmar', async (req, res) => {
  const token = (req.url || '').split('/assinar/')[1]?.split('/')[0] || '';
  try {
    const body = req._body || {};
    const { signed_name, signed_doc } = body;
    if (!signed_name) { res.writeHead(400); return res.end('Nome obrigatório'); }
    const p = await saasGet(`SELECT * FROM saas.pricing_proposals WHERE signature_token=$1`, [token]);
    if (!p) { res.writeHead(404); return res.end('Link inválido'); }
    if (p.signed_at) { res.writeHead(409); return res.end('Proposta já assinada'); }
    const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';
    await saasRun(
      `UPDATE saas.pricing_proposals SET signed_at=NOW(), signed_name=$1, signed_doc=$2, signed_ip=$3, status='approved', updated_at=NOW() WHERE id=$4`,
      [signed_name, signed_doc||null, ip, p.id]
    );
    await _logProposal(p.id, 'signed', { oldStatus: p.status, newStatus: 'approved', notes: `Assinado por ${signed_name}` });
    const result = await _activateTenantFromProposal({ ...p });
    // Redireciona para página de sucesso
    res.writeHead(302, { 'Location': `/assinar/${token}?signed=1` });
    res.end();
  } catch(e) { res.writeHead(500); res.end('<h2>Erro ao processar assinatura</h2><p>' + e.message + '</p>'); }
});

function generateSignaturePage(p, boats, cfg, token) {
  const fmtBRL  = v => 'R$ ' + Number(v||0).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const fmtDate = d => d ? new Date(d + 'T12:00:00').toLocaleDateString('pt-BR') : '—';
  const propNum = p ? `MOP-${String(p.id).padStart(4,'0')}/${new Date().getFullYear()}` : '—';
  const signed  = (new URL('http://x' + (p?.signed_at ? '?signed=1' : '?')).searchParams.get('signed')) || '';

  if (!p) return `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;text-align:center">
    <h2 style="color:#ef4444">Link inválido ou expirado</h2><p>Esta proposta não foi encontrada.</p></body></html>`;

  const alreadySigned = !!p.signed_at;
  const periodLabel = p.billing_period === 'yearly' ? 'anual' : 'mensal';
  const boatRows = boats.map((b,i) => `
    <tr><td>${i+1}. ${b.name}</td><td>${Number(b.eslora_feet).toFixed(1)} pés</td>
    <td>${b.spot_type==='molhada'?'Molhada':'Seca'}</td><td style="text-align:right">${fmtBRL(b.line_value)}</td></tr>`).join('');

  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proposta ${propNum} — Assinatura Digital</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a1628;color:#e2e8f0;min-height:100vh;padding:24px}
  .wrap{max-width:720px;margin:0 auto}
  .card{background:#111f38;border:1px solid #1e3a5f;border-radius:16px;padding:28px;margin-bottom:20px}
  h1{font-size:20px;font-weight:700;color:#1a8de6;margin-bottom:4px}
  h2{font-size:14px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}
  .meta{font-size:12px;color:#64748b;margin-bottom:24px}
  table{width:100%;border-collapse:collapse}
  td,th{padding:9px 10px;font-size:13px;border-bottom:1px solid #1e3a5f;text-align:left}
  th{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
  .total-row td{font-weight:700;font-size:16px;color:#1a8de6;border-top:2px solid #1a8de6;border-bottom:none}
  input,textarea{width:100%;background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;padding:10px 14px;color:#e2e8f0;font-size:13px;margin-top:6px;outline:none}
  input:focus,textarea:focus{border-color:#1a8de6;box-shadow:0 0 0 3px rgba(26,141,230,.2)}
  label{font-size:12px;font-weight:600;color:#94a3b8;display:block;margin-top:14px}
  .btn{display:block;width:100%;padding:14px;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
  .btn-primary{background:linear-gradient(135deg,#1a8de6,#2563eb);color:#fff}
  .btn-primary:hover{opacity:.9}
  .success{text-align:center;padding:40px}
  .success h2{color:#10b981;font-size:22px;margin-bottom:12px}
  .success p{color:#94a3b8;line-height:1.6}
  .badge{display:inline-block;padding:3px 10px;border-radius:100px;font-size:11px;font-weight:700;background:rgba(26,141,230,.15);color:#1a8de6;margin-bottom:12px}
  .warning{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);border-radius:8px;padding:12px 16px;font-size:12px;color:#fbbf24;margin-top:16px}
</style></head><body>
<div class="wrap">
  <div class="card">
    <div class="badge">⚓ ${cfg.general_system_name||'Marina One'}</div>
    <h1>Proposta Comercial ${propNum}</h1>
    <div class="meta">Emitida em ${new Date(p.created_at).toLocaleDateString('pt-BR')} · Válida até ${fmtDate(p.valid_until)} · ${p.license_type_name||'Plano personalizado'}</div>
    <h2>Dados da Marina</h2>
    <table>
      <tr><td style="color:#64748b;width:140px">Marina</td><td><strong>${p.lead_name}</strong></td></tr>
      ${p.lead_cnpj ? `<tr><td style="color:#64748b">CNPJ</td><td>${p.lead_cnpj}</td></tr>` : ''}
      ${p.lead_city_state ? `<tr><td style="color:#64748b">Cidade/UF</td><td>${p.lead_city_state}</td></tr>` : ''}
      ${p.lead_contact_name ? `<tr><td style="color:#64748b">Representante</td><td>${p.lead_contact_name}${p.lead_contact_role?' — '+p.lead_contact_role:''}</td></tr>` : ''}
    </table>
  </div>
  <div class="card">
    <h2>Embarcações</h2>
    <table>
      <thead><tr><th>Embarcação</th><th>Eslora</th><th>Vaga</th><th style="text-align:right">Valor</th></tr></thead>
      <tbody>${boatRows||'<tr><td colspan="4" style="text-align:center;color:#64748b">Nenhuma embarcação</td></tr>'}</tbody>
    </table>
    <table style="margin-top:12px;width:280px;margin-left:auto">
      ${Number(p.discount_value)>0 ? `<tr><td style="color:#64748b">Desconto</td><td style="text-align:right;color:#10b981">- ${fmtBRL(p.discount_value)}</td></tr>` : ''}
      <tr class="total-row"><td>Total ${periodLabel}</td><td style="text-align:right">${fmtBRL(p.final_value)}</td></tr>
    </table>
  </div>
  ${alreadySigned ? `
  <div class="card success">
    <h2>✅ Proposta já assinada</h2>
    <p>Assinada por <strong>${p.signed_name}</strong> em ${new Date(p.signed_at).toLocaleString('pt-BR')}.<br>
    Em breve nossa equipe entrará em contato para dar continuidade.</p>
  </div>` : `
  <div class="card">
    <h2>Assinar Proposta</h2>
    <p style="font-size:13px;color:#94a3b8;margin-bottom:4px;line-height:1.6">
      Ao assinar, você concorda com os termos desta proposta e autoriza a ${cfg.company_legal_name||'Marina One'} a prosseguir com a ativação do sistema.
    </p>
    <form method="POST" action="/assinar/${token}/confirmar">
      <label>Nome completo do signatário *</label>
      <input name="signed_name" required placeholder="Nome conforme documento" value="${p.lead_contact_name||''}">
      <label>CPF ou RG</label>
      <input name="signed_doc" placeholder="000.000.000-00">
      <div class="warning">⚠️ Esta ação é irreversível. Ao clicar em Assinar, a proposta será registrada com data, hora e IP desta sessão.</div>
      <button type="submit" class="btn btn-primary">✍️ Assinar Proposta Digitalmente</button>
    </form>
  </div>`}
  <div style="text-align:center;font-size:11px;color:#334155;margin-top:16px">
    ${cfg.company_legal_name||'Marina One'} · ${cfg.company_cnpj||''} · Proposta ${propNum}
  </div>
</div>
</body></html>`;
}

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — AUTH (por tenant)
// ═════════════════════════════════════════════════════════════════════
addRoute('POST', '/api/auth/login', async (req, res, ctx) => {
  if (!checkRateLimit(req)) return sendJson(res, { error: 'Muitas tentativas. Aguarde 15 minutos.' }, 429);
  const { email = '', password = '' } = ctx.body;
  const { dbGet: tGet, dbAll: tAll, dbRun: tRun } = ctx.db;
  const user = await tGet('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
  const { ok, needsRehash } = await verifyPassword(password, user?.password_hash || '');
  if (!user || !ok) return sendJson(res, { error: 'Credenciais inválidas' }, 401);
  if (user.active === 0) return sendJson(res, { error: 'Usuário desativado' }, 403);
  resetRateLimit(req);
  if (needsRehash) {
    await tRun('UPDATE users SET password_hash=? WHERE id=?', [await bcryptHash(password), user.id]);
  }
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
    [await bcryptHash(cleanCpf), cleanCpf, user.id]
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
    [await bcryptHash(new_password), ctx.user.user_id]
  );
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/auth/me', async (req, res, ctx) => {
  const { dbAll: tAll } = ctx.db;
  const permissions = await loadPermissionsAll(ctx.user.role, tAll);
  sendJson(res, { ...ctx.user, permissions });
});

// GET /api/tenant/my-modules — módulos efetivos do tenant logado (licença + overrides)
addRoute('GET', '/api/tenant/my-modules', async (req, res, ctx) => {
  try {
    const tenant = await saasGet(`SELECT id FROM saas.tenants WHERE slug=$1`, [ctx.tenantSlug]);
    if (!tenant) return sendJson(res, { has_license: false, slugs: [] });
    const hasLicense = !!(await saasGet(
      `SELECT 1 FROM saas.tenant_licenses WHERE tenant_id=$1 AND status='active'
       AND (ends_at IS NULL OR ends_at >= CURRENT_DATE) LIMIT 1`, [tenant.id]
    ));
    const mods = hasLicense ? await _resolveEffectiveModules(tenant.id) : [];
    sendJson(res, { has_license: hasLicense, slugs: mods.map(m => m.slug) });
  } catch (e) { sendJson(res, { has_license: false, slugs: [] }); }
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
  const allRoles = await getAllRoles(tAll);
  const roleKeys = allRoles.map(r => r.key);
  const out = {};
  for (const role of roleKeys) out[role] = await loadPermissionsAll(role, tAll);
  sendJson(res, { roles: allRoles, modules: MODULES, submodules: SUBMODULES, permissions: out });
});

addRoute('PUT', '/api/access/permissions', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { role, module, submodule = '', can_view, can_create, can_edit, can_delete } = ctx.body || {};
  if (!(await isValidRole(role, ctx.db.dbAll))) return sendJson(res, { error: 'Role inválido' }, 400);
  if (role === 'admin')              return sendJson(res, { error: 'Não é permitido alterar permissões do admin' }, 400);
  if (!MODULE_KEYS.includes(module)) return sendJson(res, { error: 'Módulo inválido' }, 400);
  if (submodule && !SUBMODULE_KEYS[`${module}.${submodule}`]) return sendJson(res, { error: 'Sub-módulo inválido' }, 400);
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const v = can_view?1:0, cr = can_create?1:0, e = can_edit?1:0, d = can_delete?1:0;
  const exists = await tGet('SELECT 1 FROM role_permissions WHERE role=? AND module=? AND submodule=?', [role, module, submodule]);
  if (exists) {
    await tRun('UPDATE role_permissions SET can_view=?,can_create=?,can_edit=?,can_delete=? WHERE role=? AND module=? AND submodule=?',
               [v, cr, e, d, role, module, submodule]);
  } else {
    await tRun('INSERT INTO role_permissions(role,module,submodule,can_view,can_create,can_edit,can_delete) VALUES(?,?,?,?,?,?,?)',
               [role, module, submodule, v, cr, e, d]);
  }
  const loc = submodule ? `${role}/${module}/${submodule}` : `${role}/${module}`;
  await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
             [ctx.user.user_id, ctx.user.name, 'update_permissions', `${loc}: v=${v} c=${cr} e=${e} d=${d}`]);
  sendJson(res, { ok: true });
});

addRoute('POST', '/api/access/permissions/reset', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const pool = getTenantPool(ctx.tenantSlug);
  await pool.unsafe(`DELETE FROM role_permissions WHERE role IN ('operador','loja','cliente','totem')`);
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
  if (!(await isValidRole(b.role, ctx.db.dbAll))) return sendJson(res, { error: 'Role inválido' }, 400);
  if (b.role === 'cliente' && !b.client_id)
    return sendJson(res, { error: 'Usuário do tipo cliente precisa de client_id' }, 400);
  const { dbRun: tRun } = ctx.db;
  try {
    const r = await tRun('INSERT INTO users(email,password_hash,name,role,client_id,active) VALUES(?,?,?,?,?,1)',
      [String(b.email).toLowerCase(), await bcryptHash(b.password), b.name, b.role, b.role==='cliente' ? b.client_id : null]);
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
  const role = b.role && (await isValidRole(b.role, ctx.db.dbAll)) ? b.role : u.role;
  const cid  = role === 'cliente' ? (b.client_id || u.client_id) : null;
  const act  = b.active === undefined ? u.active : (b.active ? 1 : 0);
  await tRun('UPDATE users SET name=?,email=?,role=?,client_id=?,active=? WHERE id=?',
             [b.name || u.name, (b.email || u.email).toLowerCase(), role, cid, act, id]);
  if (b.password) await tRun('UPDATE users SET password_hash=? WHERE id=?', [await bcryptHash(b.password), id]);
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
  let sql = `SELECT v.*, c.name as client_name, c.tier as client_tier, s.number as spot_number, s.type as spot_type, ct.id as contract_id
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

addRoute('POST', '/api/spots/resequence', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { type, prefix = '', start = 1, padding = 3, dry_run = true } = ctx.body;
  if (!['seca', 'molhada'].includes(type)) return sendJson(res, { error: 'Tipo inválido' }, 400);
  const { dbAll: tAll, dbRun: tRun } = ctx.db;
  const spots = await tAll('SELECT id, number FROM spots WHERE type=? ORDER BY id ASC', [type]);
  if (!spots.length) return sendJson(res, { error: 'Nenhuma vaga encontrada para este tipo' }, 404);
  const preview = spots.map((s, i) => ({
    id: s.id,
    old_number: s.number,
    new_number: prefix + String(parseInt(start) + i).padStart(parseInt(padding), '0')
  }));
  if (dry_run) return sendJson(res, { preview });
  for (const p of preview) await tRun('UPDATE spots SET number=? WHERE id=?', [p.new_number, p.id]);
  sendJson(res, { ok: true, updated: preview.length });
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
    v.name as vessel_name,
    s.number as spot_number,
    s.type   as spot_type
    FROM contracts ct JOIN clients c ON ct.client_id=c.id
    JOIN vessels v ON ct.vessel_id=v.id
    LEFT JOIN spots s ON s.id = ct.spot_id
    WHERE 1=1`;
  const a = [];
  const scope = clientScope(ctx.user);
  if (scope !== null) { sql += ' AND ct.client_id=?'; a.push(scope); }
  if (status) { sql += ' AND ct.status=?'; a.push(status); }
  sendJson(res, await tAll(sql + ' ORDER BY ct.start_date DESC', a));
});

addRoute('GET', '/api/contracts/:id', async (req, res, ctx) => {
  const { dbGet: tGet } = ctx.db;
  const ct = await tGet(`SELECT ct.*, c.name as client_name, c.tier as client_tier,
    v.name as vessel_name,
    s.number as spot_number,
    s.type   as spot_type
    FROM contracts ct JOIN clients c ON ct.client_id=c.id
    JOIN vessels v ON ct.vessel_id=v.id
    LEFT JOIN spots s ON s.id = ct.spot_id
    WHERE ct.id=?`, [ctx.params.id]);
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
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  await cleanupStaleQueueOps(tAll, tRun);
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
  const opsStart = settings['ops_start_time'] || '07:00';
  const opsEnd   = settings['ops_end_time']   || '18:00';
  // Última conclusão do dia — garante manobra após op concluída (mesmo sem in_progress ativo)
  const lastDone = doneEnriched.filter(d => d.status === 'completed' && d.completed_at)
    .reduce((max, d) => { const t = new Date(d.completed_at); return (!max || t > max) ? t : max; }, null);
  applyEstimatedTimes(activeEnriched, getManeuverTime(settings), opsStart, opsEnd, lastDone);
  const mtRow = await tGet(`SELECT MAX(COALESCE(completed_at, started_at, requested_at)) as mt FROM queue_operations WHERE DATE(requested_at)=? OR status NOT IN ('completed','cancelled')`, [today]);
  const mtime = mtRow?.mt || today;
  sendJson(res, { today, done: doneEnriched, active: activeEnriched, maneuver_time_min: getManeuverTime(settings), ops_start_time: opsStart, ops_end_time: opsEnd, mtime });
});

addRoute('GET', '/api/queue/calendar/mtime', async (req, res, ctx) => {
  const { dbGet: tGet } = ctx.db;
  const today = todayStr();
  const row = await tGet(`SELECT MAX(COALESCE(completed_at, started_at, requested_at)) as mt FROM queue_operations WHERE DATE(requested_at)=? OR status NOT IN ('completed','cancelled')`, [today]);
  sendJson(res, { mtime: row?.mt || today });
});

addRoute('GET', '/api/queue', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  if (!status) await cleanupStaleQueueOps(tAll, tRun); // só limpa quando carrega a fila ativa completa
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
  const opsStart = settings['ops_start_time'] || '07:00';
  const opsEnd   = settings['ops_end_time']   || '18:00';
  // Última conclusão do dia — garante manobra após op concluída (mesmo sem in_progress ativo)
  const lastDoneRow = !status ? await tGet(
    `SELECT MAX(completed_at) as lc FROM queue_operations WHERE status='completed' AND DATE(completed_at)=?`,
    [todayStr()]
  ) : null;
  const lastCompletedAt = lastDoneRow?.lc ? new Date(lastDoneRow.lc) : null;
  applyEstimatedTimes(enriched, getManeuverTime(settings), opsStart, opsEnd, lastCompletedAt);
  if (!status) await checkQueueAlerts(enriched, settings, tAll, tRun).catch(e => console.error('[alerts]', e.message));
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

  const settings    = await getSettings(tAll);
  const opsStart    = settings['ops_start_time'] || '07:00';
  const opsEnd      = settings['ops_end_time']   || '18:00';
  const maneuverMin = parseInt(settings['maneuver_time_min']) || 0;
  const hhmm2min    = s => { const [h, m] = (s||'00:00').split(':').map(Number); return h*60+m; };
  const fmtMin      = m => `${String(Math.floor(m/60)).padStart(2,'0')}:${String(m%60).padStart(2,'0')}`;
  const now         = new Date();
  const nowMin      = _brt(now).getUTCHours()*60 + _brt(now).getUTCMinutes();
  const startMin    = hhmm2min(opsStart);
  const endMin      = hhmm2min(opsEnd);

  // Rejeita imediatamente se agora já passou do horário de encerramento
  if (nowMin >= endMin)
    return sendJson(res, { error: `Fora do horário de operações. Encerramento: ${opsEnd}.` }, 400);

  // Cursor começa no maior entre: agora e horário de início das operações
  let cursorMin = Math.max(nowMin, startMin);

  // Percorre ops ativas para calcular quando o cursor estará livre
  const queuedActive = await tAll(`SELECT q.*, v.size as vessel_size FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id WHERE q.status NOT IN ('completed','cancelled') ORDER BY q.queue_order ASC, q.priority DESC, q.requested_at ASC`);
  let hasInProgress = false;
  for (const op of queuedActive) {
    const dur = getAvgDurationSync(settings, op.vessel_size, op.operation_type);
    if (op.status === 'in_progress' && op.started_at) {
      hasInProgress = true;
      // started_at vem como ISO Z string do compat.js — new Date() interpreta UTC corretamente
      const sa = op.started_at instanceof Date
        ? op.started_at
        : new Date(op.started_at);
      const estimatedEnd = new Date(sa.getTime() + dur * 60000);
      if (!isNaN(estimatedEnd) && estimatedEnd > now) {
        const opEndMin = _brt(estimatedEnd).getUTCHours()*60 + _brt(estimatedEnd).getUTCMinutes();
        if (opEndMin > cursorMin) cursorMin = opEndMin;
      }
    } else if (op.status === 'waiting') {
      cursorMin += dur;
    }
    cursorMin += maneuverMin; // tempo de manobra após cada op (e antes da próxima)
    if (cursorMin >= endMin) break;
  }

  // Se a fila estava vazia, acrescenta o tempo de manobra inicial
  // (trator precisa se posicionar antes da primeira operação)
  if (queuedActive.length === 0) {
    cursorMin += maneuverMin;
  }

  const newDur = getAvgDurationSync(settings, vessel.size, opType);
  // A nova op precisa caber inteiramente antes do encerramento
  if (cursorMin + newDur > endMin)
    return sendJson(res, { error: `Operação não cabe no horário: início previsto ${fmtMin(cursorMin)}, término ${fmtMin(cursorMin + newDur)}, encerramento ${opsEnd}.` }, 400);

  let warning = null;
  if (nowMin < startMin) warning = `Solicitação recebida antes do horário de início (${opsStart}). Início previsto às ${opsStart}.`;

  const client    = await tGet('SELECT * FROM clients WHERE id=?', [vessel.client_id]);
  const priority  = client && ['gold', 'vip'].includes(client.tier) ? 1 : 0;
  const maxOrder  = await tGet(`SELECT MAX(queue_order) as mo FROM queue_operations WHERE status NOT IN ('completed','cancelled')`);
  const queueOrder = (Number(maxOrder?.mo) || 0) + 1;
  const r = await tRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,priority,notes,queue_order,requested_at) VALUES(?,?,?,'waiting',?,?,?,?)`,
                       [ctx.body.vessel_id, vessel.client_id, opType, priority, ctx.body.notes || null, queueOrder, nowStr()]);
  sendJson(res, { id: r.lastInsertRowid, warning }, 201);
});

addRoute('PUT', '/api/queue/:id/reorder', async (req, res, ctx) => {
  const { direction, justification, public_justification } = ctx.body || {};
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
  // Log interno
  await tRun(`INSERT INTO system_logs(user_id,user_name,action,details) VALUES(?,?,?,?)`,
    [ctx.user.user_id||null, ctx.user.name||'Sistema', 'queue_reorder',
     JSON.stringify({ op_id: op.id, vessel: vessel?.name, direction, justification: justification.trim(), public_justification: public_justification?.trim()||null })]);
  // Aviso público: registra se o operador informou justificativa pública
  if (public_justification?.trim()) {
    // max_op_id = maior ID de op ativa no momento do reorder (o aviso expira quando essas ops terminarem)
    const maxOp = await tGet(`SELECT MAX(id) as mid FROM queue_operations WHERE status NOT IN ('completed','cancelled')`);
    const maxId = Number(maxOp?.mid) || 0;
    // Desativa avisos anteriores ainda ativos (substitui pelo mais recente)
    await tRun(`UPDATE queue_notices SET active=0 WHERE active=1`, []);
    await tRun(`INSERT INTO queue_notices(message, max_op_id, created_by, created_by_name) VALUES(?,?,?,?)`,
      [public_justification.trim(), maxId, ctx.user.user_id||null, ctx.user.name||'Sistema']);
  }
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/queue/notices', async (req, res, ctx) => {
  const { dbAll: tAll, dbRun: tRun } = ctx.db;
  // Auto-dismiss: aviso expira quando todas as ops registradas até o reorder forem concluídas
  const active = await tAll(`SELECT * FROM queue_notices WHERE active=1 ORDER BY created_at DESC`);
  for (const n of active) {
    const pending = await tAll(
      `SELECT id FROM queue_operations WHERE id <= ? AND status NOT IN ('completed','cancelled')`,
      [n.max_op_id]
    );
    if (pending.length === 0) {
      await tRun(`UPDATE queue_notices SET active=0 WHERE id=?`, [n.id]);
      n.active = 0;
    }
  }
  let notices = await tAll(`SELECT * FROM queue_notices WHERE active=1 ORDER BY created_at ASC`);
  // Para role cliente: só exibir aviso se o cliente tinha operação na fila no momento da alteração.
  // Clientes que entraram após a alteração (op_id > max_op_id) já usam o novo escalonamento e não precisam ver o banner.
  if (ctx.user && ctx.user.role === 'cliente' && ctx.user.client_id) {
    const filtered = [];
    for (const n of notices) {
      const clientOp = await tAll(
        `SELECT id FROM queue_operations WHERE client_id=? AND id<=?`,
        [ctx.user.client_id, n.max_op_id]
      );
      if (clientOp.length > 0) filtered.push(n);
    }
    notices = filtered;
  }
  sendJson(res, notices);
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
  // Auto-dismiss alertas ao mudar status
  if (ns === 'in_progress') {
    await tRun(`UPDATE queue_alerts SET dismissed_at=NOW() WHERE operation_id=? AND alert_type='warning' AND dismissed_at IS NULL`, [ctx.params.id]);
  } else if (['completed','cancelled'].includes(ns)) {
    await tRun(`UPDATE queue_alerts SET dismissed_at=NOW() WHERE operation_id=? AND dismissed_at IS NULL`, [ctx.params.id]);
  }
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/queue/:id', async (req, res, ctx) => {
  await ctx.db.dbRun(`UPDATE queue_operations SET status='cancelled' WHERE id=?`, [ctx.params.id]);
  await ctx.db.dbRun(`UPDATE queue_alerts SET dismissed_at=NOW() WHERE operation_id=? AND dismissed_at IS NULL`, [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── Alertas de fila ──────────────────────────────────────────────────

addRoute('GET', '/api/queue/alerts', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;
  const role = ctx.user.role;
  // Busca tipos de alerta habilitados para o papel do usuário
  const cfg = await tAll(`SELECT alert_type FROM alert_role_config WHERE role=? AND enabled=TRUE`, [role]);
  if (!cfg.length) return sendJson(res, []);
  const types = cfg.map(r => r.alert_type);
  const placeholders = types.map(() => '?').join(',');
  const alerts = await tAll(
    `SELECT * FROM queue_alerts WHERE dismissed_at IS NULL AND alert_type IN (${placeholders}) ORDER BY created_at DESC`,
    types
  );
  sendJson(res, alerts);
});

addRoute('GET', '/api/queue/alerts/mtime', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbGet: tGet } = ctx.db;
  const role = ctx.user.role;
  const cfg = await ctx.db.dbAll(`SELECT alert_type FROM alert_role_config WHERE role=? AND enabled=TRUE`, [role]);
  if (!cfg.length) return sendJson(res, { mtime: null, count: 0 });
  const types = cfg.map(r => r.alert_type);
  const placeholders = types.map(() => '?').join(',');
  const row = await tGet(
    `SELECT MAX(created_at) as mt, COUNT(*) as cnt FROM queue_alerts WHERE dismissed_at IS NULL AND alert_type IN (${placeholders})`,
    types
  );
  sendJson(res, { mtime: row?.mt || null, count: Number(row?.cnt || 0) });
});

addRoute('PATCH', '/api/queue/alerts/:id/dismiss', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  await ctx.db.dbRun(`UPDATE queue_alerts SET dismissed_at=NOW(), dismissed_by=? WHERE id=?`,
    [ctx.user.id, ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/settings/alert-config', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;
  // Roles dinâmicas do banco (exclui totem — kiosk sem dashboard)
  const allRoles   = await getAllRoles(tAll);
  const alertRoles = allRoles.filter(r => r.key !== 'totem').map(r => r.key);
  const rows       = await tAll(`SELECT alert_type, role, enabled FROM alert_role_config`);
  const cfgMap     = {};
  rows.forEach(r => { cfgMap[`${r.alert_type}|${r.role}`] = r.enabled; });
  const fullRows = [];
  for (const t of ALERT_TYPE_DEFS) {
    for (const role of alertRoles) {
      const key = `${t.key}|${role}`;
      fullRows.push({ alert_type: t.key, role, enabled: cfgMap[key] !== undefined ? cfgMap[key] : false });
    }
  }
  sendJson(res, { roles: alertRoles, types: ALERT_TYPE_DEFS, rows: fullRows });
});

addRoute('PUT', '/api/settings/alert-config', async (req, res, ctx) => {
  if (!ctx.user || ctx.user.role !== 'admin') return sendJson(res, { error: 'Acesso negado' }, 403);
  const { dbRun: tRun } = ctx.db;
  for (const item of (ctx.body || [])) {
    await tRun(
      `INSERT INTO alert_role_config(alert_type, role, enabled) VALUES(?,?,?)
       ON CONFLICT(alert_type, role) DO UPDATE SET enabled=EXCLUDED.enabled`,
      [item.alert_type, item.role, item.enabled ? true : false]
    );
  }
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

addRoute('GET', '/api/store/items/:id', async (req, res, ctx) => {
  const item = await ctx.db.dbGet('SELECT * FROM store_items WHERE id=? AND active=1', [ctx.params.id]);
  if (!item) return sendJson(res, 404, { error: 'Item não encontrado' });
  sendJson(res, item);
});

addRoute('POST', '/api/store/items', async (req, res, ctx) => {
  const b = ctx.body;
  const r = await ctx.db.dbRun(
    'INSERT INTO store_items(name,category,price,cost,stock,min_stock,unit,photo_url) VALUES(?,?,?,?,?,?,?,?)',
    [b.name, b.category||'outros', b.price, b.cost||0, b.stock||0, b.min_stock||5, b.unit||'un', b.photo_url||null]
  );
  sendJson(res, { id: r.lastInsertRowid }, 201);
});

addRoute('PUT', '/api/store/items/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  await tRun(
    'UPDATE store_items SET name=?,category=?,price=?,cost=?,stock=?,min_stock=?,unit=?,photo_url=? WHERE id=?',
    [b.name, b.category, b.price, b.cost||0, b.stock||0, b.min_stock||5, b.unit||'un',
     b.photo_url||null, ctx.params.id]
  );
  await checkStock(tAll, tAll, tGet, tRun);
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/store/items/:id', async (req, res, ctx) => {
  await ctx.db.dbRun('UPDATE store_items SET active=0 WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/store/suggest-photo', async (req, res, ctx) => {
  const q = (ctx.qs.q || '').trim();
  if (!q) return sendJson(res, 400, { error: 'Parâmetro q obrigatório' });
  try {
    const url = `https://world.openfoodfacts.org/cgi/search.pl?search_terms=${encodeURIComponent(q)}&json=1&action=process&fields=product_name,image_small_url&page_size=12&lc=pt`;
    const r = await fetch(url, { headers: { 'User-Agent': 'MarinaOne/2.0 (rj.madmax@gmail.com)' }, signal: AbortSignal.timeout(8000) });
    const data = await r.json();
    const suggestions = (data.products || [])
      .filter(p => p.image_small_url)
      .slice(0, 6)
      .map(p => ({ url: p.image_small_url, title: p.product_name || q }));
    sendJson(res, { suggestions });
  } catch (e) {
    sendJson(res, 502, { error: 'Erro ao buscar sugestões: ' + e.message });
  }
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
  const isFiado  = b.payment_method === 'fiado';
  const isFicha  = b.payment_method === 'ficha';
  // fiado e ficha → paid+preparando direto (dívida rastreada pela aba/paid_date)
  const isOnAccount        = isFiado || isFicha;
  const forcedStatus       = isOnAccount ? 'paid' : (b.status || 'open');
  const forcedDelivery     = isOnAccount ? 'preparando' : (b.delivery_status || null);
  const forcedPaidDate     = isOnAccount ? null : (forcedStatus === 'paid' ? todayStr() : null);
  const r = await tRun('INSERT INTO store_orders(vessel_id,client_id,items,subtotal,discount,total,status,payment_method,notes,tab_id,delivery_status,paid_date) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       [b.vessel_id||null, b.client_id||null, JSON.stringify(items), subtotal, discount, total,
                        forcedStatus, b.payment_method||null, b.notes||null, b.tab_id||null,
                        forcedDelivery, forcedPaidDate]);
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

// ── Contas abertas (fiado) ────────────────────────────────────────────
addRoute('GET', '/api/store/tabs', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;
  const tabs = await tAll(`
    SELECT t.id, t.client_id, t.status, t.opened_at, t.notes,
           c.name as client_name, c.phone as client_phone, c.tier as client_tier,
           COALESCE(SUM(o.total),0) as total,
           COUNT(o.id) as order_count
    FROM client_tabs t
    JOIN clients c ON c.id = t.client_id
    LEFT JOIN store_orders o ON o.tab_id = t.id AND o.paid_date IS NULL
    WHERE t.status = 'open'
    GROUP BY t.id, t.client_id, t.status, t.opened_at, t.notes, c.name, c.phone, c.tier
    ORDER BY t.opened_at DESC`);
  sendJson(res, tabs);
});

addRoute('POST', '/api/store/tabs', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const { client_id, notes } = ctx.body;
  if (!client_id) return sendJson(res, { error: 'client_id obrigatório' }, 400);
  const existing = await tGet(`SELECT id FROM client_tabs WHERE client_id=? AND status='open'`, [client_id]);
  if (existing) return sendJson(res, { error: 'Cliente já possui conta aberta', tab_id: existing.id }, 409);
  const r = await tRun(`INSERT INTO client_tabs(client_id, notes) VALUES(?,?)`, [client_id, notes||'']);
  sendJson(res, { id: r.lastInsertRowid }, 201);
});

addRoute('GET', '/api/store/tabs/check/:client_id', async (req, res, ctx) => {
  const { dbGet: tGet } = ctx.db;
  const tab = await tGet(`SELECT id, opened_at FROM client_tabs WHERE client_id=? AND status='open'`, [ctx.params.client_id]);
  sendJson(res, tab || null);
});

addRoute('PUT', '/api/store/tabs/:id/close', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbRun: tRun, dbAll: tAll } = ctx.db;
  const { payment_method } = ctx.body;
  if (!payment_method) return sendJson(res, { error: 'payment_method obrigatório' }, 400);
  await tRun(`UPDATE store_orders SET paid_date=CURRENT_DATE, payment_method=COALESCE(?,payment_method)
              WHERE tab_id=? AND paid_date IS NULL`, [payment_method, ctx.params.id]);
  await tRun(`UPDATE client_tabs SET status='closed', closed_at=NOW() WHERE id=?`, [ctx.params.id]);
  sendJson(res, { ok: true });
});

addRoute('GET', '/api/store/tabs/:id/orders', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;
  const orders = await tAll(`SELECT o.*, v.name as vessel_name FROM store_orders o
    LEFT JOIN vessels v ON o.vessel_id=v.id
    WHERE o.tab_id=? AND o.paid_date IS NULL ORDER BY o.created_at ASC`, [ctx.params.id]);
  for (const r of orders) { try { r.items = JSON.parse(r.items); } catch {} }
  sendJson(res, orders);
});

addRoute('GET', '/api/store/client-accounts', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;

  // Pendentes avulsos (PIX WhatsApp, etc.) — status=pending_payment, excluindo fiado (já tem aba)
  const rows = await tAll(`SELECT o.*, c.name as client_name, c.phone as client_phone, c.tier as client_tier, v.name as vessel_name
    FROM store_orders o LEFT JOIN clients c ON o.client_id=c.id LEFT JOIN vessels v ON o.vessel_id=v.id
    WHERE o.status='pending_payment' AND (o.payment_method IS NULL OR o.payment_method NOT IN ('fiado'))
    ORDER BY o.created_at ASC`);
  for (const r of rows) { try { r.items = JSON.parse(r.items); } catch {} }
  const map = {};
  for (const o of rows) {
    const key = o.client_id || 0;
    if (!map[key]) map[key] = { client_id: o.client_id, client_name: o.client_name||'Balcão', client_phone: o.client_phone, client_tier: o.client_tier, orders: [], total: 0 };
    map[key].orders.push(o);
    map[key].total += Number(o.total);
  }
  const accounts = Object.values(map).sort((a, b) => b.total - a.total);

  // Contas ficha — pedidos paid, payment_method='ficha', paid_date=null (dívida ainda não quitada)
  const fichaRows = await tAll(`SELECT o.*, c.name as client_name, c.phone as client_phone, c.tier as client_tier, v.name as vessel_name
    FROM store_orders o LEFT JOIN clients c ON o.client_id=c.id LEFT JOIN vessels v ON o.vessel_id=v.id
    WHERE o.payment_method='ficha' AND o.paid_date IS NULL AND o.status='paid'
    ORDER BY o.created_at ASC`);
  for (const r of fichaRows) { try { r.items = JSON.parse(r.items); } catch {} }
  const fichaMap = {};
  for (const o of fichaRows) {
    const key = o.client_id || 0;
    if (!fichaMap[key]) fichaMap[key] = { client_id: o.client_id, client_name: o.client_name||'Balcão', client_phone: o.client_phone, client_tier: o.client_tier, orders: [], total: 0 };
    fichaMap[key].orders.push(o);
    fichaMap[key].total += Number(o.total);
  }
  const ficha_accounts = Object.values(fichaMap).sort((a, b) => b.total - a.total);

  const grand_total = accounts.reduce((s, a) => s + a.total, 0)
                    + ficha_accounts.reduce((s, a) => s + a.total, 0);
  sendJson(res, { accounts, ficha_accounts, grand_total });
});

addRoute('PUT', '/api/store/ficha-accounts/:client_id/settle', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { payment_method } = ctx.body || {};
  await ctx.db.dbRun(
    `UPDATE store_orders SET paid_date=CURRENT_DATE, payment_method=COALESCE(?,payment_method)
     WHERE client_id=? AND payment_method='ficha' AND paid_date IS NULL AND status='paid'`,
    [payment_method || null, ctx.params.client_id]
  );
  sendJson(res, { ok: true });
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
//  ROTAS — CONVENIÊNCIA (auto-atendimento / totem)
// ═════════════════════════════════════════════════════════════════════
// Marca da marina — pública, sem auth (usada na tela de login antes de autenticar)
addRoute('GET', '/api/brand', async (req, res, ctx) => {
  const { dbGet: tGet } = ctx.db;
  const name = (await tGet(`SELECT value FROM settings WHERE key='marina_name'`))?.value || 'Marina One';
  const logo = (await tGet(`SELECT value FROM settings WHERE key='marina_logo'`))?.value || '';
  sendJson(res, { name, logo });
});

addRoute('GET', '/api/conveniencia/catalog', async (req, res, ctx) => {
  const items = await ctx.db.dbAll(
    'SELECT id, name, category, price, stock, unit, photo_url FROM store_items WHERE active=1 ORDER BY category, name'
  );
  const catMap = {};
  for (const item of items) {
    const cat = item.category || 'outros';
    if (!catMap[cat]) catMap[cat] = [];
    catMap[cat].push({ ...item, price: Number(item.price), stock: Number(item.stock) });
  }
  const categories = Object.entries(catMap).map(([name, items]) => ({ name, items }));
  sendJson(res, { categories });
});

addRoute('POST', '/api/conveniencia/order', async (req, res, ctx) => {
  const b = ctx.body;
  const { dbAll: tAll, dbGet: tGet, dbRun: tRun } = ctx.db;
  const items = b.items || [];
  if (!items.length) return sendJson(res, { error: 'Nenhum item no pedido' }, 400);
  const customerName = (b.customer_name || '').trim();
  if (!customerName && !b.client_id) return sendJson(res, { error: 'Informe o nome do cliente' }, 400);
  const subtotal = items.reduce((s, i) => s + Number(i.price) * Number(i.qty), 0);
  const source = b.source === 'totem' ? 'totem' : 'self_service';
  const r = await tRun(
    'INSERT INTO store_orders(vessel_id,client_id,customer_name,items,subtotal,discount,total,status,payment_method,notes,source,delivery_status) VALUES(?,?,?,?,?,0,?,?,?,?,?,?)',
    [b.vessel_id||null, b.client_id||null, customerName||null, JSON.stringify(items),
     subtotal, subtotal, 'open', null, b.notes||null, source, null]
  );
  for (const item of items) {
    await tRun('UPDATE store_items SET stock=GREATEST(0,stock-?) WHERE id=?', [item.qty, item.item_id]);
  }
  await checkStock(tAll, tAll, tGet, tRun);
  sendJson(res, { id: r.lastInsertRowid, order_number: r.lastInsertRowid }, 201);
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
  const r = await tRun('INSERT INTO maintenance_os(vessel_id,os_number,type,description,status,priority,scheduled_date,estimated_hours,cost,technician,technician_level,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       [b.vessel_id||null, os_num, b.type, b.description, b.status||'open', b.priority||'normal', b.scheduled_date||null, b.estimated_hours||null, b.cost||0, b.technician||null, b.technician_level||null, b.notes||null]);
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
  await tRun('UPDATE maintenance_os SET vessel_id=?,type=?,description=?,status=?,priority=?,scheduled_date=?,completed_date=?,actual_hours=?,cost=?,technician=?,technician_level=?,notes=? WHERE id=?',
             [b.vessel_id!==undefined ? (b.vessel_id||null) : old.vessel_id,
              b.type||old.type, b.description||old.description, ns,
              b.priority||old.priority, b.scheduled_date||old.scheduled_date||null, completed_date,
              b.actual_hours||old.actual_hours||null, b.cost!==undefined ? b.cost : old.cost,
              b.technician||old.technician||null, b.technician_level||old.technician_level||null,
              b.notes!==undefined ? b.notes : old.notes, ctx.params.id]);
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
  const year = new Date().getFullYear();
  const rows = await ctx.db.dbAll(
    `SELECT TO_CHAR(paid_date,'YYYY-MM') as month, COALESCE(SUM(amount),0) as total
     FROM financial_charges
     WHERE status='paid' AND paid_date IS NOT NULL
       AND EXTRACT(YEAR FROM paid_date) = $1
     GROUP BY TO_CHAR(paid_date,'YYYY-MM')`,
    [year]
  );
  // Garante os 12 meses do ano corrente, com zero nos meses sem receita
  const dataMap = {};
  rows.forEach(r => { dataMap[r.month] = Number(r.total); });
  const result = Array.from({ length: 12 }, (_, i) => {
    const m = String(i + 1).padStart(2, '0');
    const key = `${year}-${m}`;
    return { month: key, total: dataMap[key] || 0 };
  });
  sendJson(res, result);
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
//  ROTAS — GESTÃO DE ROLES
// ═════════════════════════════════════════════════════════════════════

addRoute('GET', '/api/roles', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  const { dbAll: tAll } = ctx.db;
  const roles = await getAllRoles(tAll);
  // Enriquece com contagem de usuários por role
  const counts = await tAll(`SELECT role, COUNT(*) as cnt FROM users WHERE active=1 GROUP BY role`);
  const countMap = {};
  counts.forEach(c => { countMap[c.role] = Number(c.cnt); });
  sendJson(res, roles.map(r => ({ ...r, user_count: countMap[r.key] || 0 })));
});

addRoute('POST', '/api/roles', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const b = ctx.body || {};
  if (!b.key || !b.label) return sendJson(res, { error: 'key e label são obrigatórios' }, 400);
  // key deve ser slug válido
  const key = String(b.key).toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 32);
  if (!key) return sendJson(res, { error: 'key inválido' }, 400);
  const { dbRun: tRun, dbAll: tAll } = ctx.db;
  if (await isValidRole(key, tAll)) return sendJson(res, { error: 'Role já existe' }, 409);
  await tRun(
    `INSERT INTO roles(key, label, description, color, icon, is_system) VALUES(?,?,?,?,?,FALSE)`,
    [key, b.label, b.description || null, b.color || '#6b7280', b.icon || '👤']
  );
  // Seed de alert_role_config para a nova role (padrão tudo desabilitado)
  for (const t of ALERT_TYPE_DEFS) {
    await tRun(
      `INSERT OR IGNORE INTO alert_role_config(alert_type, role, enabled) VALUES(?,?,FALSE)`,
      [t.key, key]
    );
  }
  // Seed de role_permissions vazia para que apareça na tela de permissões
  for (const mod of MODULE_KEYS) {
    await tRun(
      `INSERT OR IGNORE INTO role_permissions(role, module, submodule, can_view, can_create, can_edit, can_delete) VALUES(?,?,'',0,0,0,0)`,
      [key, mod]
    );
  }
  sendJson(res, { ok: true, key });
});

addRoute('PUT', '/api/roles/:key', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const b = ctx.body || {};
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const role = await tGet(`SELECT * FROM roles WHERE key=?`, [ctx.params.key]);
  if (!role) return sendJson(res, { error: 'Role não encontrada' }, 404);
  await tRun(
    `UPDATE roles SET label=?, description=?, color=?, icon=? WHERE key=?`,
    [b.label || role.label, b.description !== undefined ? b.description : role.description,
     b.color || role.color, b.icon || role.icon, ctx.params.key]
  );
  sendJson(res, { ok: true });
});

addRoute('DELETE', '/api/roles/:key', async (req, res, ctx) => {
  if (!requireRole(ctx, res, 'admin')) return;
  const { dbGet: tGet, dbRun: tRun } = ctx.db;
  const role = await tGet(`SELECT * FROM roles WHERE key=?`, [ctx.params.key]);
  if (!role) return sendJson(res, { error: 'Role não encontrada' }, 404);
  if (role.is_system) return sendJson(res, { error: 'Roles de sistema não podem ser excluídas' }, 400);
  const users = await tGet(`SELECT COUNT(*) as n FROM users WHERE role=? AND active=1`, [ctx.params.key]);
  if (Number(users?.n) > 0) return sendJson(res, { error: `Existem ${users.n} usuário(s) com esta role. Reatribua-os antes de excluir.` }, 400);
  await tRun(`UPDATE roles SET active=FALSE WHERE key=?`, [ctx.params.key]);
  sendJson(res, { ok: true });
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
  const { limit: lim = '500', action = '', search = '' } = ctx.qs;
  const { dbAll: tAll } = ctx.db;
  let sql = 'SELECT * FROM system_logs WHERE 1=1';
  const a = [];
  if (action) { sql += ' AND action=$' + (a.length+1); a.push(action); }
  if (search) {
    sql += ` AND (user_name ILIKE $${a.length+1} OR details ILIKE $${a.length+2})`;
    a.push(`%${search}%`, `%${search}%`);
  }
  sql += ` ORDER BY created_at DESC LIMIT ${Math.min(parseInt(lim)||500, 1000)}`;
  sendJson(res, await tAll(sql, a));
});

// ═════════════════════════════════════════════════════════════════════
//  ROTAS — CO-PILOTO IA
// ═════════════════════════════════════════════════════════════════════

// POST /api/ai/query — envia pergunta ao Co-piloto IA
addRoute('POST', '/api/ai/query', async (req, res, ctx) => {
  console.log('[AI/query] início — user:', ctx.user?.id, 'tenant:', ctx.tenantSlug);
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  if (!ctx.db)   return sendJson(res, { error: 'Tenant não identificado' }, 400);

  // 1. Gate de módulo licenciado (SaaS)
  let modulePassed = false;
  await requireModule('ai_copilot')(req, res, ctx, () => { modulePassed = true; });
  console.log('[AI/query] module gate:', modulePassed ? 'OK' : 'BLOQUEADO');
  if (!modulePassed) return;

  // 2. Permissão RBAC do tenant (copilot · create)
  const permOk = await requirePerm(ctx, res, 'copilot', 'create');
  console.log('[AI/query] perm gate:', permOk ? 'OK' : 'BLOQUEADO');
  if (!permOk) return;

  const question = (ctx.body.question || '').trim();
  if (!question) return sendJson(res, { error: 'Pergunta não pode ser vazia.' }, 400);
  if (question.length > 2000) return sendJson(res, { error: 'Pergunta muito longa (máximo 2000 caracteres).' }, 400);

  const t0 = Date.now();
  let logStatus = 'ok', logError = null, result = null;

  try {
    // Lê chave de API das configurações do próprio tenant (tabela settings do schema do tenant)
    const keyRow = await ctx.db.dbGet(`SELECT value FROM settings WHERE key='claude_api_key'`, []);
    const apiKey = (keyRow?.value || '').trim();
    console.log('[AI/query] apiKey configurada:', apiKey ? 'SIM (' + apiKey.slice(0,8) + '...)' : 'NÃO (vazia)');

    // Schema do tenant: marina_<slug>
    const schema = `marina_${ctx.tenantSlug}`;

    const { runAiQuery } = require('./src/ai/claude');
    console.log('[AI/query] chamando runAiQuery...');
    result = await runAiQuery({ question, dbAll: ctx.db.dbAll, apiKey, schema });
    console.log('[AI/query] runAiQuery OK — tokens:', result._tokens);
  } catch (e) {
    console.error('[AI/query] erro:', e.message);
    logStatus = 'error';
    logError  = e.message;
    result    = { answer: e.message, components: [] };
  }

  const duration = Date.now() - t0;

  // Persiste no log do tenant (não bloqueia resposta)
  ctx.db.dbRun(
    `INSERT INTO ai_usage_log(user_id, user_name, question, answer, components, tokens_in, tokens_out, duration_ms, status, error_msg)
     VALUES(?,?,?,?,?,?,?,?,?,?)`,
    [
      ctx.user.id,
      ctx.user.name || ctx.user.username || '',
      question,
      result.answer || '',
      JSON.stringify(result.components || []),
      result._tokens?.in  || 0,
      result._tokens?.out || 0,
      duration,
      logStatus,
      logError,
    ]
  ).catch(() => {}); // falha silenciosa no log

  // Remove metadados internos antes de enviar ao frontend
  const { _tokens, ...clean } = result;
  sendJson(res, { ok: true, duration_ms: duration, ...clean });
});

// GET /api/ai/history — histórico das últimas N perguntas do usuário
addRoute('GET', '/api/ai/history', async (req, res, ctx) => {
  if (!ctx.user) return sendJson(res, { error: 'Não autorizado' }, 401);
  if (!ctx.db)   return sendJson(res, { error: 'Tenant não identificado' }, 400);

  // 1. Gate de módulo licenciado (SaaS)
  let modulePassed = false;
  await requireModule('ai_copilot')(req, res, ctx, () => { modulePassed = true; });
  if (!modulePassed) {
    console.log('[AI/history] MODULE_NOT_LICENSED para tenant:', ctx.tenantSlug);
    return;
  }

  // 2. Permissão RBAC do tenant (copilot · view)
  if (!(await requirePerm(ctx, res, 'copilot', 'view'))) return;

  try {
    const limit = Math.min(parseInt(ctx.qs.limit || '20', 10), 50);
    const rows  = await ctx.db.dbAll(
      `SELECT id, user_name, question, answer, components, tokens_in, tokens_out, duration_ms, status, error_msg, created_at
       FROM ai_usage_log
       WHERE user_id=?
       ORDER BY created_at DESC
       LIMIT ?`,
      [ctx.user.id, limit]
    );
    sendJson(res, rows.map(r => ({
      ...r,
      components: typeof r.components === 'string' ? JSON.parse(r.components || '[]') : (r.components || []),
    })));
  } catch (e) {
    sendJson(res, { error: e.message }, 500);
  }
});

// ═════════════════════════════════════════════════════════════════════
//  SERVIDOR HTTP
// ═════════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const urlpath = (req.url || '/').split('?')[0];
  if (urlpath.startsWith('/api/') && req.method !== 'OPTIONS') {
    console.log('[HTTP]', req.method, urlpath);
  }
  setCors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

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

  // 3. Roda migrações pendentes em TODOS os tenants existentes (produção multi-tenant)
  try {
    const { getGlobalPool } = require('./src/db/pool');
    const tenants = await getGlobalPool().unsafe(`SELECT slug FROM saas.tenants`);
    for (const { slug } of tenants) {
      try {
        await runMigrations(slug);
        await seedDefaultPermissions(getTenantPool(slug));
      } catch (e) {
        console.error(`[boot] Erro ao migrar tenant ${slug}:`, e.message);
      }
    }
    if (tenants.length > 0) console.log(`[boot] Migrations e permissões verificadas em ${tenants.length} tenant(s).`);
  } catch (e) {
    console.error('[boot] Erro ao listar tenants para migração:', e.message);
  }

  // Verificação de integridade: todos os arquivos de migration devem estar em _migrations
  try {
    const migDir  = require('path').join(__dirname, 'src/db/migrations');
    const migFiles = require('fs').readdirSync(migDir).filter(f => f.endsWith('.sql')).sort();
    const { getGlobalPool } = require('./src/db/pool');
    const allTenants = await getGlobalPool().unsafe(`SELECT slug FROM saas.tenants`);
    for (const { slug } of allTenants) {
      try {
        const pool = require('./src/db/pool').getTenantPool(slug);
        const registered = await pool.unsafe(`SELECT filename FROM _migrations`);
        const regSet = new Set(registered.map(r => r.filename));
        const missing = migFiles.filter(f => !regSet.has(f));
        if (missing.length > 0) {
          console.error(`[boot] ⚠️  CRÍTICO — tenant "${slug}" tem ${missing.length} migration(s) não aplicada(s): ${missing.join(', ')}`);
        }
      } catch (e) {
        console.error(`[boot] ⚠️  Não foi possível verificar migrations do tenant "${slug}": ${e.message}`);
      }
    }
  } catch (e) {
    console.error('[boot] Erro na verificação de integridade de migrations:', e.message);
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
