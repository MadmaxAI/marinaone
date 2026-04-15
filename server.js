'use strict';
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'marinaone_secret_2024';
const DB_PATH = process.env.VERCEL ? '/tmp/marina.db' : path.join(__dirname, 'marina.db');
let db;

// ── JWT ──────────────────────────────────────────────────────────────
function jwtSign(payload, secs = 43200) {
  const hdr  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + secs })).toString('base64url');
  const sig  = crypto.createHmac('sha256', SECRET).update(`${hdr}.${body}`).digest('base64url');
  return `${hdr}.${body}.${sig}`;
}
function jwtVerify(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('invalid');
  const [hdr, body, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${hdr}.${body}`).digest('base64url');
  if (sig !== expected) throw new Error('bad sig');
  const p = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (p.exp && Date.now() / 1000 > p.exp) throw new Error('expired');
  return p;
}

// ── DB helpers ───────────────────────────────────────────────────────
const dbAll  = (sql, a = []) => db.prepare(sql).all(...a);
const dbGet  = (sql, a = []) => db.prepare(sql).get(...a);
const dbRun  = (sql, a = []) => db.prepare(sql).run(...a);
const nowStr = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const todayStr = () => new Date().toISOString().slice(0, 10);
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
function monthStart() { const d = new Date(); d.setDate(1); return d.toISOString().slice(0, 10); }
function daysAgo(n)   { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); }
function daysAhead(n) { const d = new Date(); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); }

// ── HTTP helpers ─────────────────────────────────────────────────────
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
}
function sendJson(res, data, status = 200) {
  setCors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
function parseBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve({}); } });
  });
}
function getQS(url) {
  const o = {};
  new URLSearchParams((url.split('?')[1] || '')).forEach((v, k) => { o[k] = v; });
  return o;
}
function getAuth(req) {
  try { return jwtVerify((req.headers.authorization || '').replace('Bearer ', '')); }
  catch { return null; }
}

// ── Side effects ─────────────────────────────────────────────────────
function addAlert(type, message, severity, entity_type, entity_id) {
  dbRun('INSERT INTO alerts(type,message,severity,entity_type,entity_id) VALUES(?,?,?,?,?)',
        [type, message, severity || 'info', entity_type || null, entity_id || null]);
}
function checkOverdue() {
  dbRun(`UPDATE financial_charges SET status='overdue' WHERE status='pending' AND due_date<?`, [todayStr()]);
}
function recalcLtv(client_id) {
  const r = dbGet(`SELECT COALESCE(SUM(amount),0) as t FROM financial_charges WHERE client_id=? AND status='paid'`, [client_id]);
  dbRun('UPDATE clients SET ltv=? WHERE id=?', [r ? r.t : 0, client_id]);
}
function checkStock() {
  const low = dbAll('SELECT * FROM store_items WHERE active=1 AND stock<=min_stock');
  for (const item of low) {
    const ex = dbAll(`SELECT id FROM alerts WHERE entity_type='store_item' AND entity_id=? AND read_at IS NULL`, [item.id]);
    if (!ex.length) addAlert('estoque', `Estoque baixo: ${item.name} (${item.stock} ${item.unit})`, 'warning', 'store_item', item.id);
  }
}

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
  const tlv = (t, v) => `${t}${String(v.length).padStart(2, '0')}${v}`;
  const ma = tlv('00', 'BR.GOV.BCB.PIX') + tlv('01', key);
  let p = tlv('00','01') + tlv('26',ma) + tlv('52','0000') + tlv('53','986') +
          tlv('54', amount.toFixed(2)) + tlv('58','BR') +
          tlv('59', name.slice(0,25)) + tlv('60', city.slice(0,15)) +
          tlv('62', tlv('05', txid.slice(0,25)));
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

// ── AUTH ─────────────────────────────────────────────────────────────
addRoute('POST', '/api/auth/login', async (req, res, ctx) => {
  const { email = '', password = '' } = ctx.body;
  const user = dbGet('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
  if (!user || user.password_hash !== sha256(password))
    return sendJson(res, { error: 'Credenciais inválidas' }, 401);
  const token = jwtSign({ user_id: user.id, email: user.email, name: user.name, role: user.role });
  sendJson(res, { token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});
addRoute('GET', '/api/auth/me', async (req, res, ctx) => sendJson(res, ctx.user));

// ── CLIENTS ──────────────────────────────────────────────────────────
addRoute('GET', '/api/clients', async (req, res, ctx) => {
  const { search = '', tier = '' } = ctx.qs;
  let sql = 'SELECT c.*, (SELECT COUNT(*) FROM vessels WHERE client_id=c.id AND active=1) as vessel_count FROM clients c WHERE c.active=1';
  const a = [];
  if (search) { sql += ' AND (c.name LIKE ? OR c.email LIKE ? OR c.cpf LIKE ?)'; a.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (tier)   { sql += ' AND c.tier=?'; a.push(tier); }
  sendJson(res, dbAll(sql + ' ORDER BY c.name', a));
});
addRoute('GET', '/api/clients/:id', async (req, res, ctx) => {
  const c = dbGet('SELECT * FROM clients WHERE id=?', [ctx.params.id]);
  if (!c) return sendJson(res, { error: 'Não encontrado' }, 404);
  c.vessels   = dbAll('SELECT * FROM vessels WHERE client_id=? AND active=1', [ctx.params.id]);
  c.contracts = dbAll('SELECT ct.*, s.number as spot_number FROM contracts ct LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.client_id=?', [ctx.params.id]);
  c.charges   = dbAll('SELECT * FROM financial_charges WHERE client_id=? ORDER BY due_date DESC LIMIT 10', [ctx.params.id]);
  sendJson(res, c);
});
addRoute('POST', '/api/clients', async (req, res, ctx) => {
  const b = ctx.body;
  const r = dbRun('INSERT INTO clients(name,email,phone,cpf,tier,address,notes) VALUES(?,?,?,?,?,?,?)',
                  [b.name, b.email, b.phone, b.cpf, b.tier || 'standard', b.address, b.notes]);
  addAlert('sistema', `Novo cliente: ${b.name}`, 'info');
  sendJson(res, { id: Number(r.lastInsertRowid) }, 201);
});
addRoute('PUT', '/api/clients/:id', async (req, res, ctx) => {
  const b = ctx.body;
  dbRun('UPDATE clients SET name=?,email=?,phone=?,cpf=?,tier=?,address=?,notes=? WHERE id=?',
        [b.name, b.email, b.phone, b.cpf, b.tier || 'standard', b.address, b.notes, ctx.params.id]);
  recalcLtv(ctx.params.id);
  sendJson(res, { ok: true });
});
addRoute('DELETE', '/api/clients/:id', async (req, res, ctx) => {
  dbRun('UPDATE clients SET active=0 WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── VESSELS ──────────────────────────────────────────────────────────
addRoute('GET', '/api/vessels', async (req, res, ctx) => {
  const { search = '', client_id = '' } = ctx.qs;
  let sql = `SELECT v.*, c.name as client_name, c.tier as client_tier, s.number as spot_number
    FROM vessels v JOIN clients c ON v.client_id=c.id
    LEFT JOIN contracts ct ON ct.vessel_id=v.id AND ct.status='active'
    LEFT JOIN spots s ON ct.spot_id=s.id WHERE v.active=1`;
  const a = [];
  if (search)    { sql += ' AND (v.name LIKE ? OR v.registration LIKE ? OR c.name LIKE ?)'; a.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (client_id) { sql += ' AND v.client_id=?'; a.push(client_id); }
  sendJson(res, dbAll(sql + ' ORDER BY v.name', a));
});
addRoute('GET', '/api/vessels/:id', async (req, res, ctx) => {
  const v = dbGet(`SELECT v.*, c.name as client_name FROM vessels v JOIN clients c ON v.client_id=c.id WHERE v.id=?`, [ctx.params.id]);
  if (!v) return sendJson(res, { error: 'Não encontrado' }, 404);
  v.history     = dbAll(`SELECT * FROM queue_operations WHERE vessel_id=? ORDER BY requested_at DESC LIMIT 20`, [ctx.params.id]);
  v.maintenance = dbAll(`SELECT * FROM maintenance_os WHERE vessel_id=? ORDER BY created_at DESC LIMIT 10`, [ctx.params.id]);
  v.contract    = dbGet(`SELECT ct.*, s.number as spot_number FROM contracts ct LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.vessel_id=? AND ct.status='active'`, [ctx.params.id]);
  sendJson(res, v);
});
addRoute('POST', '/api/vessels', async (req, res, ctx) => {
  const b = ctx.body;
  const r = dbRun('INSERT INTO vessels(client_id,name,type,length,beam,draft,year,registration,model,manufacturer,engine,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                  [b.client_id, b.name, b.type, b.length, b.beam, b.draft, b.year, b.registration, b.model, b.manufacturer, b.engine, b.notes]);
  sendJson(res, { id: Number(r.lastInsertRowid) }, 201);
});
addRoute('PUT', '/api/vessels/:id', async (req, res, ctx) => {
  const b = ctx.body;
  dbRun('UPDATE vessels SET name=?,type=?,length=?,beam=?,draft=?,year=?,registration=?,model=?,manufacturer=?,engine=?,notes=? WHERE id=?',
        [b.name, b.type, b.length, b.beam, b.draft, b.year, b.registration, b.model, b.manufacturer, b.engine, b.notes, ctx.params.id]);
  sendJson(res, { ok: true });
});
addRoute('DELETE', '/api/vessels/:id', async (req, res, ctx) => {
  dbRun('UPDATE vessels SET active=0 WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── SPOTS ─────────────────────────────────────────────────────────────
addRoute('GET', '/api/spots/summary', async (req, res) => {
  const rows = dbAll('SELECT type, status, COUNT(*) as count FROM spots GROUP BY type, status');
  const r = { seca: { total:0,available:0,occupied:0,maintenance:0 }, molhada: { total:0,available:0,occupied:0,maintenance:0 } };
  for (const row of rows) {
    r[row.type].total += row.count;
    if (row.status in r[row.type]) r[row.type][row.status] += row.count;
  }
  sendJson(res, r);
});
addRoute('GET', '/api/spots', async (req, res, ctx) => {
  const { type = '', status = '' } = ctx.qs;
  let sql = 'SELECT s.*, v.name as vessel_name, c.name as client_name FROM spots s LEFT JOIN vessels v ON s.vessel_id=v.id LEFT JOIN clients c ON v.client_id=c.id WHERE 1=1';
  const a = [];
  if (type)   { sql += ' AND s.type=?';   a.push(type); }
  if (status) { sql += ' AND s.status=?'; a.push(status); }
  sendJson(res, dbAll(sql + ' ORDER BY s.number', a));
});
addRoute('PUT', '/api/spots/:id', async (req, res, ctx) => {
  dbRun('UPDATE spots SET status=?,vessel_id=? WHERE id=?', [ctx.body.status, ctx.body.vessel_id || null, ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── CONTRACTS ─────────────────────────────────────────────────────────
addRoute('GET', '/api/contracts', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  let sql = `SELECT ct.*, c.name as client_name, c.tier as client_tier,
    v.name as vessel_name, s.number as spot_number
    FROM contracts ct JOIN clients c ON ct.client_id=c.id
    JOIN vessels v ON ct.vessel_id=v.id LEFT JOIN spots s ON ct.spot_id=s.id WHERE 1=1`;
  const a = [];
  if (status) { sql += ' AND ct.status=?'; a.push(status); }
  sendJson(res, dbAll(sql + ' ORDER BY ct.start_date DESC', a));
});
addRoute('POST', '/api/contracts', async (req, res, ctx) => {
  const b = ctx.body;
  const r = dbRun('INSERT INTO contracts(client_id,vessel_id,spot_id,type,start_date,end_date,monthly_value,status,notes) VALUES(?,?,?,?,?,?,?,?,?)',
                  [b.client_id, b.vessel_id, b.spot_id || null, b.type, b.start_date, b.end_date || null, b.monthly_value, b.status || 'active', b.notes || null]);
  if (b.spot_id) dbRun(`UPDATE spots SET status='occupied',vessel_id=? WHERE id=?`, [b.vessel_id, b.spot_id]);
  for (let i = 0; i < 3; i++) {
    const d = new Date(b.start_date); d.setDate(d.getDate() + 30 * i);
    const ds = d.toISOString().slice(0, 10);
    const month = d.toLocaleDateString('pt-BR', { month: '2-digit', year: 'numeric' });
    dbRun(`INSERT INTO financial_charges(client_id,contract_id,description,amount,due_date,status) VALUES(?,?,?,?,?,'pending')`,
          [b.client_id, r.lastInsertRowid, `Mensalidade ${b.type} - ${month}`, b.monthly_value, ds]);
  }
  sendJson(res, { id: Number(r.lastInsertRowid) }, 201);
});
addRoute('PUT', '/api/contracts/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const old = dbGet('SELECT * FROM contracts WHERE id=?', [ctx.params.id]);
  dbRun('UPDATE contracts SET status=?,monthly_value=?,end_date=?,notes=? WHERE id=?',
        [b.status || old.status, b.monthly_value || old.monthly_value, b.end_date || old.end_date, b.notes || old.notes, ctx.params.id]);
  if (b.status === 'cancelled' && old.spot_id)
    dbRun(`UPDATE spots SET status='available',vessel_id=NULL WHERE id=?`, [old.spot_id]);
  sendJson(res, { ok: true });
});

// ── QUEUE ─────────────────────────────────────────────────────────────
addRoute('GET', '/api/queue/history', async (req, res) => {
  sendJson(res, dbAll(`SELECT q.*, v.name as vessel_name, c.name as client_name
    FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id JOIN clients c ON q.client_id=c.id
    WHERE q.status IN ('completed','cancelled') ORDER BY q.requested_at DESC LIMIT 50`));
});
addRoute('GET', '/api/queue', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  let sql = `SELECT q.*, v.name as vessel_name, v.type as vessel_type, v.length as vessel_length,
    c.name as client_name, c.tier as client_tier
    FROM queue_operations q JOIN vessels v ON q.vessel_id=v.id JOIN clients c ON q.client_id=c.id WHERE 1=1`;
  const a = [];
  if (status) {
    const ss = status.split(',');
    sql += ` AND q.status IN (${ss.map(() => '?').join(',')})`;
    a.push(...ss);
  } else {
    sql += ` AND q.status NOT IN ('completed','cancelled')`;
  }
  sendJson(res, dbAll(sql + ' ORDER BY q.priority DESC, q.requested_at ASC', a));
});
addRoute('POST', '/api/queue', async (req, res, ctx) => {
  const vessel = dbGet('SELECT * FROM vessels WHERE id=?', [ctx.body.vessel_id]);
  if (!vessel) return sendJson(res, { error: 'Embarcação não encontrada' }, 404);
  const client = dbGet('SELECT * FROM clients WHERE id=?', [vessel.client_id]);
  const priority = client && ['gold', 'vip'].includes(client.tier) ? 1 : 0;
  const r = dbRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,priority,notes) VALUES(?,?,?,'waiting',?,?)`,
                  [ctx.body.vessel_id, vessel.client_id, ctx.body.operation_type, priority, ctx.body.notes || null]);
  sendJson(res, { id: Number(r.lastInsertRowid) }, 201);
});
addRoute('PUT', '/api/queue/:id', async (req, res, ctx) => {
  const b = ctx.body;
  const old = dbGet('SELECT * FROM queue_operations WHERE id=?', [ctx.params.id]);
  const ns = b.status || old.status;
  let started   = old.started_at,   completed = old.completed_at;
  if (ns === 'in_progress' && !started)                       started   = nowStr();
  if (['completed', 'cancelled'].includes(ns) && !completed)  completed = nowStr();
  dbRun('UPDATE queue_operations SET status=?,started_at=?,completed_at=?,operator=?,notes=? WHERE id=?',
        [ns, started || null, completed || null, b.operator || old.operator || null, b.notes || old.notes || null, ctx.params.id]);
  sendJson(res, { ok: true });
});
addRoute('DELETE', '/api/queue/:id', async (req, res, ctx) => {
  dbRun(`UPDATE queue_operations SET status='cancelled' WHERE id=?`, [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── FINANCIAL ─────────────────────────────────────────────────────────
addRoute('GET', '/api/financial/charges', async (req, res, ctx) => {
  const { status = '', client_id = '' } = ctx.qs;
  let sql = 'SELECT fc.*, c.name as client_name, c.tier as client_tier FROM financial_charges fc JOIN clients c ON fc.client_id=c.id WHERE 1=1';
  const a = [];
  if (status)    { sql += ' AND fc.status=?';    a.push(status); }
  if (client_id) { sql += ' AND fc.client_id=?'; a.push(client_id); }
  sendJson(res, dbAll(sql + ' ORDER BY fc.due_date DESC', a));
});
addRoute('POST', '/api/financial/charges', async (req, res, ctx) => {
  const b = ctx.body;
  const r = dbRun(`INSERT INTO financial_charges(client_id,contract_id,description,amount,due_date,status,notes) VALUES(?,?,?,?,?,?,?)`,
                  [b.client_id, b.contract_id || null, b.description, b.amount, b.due_date, b.status || 'pending', b.notes || null]);
  sendJson(res, { id: Number(r.lastInsertRowid) }, 201);
});
addRoute('PUT', '/api/financial/charges/:id', async (req, res, ctx) => {
  const b   = ctx.body;
  const old = dbGet('SELECT * FROM financial_charges WHERE id=?', [ctx.params.id]);
  const ns  = b.status || old.status;
  const paid_date = (ns === 'paid' && !old.paid_date) ? todayStr() : (b.paid_date || old.paid_date || null);
  dbRun('UPDATE financial_charges SET status=?,paid_date=?,payment_method=?,notes=? WHERE id=?',
        [ns, paid_date, b.payment_method || old.payment_method || null, b.notes || old.notes || null, ctx.params.id]);
  if (ns === 'paid') recalcLtv(old.client_id);
  checkOverdue();
  sendJson(res, { ok: true });
});
addRoute('GET', '/api/financial/summary', async (req, res) => {
  checkOverdue();
  const ms = monthStart();
  sendJson(res, {
    total_paid_month: dbGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`, [ms])?.v || 0,
    total_pending:    dbGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='pending'`)?.v || 0,
    total_overdue:    dbGet(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='overdue'`)?.v || 0,
    count_overdue:    dbGet(`SELECT COUNT(*) as v FROM financial_charges WHERE status='overdue'`)?.v || 0,
    revenue_by_month: dbAll(`SELECT strftime('%Y-%m',paid_date) as month, COALESCE(SUM(amount),0) as total FROM financial_charges WHERE status='paid' AND paid_date IS NOT NULL GROUP BY month ORDER BY month DESC LIMIT 6`),
  });
});

// ── STORE ─────────────────────────────────────────────────────────────
addRoute('GET', '/api/store/items', async (req, res, ctx) => {
  const { category = '', low_stock = '' } = ctx.qs;
  let sql = 'SELECT * FROM store_items WHERE active=1';
  const a = [];
  if (category)  { sql += ' AND category=?'; a.push(category); }
  if (low_stock) sql += ' AND stock<=min_stock';
  sendJson(res, dbAll(sql + ' ORDER BY category,name', a));
});
addRoute('POST', '/api/store/items', async (req, res, ctx) => {
  const b = ctx.body;
  const r = dbRun('INSERT INTO store_items(name,category,price,cost,stock,min_stock,unit) VALUES(?,?,?,?,?,?,?)',
                  [b.name, b.category || 'outros', b.price, b.cost || 0, b.stock || 0, b.min_stock || 5, b.unit || 'un']);
  sendJson(res, { id: Number(r.lastInsertRowid) }, 201);
});
addRoute('PUT', '/api/store/items/:id', async (req, res, ctx) => {
  const b = ctx.body;
  dbRun('UPDATE store_items SET name=?,category=?,price=?,cost=?,stock=?,min_stock=?,unit=? WHERE id=?',
        [b.name, b.category, b.price, b.cost || 0, b.stock || 0, b.min_stock || 5, b.unit || 'un', ctx.params.id]);
  checkStock();
  sendJson(res, { ok: true });
});
addRoute('DELETE', '/api/store/items/:id', async (req, res, ctx) => {
  dbRun('UPDATE store_items SET active=0 WHERE id=?', [ctx.params.id]);
  sendJson(res, { ok: true });
});
addRoute('GET', '/api/store/orders', async (req, res, ctx) => {
  const { status = '' } = ctx.qs;
  let sql = 'SELECT o.*, v.name as vessel_name, c.name as client_name FROM store_orders o LEFT JOIN vessels v ON o.vessel_id=v.id LEFT JOIN clients c ON o.client_id=c.id WHERE 1=1';
  const a = [];
  if (status) { sql += ' AND o.status=?'; a.push(status); }
  const rows = dbAll(sql + ' ORDER BY o.created_at DESC LIMIT 100', a);
  for (const r of rows) { try { r.items = JSON.parse(r.items); } catch { /* keep raw */ } }
  sendJson(res, rows);
});
addRoute('POST', '/api/store/orders', async (req, res, ctx) => {
  const b = ctx.body;
  const items    = b.items || [];
  const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
  const discount = b.discount || 0;
  const total    = subtotal - discount;
  const r = dbRun('INSERT INTO store_orders(vessel_id,client_id,items,subtotal,discount,total,status,payment_method,notes) VALUES(?,?,?,?,?,?,?,?,?)',
                  [b.vessel_id || null, b.client_id || null, JSON.stringify(items), subtotal, discount, total,
                   b.status || 'open', b.payment_method || null, b.notes || null]);
  for (const item of items) dbRun('UPDATE store_items SET stock=MAX(0,stock-?) WHERE id=?', [item.qty, item.item_id]);
  checkStock();
  sendJson(res, { id: Number(r.lastInsertRowid), total }, 201);
});
addRoute('PUT', '/api/store/orders/:id', async (req, res, ctx) => {
  dbRun('UPDATE store_orders SET status=?,payment_method=?,notes=? WHERE id=?',
        [ctx.body.status, ctx.body.payment_method || null, ctx.body.notes || null, ctx.params.id]);
  sendJson(res, { ok: true });
});
addRoute('PUT', '/api/store/orders/:id/delivery', async (req, res, ctx) => {
  const { delivery_status, status } = ctx.body;
  const updates = [];
  const params = [];
  if (delivery_status !== undefined) { updates.push('delivery_status=?'); params.push(delivery_status); }
  if (status !== undefined) { updates.push('status=?'); params.push(status); }
  if (!updates.length) { sendJson(res,{ok:true}); return; }
  params.push(ctx.params.id);
  dbRun(`UPDATE store_orders SET ${updates.join(',')} WHERE id=?`, params);
  sendJson(res, { ok: true });
});
addRoute('GET', '/api/store/pix-config', async (req, res) => {
  sendJson(res, dbGet(`SELECT * FROM store_pix_config WHERE active=1 ORDER BY id DESC`) || {});
});
addRoute('POST', '/api/store/pix-config', async (req, res, ctx) => {
  dbRun(`UPDATE store_pix_config SET active=0`);
  dbRun(`INSERT INTO store_pix_config(key,key_type,merchant_name,city,active) VALUES(?,?,?,?,1)`,
        [ctx.body.key, ctx.body.key_type, ctx.body.merchant_name, ctx.body.city]);
  sendJson(res, { ok: true });
});
addRoute('POST', '/api/store/pix-qrcode', async (req, res, ctx) => {
  const cfg = dbGet(`SELECT * FROM store_pix_config WHERE active=1 ORDER BY id DESC`);
  if (!cfg) return sendJson(res, { error: 'PIX não configurado' }, 400);
  const amount  = parseFloat(ctx.body.amount) || 0;
  const txid    = crypto.randomBytes(12).toString('hex').toUpperCase().slice(0, 25);
  const payload = buildPix(cfg.key, cfg.merchant_name, cfg.city, amount, txid);
  sendJson(res, { payload, txid, amount });
});

// ── MAINTENANCE ───────────────────────────────────────────────────────
addRoute('GET', '/api/maintenance', async (req, res, ctx) => {
  const { status = '', vessel_id = '' } = ctx.qs;
  let sql = `SELECT m.*, v.name as vessel_name, c.name as client_name
    FROM maintenance_os m LEFT JOIN vessels v ON m.vessel_id=v.id LEFT JOIN clients c ON v.client_id=c.id WHERE 1=1`;
  const a = [];
  if (status)    { sql += ' AND m.status=?';    a.push(status); }
  if (vessel_id) { sql += ' AND m.vessel_id=?'; a.push(vessel_id); }
  sql += ` ORDER BY CASE m.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, m.created_at DESC`;
  sendJson(res, dbAll(sql, a));
});
addRoute('POST', '/api/maintenance', async (req, res, ctx) => {
  const b      = ctx.body;
  const os_num = `OS-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${Math.floor(Math.random()*900)+100}`;
  const r = dbRun('INSERT INTO maintenance_os(vessel_id,os_number,type,description,status,priority,scheduled_date,estimated_hours,cost,technician,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                  [b.vessel_id || null, os_num, b.type, b.description, b.status || 'open', b.priority || 'normal',
                   b.scheduled_date || null, b.estimated_hours || null, b.cost || 0, b.technician || null, b.notes || null]);
  if (['urgent', 'high'].includes(b.priority))
    addAlert('manutencao', `OS urgente: ${b.description.slice(0, 50)}`, 'warning');
  sendJson(res, { id: Number(r.lastInsertRowid), os_number: os_num }, 201);
});
addRoute('PUT', '/api/maintenance/:id', async (req, res, ctx) => {
  const b   = ctx.body;
  const old = dbGet('SELECT * FROM maintenance_os WHERE id=?', [ctx.params.id]);
  const ns  = b.status || old.status;
  const completed_date = (ns === 'completed' && !old.completed_date) ? todayStr() : (b.completed_date || old.completed_date || null);
  dbRun('UPDATE maintenance_os SET status=?,priority=?,scheduled_date=?,completed_date=?,actual_hours=?,cost=?,technician=?,notes=? WHERE id=?',
        [ns, b.priority || old.priority, b.scheduled_date || old.scheduled_date || null, completed_date,
         b.actual_hours || old.actual_hours || null, b.cost !== undefined ? b.cost : old.cost,
         b.technician || old.technician || null, b.notes || old.notes || null, ctx.params.id]);
  sendJson(res, { ok: true });
});
addRoute('DELETE', '/api/maintenance/:id', async (req, res, ctx) => {
  dbRun(`UPDATE maintenance_os SET status='cancelled' WHERE id=?`, [ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── ALERTS ────────────────────────────────────────────────────────────
addRoute('GET', '/api/alerts', async (req, res, ctx) => {
  const { unread = '' } = ctx.qs;
  let sql = 'SELECT * FROM alerts WHERE 1=1';
  if (unread) sql += ' AND read_at IS NULL';
  sendJson(res, dbAll(sql + ' ORDER BY created_at DESC LIMIT 50'));
});
addRoute('PUT', '/api/alerts/read-all', async (req, res) => {
  dbRun('UPDATE alerts SET read_at=? WHERE read_at IS NULL', [nowStr()]);
  sendJson(res, { ok: true });
});
addRoute('PUT', '/api/alerts/:id/read', async (req, res, ctx) => {
  dbRun('UPDATE alerts SET read_at=? WHERE id=?', [nowStr(), ctx.params.id]);
  sendJson(res, { ok: true });
});

// ── ANALYTICS ─────────────────────────────────────────────────────────
addRoute('GET', '/api/analytics/kpis', async (req, res) => {
  checkOverdue();
  const ms   = monthStart();
  const td   = todayStr();
  const ago30 = daysAgo(30);
  const g1 = (sql, a = []) => dbGet(sql, a);

  const vagas_total         = g1('SELECT COUNT(*) as v FROM spots')?.v || 0;
  const vagas_ocupadas      = g1(`SELECT COUNT(*) as v FROM spots WHERE status='occupied'`)?.v || 0;
  const vagas_seca_total    = g1(`SELECT COUNT(*) as v FROM spots WHERE type='seca'`)?.v || 0;
  const vagas_seca_ocupadas = g1(`SELECT COUNT(*) as v FROM spots WHERE type='seca' AND status='occupied'`)?.v || 0;
  const vagas_molhada_total    = g1(`SELECT COUNT(*) as v FROM spots WHERE type='molhada'`)?.v || 0;
  const vagas_molhada_ocupadas = g1(`SELECT COUNT(*) as v FROM spots WHERE type='molhada' AND status='occupied'`)?.v || 0;

  const receita_mes  = g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`, [ms])?.v || 0;
  const inadimplencia= g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='overdue'`)?.v || 0;
  const pendente     = g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='pending'`)?.v || 0;
  const total_ct_val = g1(`SELECT COALESCE(SUM(monthly_value),0) as v FROM contracts WHERE status='active'`)?.v || 0;
  const receita_seca = g1(`SELECT COALESCE(SUM(fc.amount),0) as v FROM financial_charges fc JOIN contracts ct ON fc.contract_id=ct.id WHERE fc.status='paid' AND fc.paid_date>=? AND ct.type='seca'`, [ms])?.v || 0;
  const receita_mol  = g1(`SELECT COALESCE(SUM(fc.amount),0) as v FROM financial_charges fc JOIN contracts ct ON fc.contract_id=ct.id WHERE fc.status='paid' AND fc.paid_date>=? AND ct.type='molhada'`, [ms])?.v || 0;
  const loja_mes     = g1(`SELECT COALESCE(SUM(total),0) as v FROM store_orders WHERE status='paid' AND DATE(created_at)>=?`, [ms])?.v || 0;

  const total_clientes   = g1(`SELECT COUNT(*) as v FROM clients WHERE active=1`)?.v || 0;
  const vip_count        = g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier IN ('gold','vip')`)?.v || 0;
  const total_vessels    = g1(`SELECT COUNT(*) as v FROM vessels WHERE active=1`)?.v || 0;
  const contratos_ativos = g1(`SELECT COUNT(*) as v FROM contracts WHERE status='active'`)?.v || 0;
  const queue_hoje       = g1(`SELECT COUNT(*) as v FROM queue_operations WHERE DATE(requested_at)=? AND status!='cancelled'`, [td])?.v || 0;
  const queue_aguardando = g1(`SELECT COUNT(*) as v FROM queue_operations WHERE status IN ('waiting','in_progress')`)?.v || 0;
  const os_abertas       = g1(`SELECT COUNT(*) as v FROM maintenance_os WHERE status IN ('open','in_progress')`)?.v || 0;
  const os_urgentes      = g1(`SELECT COUNT(*) as v FROM maintenance_os WHERE status IN ('open','in_progress') AND priority IN ('urgent','high')`)?.v || 0;
  const custo_manut      = g1(`SELECT COALESCE(SUM(cost),0) as v FROM maintenance_os WHERE completed_date>=?`, [ms])?.v || 0;
  const alertas_nl       = g1(`SELECT COUNT(*) as v FROM alerts WHERE read_at IS NULL`)?.v || 0;
  const ticket_medio     = g1(`SELECT AVG(total) as v FROM store_orders WHERE status='paid'`)?.v || 0;
  const ltv_medio        = g1(`SELECT AVG(ltv) as v FROM clients WHERE active=1`)?.v || 0;
  const sla              = g1(`SELECT AVG((julianday(completed_at)-julianday(requested_at))*24*60) as avg_min FROM queue_operations WHERE status='completed' AND DATE(completed_at)>=?`, [ms])?.avg_min || 0;
  const ops_por_tipo     = dbAll(`SELECT operation_type, COUNT(*) as count FROM queue_operations WHERE DATE(requested_at)>=? GROUP BY operation_type`, [ago30]);

  sendJson(res, {
    ocupacao_total:   vagas_total    ? Math.round(vagas_ocupadas      / vagas_total    * 1000) / 10 : 0,
    ocupacao_seca:    vagas_seca_total    ? Math.round(vagas_seca_ocupadas    / vagas_seca_total    * 1000) / 10 : 0,
    ocupacao_molhada: vagas_molhada_total ? Math.round(vagas_molhada_ocupadas / vagas_molhada_total * 1000) / 10 : 0,
    vagas_total, vagas_ocupadas,
    vagas_seca_total, vagas_seca_ocupadas,
    vagas_molhada_total, vagas_molhada_ocupadas,
    receita_mes, inadimplencia, pendente, receita_seca, receita_molhada: receita_mol, receita_loja: loja_mes,
    taxa_inadimplencia: total_ct_val ? Math.round(inadimplencia / total_ct_val * 1000) / 10 : 0,
    total_clientes, vip_count, total_vessels, contratos_ativos,
    queue_hoje, queue_aguardando,
    sla_avg_min:         Math.round(sla * 10) / 10,
    os_abertas, os_urgentes, custo_manutencao_mes: custo_manut,
    alertas_nao_lidos:   alertas_nl,
    ticket_medio_loja:   Math.round((ticket_medio || 0) * 100) / 100,
    ltv_medio:           Math.round((ltv_medio    || 0) * 100) / 100,
    ops_por_tipo,
  });
});
addRoute('GET', '/api/analytics/revenue-chart', async (req, res) => {
  const rows = dbAll(`SELECT strftime('%Y-%m',paid_date) as month, COALESCE(SUM(amount),0) as total FROM financial_charges WHERE status='paid' AND paid_date IS NOT NULL GROUP BY month ORDER BY month DESC LIMIT 12`);
  sendJson(res, rows.reverse());
});
addRoute('GET', '/api/analytics/top-clients', async (req, res) => {
  sendJson(res, dbAll(`SELECT c.name, c.tier, c.ltv,
    COUNT(DISTINCT v.id) as vessels, COUNT(DISTINCT ct.id) as contracts
    FROM clients c LEFT JOIN vessels v ON v.client_id=c.id AND v.active=1
    LEFT JOIN contracts ct ON ct.client_id=c.id AND ct.status='active'
    WHERE c.active=1 ORDER BY c.ltv DESC LIMIT 10`));
});
addRoute('GET', '/api/analytics/occupancy-trend', async (req, res) => {
  sendJson(res, dbAll(`SELECT DATE(start_date) as d, COUNT(*) as new_contracts FROM contracts GROUP BY DATE(start_date) ORDER BY d DESC LIMIT 30`));
});
addRoute('GET', '/api/analytics/extended', async (req, res) => {
  checkOverdue();
  const ms = monthStart();
  const ago3m = daysAgo(90);
  const ago6m = daysAgo(180);
  const g1 = (sql,a=[]) => dbGet(sql,a);

  const receita_3m    = g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`,[ago3m])?.v||0;
  const receita_6m    = g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid' AND paid_date>=?`,[ago6m])?.v||0;
  const receita_total = g1(`SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status='paid'`)?.v||0;
  const despesas_manut= g1(`SELECT COALESCE(SUM(cost),0) as v FROM maintenance_os WHERE status='completed'`)?.v||0;
  const contratos_vencendo_30d = g1(`SELECT COUNT(*) as v FROM contracts WHERE status='active' AND end_date<=?`,[daysAhead(30)])?.v||0;
  const contratos_vencendo_7d  = g1(`SELECT COUNT(*) as v FROM contracts WHERE status='active' AND end_date<=?`,[daysAhead(7)])?.v||0;
  const valor_carteira = g1(`SELECT COALESCE(SUM(monthly_value),0) as v FROM contracts WHERE status='active'`)?.v||0;
  const clientes_novos_mes = g1(`SELECT COUNT(*) as v FROM clients WHERE DATE(created_at)>=?`,[ms])?.v||0;
  const ltv_max  = g1(`SELECT MAX(ltv) as v FROM clients WHERE active=1`)?.v||0;
  const pedidos_mes = g1(`SELECT COUNT(*) as v FROM store_orders WHERE status='paid' AND DATE(created_at)>=?`,[ms])?.v||0;
  const pedidos_pendentes = g1(`SELECT COUNT(*) as v FROM store_orders WHERE status IN ('open','pending_payment')`)?.v||0;
  const ops_total = g1(`SELECT COUNT(*) as v FROM queue_operations`)?.v||0;
  const ops_mes   = g1(`SELECT COUNT(*) as v FROM queue_operations WHERE DATE(requested_at)>=?`,[ms])?.v||0;
  const ops_completed_mes = g1(`SELECT COUNT(*) as v FROM queue_operations WHERE status='completed' AND DATE(completed_at)>=?`,[ms])?.v||0;
  const taxa_conclusao = ops_mes>0 ? Math.round(ops_completed_mes/ops_mes*100) : 0;
  const os_total = g1(`SELECT COUNT(*) as v FROM maintenance_os`)?.v||0;
  const os_concluidas = g1(`SELECT COUNT(*) as v FROM maintenance_os WHERE status='completed'`)?.v||0;
  const taxa_resolucao_os = os_total>0 ? Math.round(os_concluidas/os_total*100) : 0;
  const spots_seca_livre = g1(`SELECT COUNT(*) as v FROM spots WHERE type='seca' AND status='available'`)?.v||0;
  const spots_mol_livre  = g1(`SELECT COUNT(*) as v FROM spots WHERE type='molhada' AND status='available'`)?.v||0;

  const receita_por_mes    = dbAll(`SELECT strftime('%Y-%m',paid_date) as month, COALESCE(SUM(amount),0) as total, COUNT(*) as count FROM financial_charges WHERE status='paid' AND paid_date IS NOT NULL GROUP BY month ORDER BY month DESC LIMIT 12`).reverse();
  const loja_por_mes       = dbAll(`SELECT strftime('%Y-%m',created_at) as month, COALESCE(SUM(total),0) as total, COUNT(*) as count FROM store_orders WHERE status='paid' GROUP BY month ORDER BY month DESC LIMIT 12`).reverse();
  const ops_por_tipo       = dbAll(`SELECT operation_type, COUNT(*) as count FROM queue_operations GROUP BY operation_type ORDER BY count DESC`);
  const ops_por_mes        = dbAll(`SELECT strftime('%Y-%m',requested_at) as month, COUNT(*) as count FROM queue_operations GROUP BY month ORDER BY month DESC LIMIT 12`).reverse();
  const manut_por_tipo     = dbAll(`SELECT type, COUNT(*) as count, COALESCE(SUM(cost),0) as total FROM maintenance_os GROUP BY type`);
  const charges_por_status = dbAll(`SELECT status, COUNT(*) as count, COALESCE(SUM(amount),0) as total FROM financial_charges GROUP BY status`);
  const top_clientes_loja  = dbAll(`SELECT c.name, c.tier, COALESCE(SUM(o.total),0) as total_loja, COUNT(o.id) as pedidos FROM clients c LEFT JOIN store_orders o ON o.client_id=c.id AND o.status='paid' WHERE c.active=1 GROUP BY c.id ORDER BY total_loja DESC LIMIT 10`);
  const vip_count   = g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='vip'`)?.v||0;
  const gold_count  = g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='gold'`)?.v||0;
  const silver_count= g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='silver'`)?.v||0;
  const std_count   = g1(`SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier='standard'`)?.v||0;

  sendJson(res, {
    receita_3m, receita_6m, receita_total, despesas_manut,
    margem_bruta: receita_total - despesas_manut,
    contratos_vencendo_30d, contratos_vencendo_7d,
    valor_carteira, valor_carteira_anual: valor_carteira*12,
    clientes_novos_mes, ltv_max,
    pedidos_mes, pedidos_pendentes,
    ops_total, ops_mes, ops_completed_mes, taxa_conclusao,
    os_total, os_concluidas, taxa_resolucao_os,
    spots_seca_livre, spots_mol_livre,
    receita_por_mes, loja_por_mes, ops_por_tipo, ops_por_mes,
    manut_por_tipo, charges_por_status, top_clientes_loja,
    vip_count, gold_count, silver_count, std_count,
  });
});

// ── DB INIT & SEED ────────────────────────────────────────────────────
function initDb() {
  db = new DatabaseSync(DB_PATH);
  db.exec(`
  PRAGMA foreign_keys=ON;
  CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,name TEXT NOT NULL,role TEXT DEFAULT 'admin');
  CREATE TABLE IF NOT EXISTS clients(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT,phone TEXT,cpf TEXT,tier TEXT DEFAULT 'standard',ltv REAL DEFAULT 0,address TEXT,notes TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS vessels(id INTEGER PRIMARY KEY AUTOINCREMENT,client_id INTEGER NOT NULL,name TEXT NOT NULL,type TEXT,length REAL,beam REAL,draft REAL,year INTEGER,registration TEXT,model TEXT,manufacturer TEXT,engine TEXT,notes TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS spots(id INTEGER PRIMARY KEY AUTOINCREMENT,number TEXT NOT NULL,type TEXT NOT NULL,status TEXT DEFAULT 'available',vessel_id INTEGER);
  CREATE TABLE IF NOT EXISTS contracts(id INTEGER PRIMARY KEY AUTOINCREMENT,client_id INTEGER NOT NULL,vessel_id INTEGER NOT NULL,spot_id INTEGER,type TEXT NOT NULL,start_date TEXT NOT NULL,end_date TEXT,monthly_value REAL NOT NULL,status TEXT DEFAULT 'active',notes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS queue_operations(id INTEGER PRIMARY KEY AUTOINCREMENT,vessel_id INTEGER NOT NULL,client_id INTEGER NOT NULL,operation_type TEXT NOT NULL,status TEXT DEFAULT 'waiting',priority INTEGER DEFAULT 0,requested_at TEXT DEFAULT CURRENT_TIMESTAMP,started_at TEXT,completed_at TEXT,operator TEXT,notes TEXT);
  CREATE TABLE IF NOT EXISTS financial_charges(id INTEGER PRIMARY KEY AUTOINCREMENT,client_id INTEGER NOT NULL,contract_id INTEGER,description TEXT NOT NULL,amount REAL NOT NULL,due_date TEXT NOT NULL,paid_date TEXT,payment_method TEXT,status TEXT DEFAULT 'pending',notes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS store_items(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT,price REAL NOT NULL,cost REAL DEFAULT 0,stock INTEGER DEFAULT 0,min_stock INTEGER DEFAULT 5,unit TEXT DEFAULT 'un',active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS store_orders(id INTEGER PRIMARY KEY AUTOINCREMENT,vessel_id INTEGER,client_id INTEGER,items TEXT NOT NULL,subtotal REAL NOT NULL,discount REAL DEFAULT 0,total REAL NOT NULL,status TEXT DEFAULT 'open',payment_method TEXT,pix_txid TEXT,notes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS store_pix_config(id INTEGER PRIMARY KEY AUTOINCREMENT,key TEXT NOT NULL,key_type TEXT NOT NULL,merchant_name TEXT NOT NULL,city TEXT NOT NULL,active INTEGER DEFAULT 1);
  CREATE TABLE IF NOT EXISTS maintenance_os(id INTEGER PRIMARY KEY AUTOINCREMENT,vessel_id INTEGER,os_number TEXT NOT NULL,type TEXT NOT NULL,description TEXT NOT NULL,status TEXT DEFAULT 'open',priority TEXT DEFAULT 'normal',scheduled_date TEXT,completed_date TEXT,estimated_hours REAL,actual_hours REAL,cost REAL DEFAULT 0,technician TEXT,parts_used TEXT,notes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT NOT NULL,message TEXT NOT NULL,severity TEXT DEFAULT 'info',entity_type TEXT,entity_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,read_at TEXT);
  `);
}

function seedDb() {
  if ((dbGet('SELECT COUNT(*) as n FROM users')?.n || 0) > 0) return;

  dbRun('INSERT INTO users(email,password_hash,name,role) VALUES(?,?,?,?)',
        ['admin@marina.com', sha256('marina123'), 'Administrador', 'admin']);

  for (let i = 1; i <= 90; i++)
    dbRun(`INSERT INTO spots(number,type,status) VALUES(?,'seca','available')`, [`S${String(i).padStart(3,'0')}`]);
  for (let i = 1; i <= 20; i++)
    dbRun(`INSERT INTO spots(number,type,status) VALUES(?,'molhada','available')`, [`M${String(i).padStart(2,'0')}`]);

  const clientData = [
    ['Carlos Eduardo Souza','carlos@email.com','(11) 99999-0001','123.456.789-01','vip','Av. Beira Mar, 100'],
    ['Ana Paula Ferreira','ana@email.com','(11) 99999-0002','234.567.890-02','gold','Rua das Flores, 200'],
    ['Roberto Alves Lima','roberto@email.com','(11) 99999-0003','345.678.901-03','gold','Alameda Santos, 300'],
    ['Mariana Costa Pinto','mariana@email.com','(11) 99999-0004','456.789.012-04','silver','Rua Augusta, 400'],
    ['Fernando Oliveira','fernando@email.com','(11) 99999-0005','567.890.123-05','silver','Av. Paulista, 500'],
    ['Juliana Santos Cruz','juliana@email.com','(11) 99999-0006','678.901.234-06','standard','Rua 7 de Abril, 600'],
    ['Marcelo Rodrigues','marcelo@email.com','(11) 99999-0007','789.012.345-07','standard','Av. Brasil, 700'],
    ['Patricia Mendes Luz','patricia@email.com','(11) 99999-0008','890.123.456-08','vip','Rua Consolacao, 800'],
  ];
  const cids = clientData.map(c => Number(dbRun('INSERT INTO clients(name,email,phone,cpf,tier,address) VALUES(?,?,?,?,?,?)', c).lastInsertRowid));
  const cEmails = ['carlos','ana','roberto','mariana','fernando','juliana','marcelo','patricia'];
  cEmails.forEach((prefix,i) => {
    try { dbRun('INSERT INTO users(email,password_hash,name,role) VALUES(?,?,?,?)',
                [`${prefix}@marinaone.com`, sha256('senha123'), clientData[i][0], 'client']); }
    catch(e) {}
  });

  const vesselData = [
    [cids[0],'Rei dos Mares','lancha',12.5,3.2,1.0,2020,'SP-1001','Phantom 45','Phantom','Diesel 600cv'],
    [cids[1],'Brisa do Mar','veleiro',10.0,3.0,1.5,2018,'SP-1002','Bavaria 33','Bavaria','Vela'],
    [cids[2],'Pegaso','lancha',9.5,2.8,0.9,2021,'SP-1003','Focker 295','Focker','Diesel 400cv'],
    [cids[3],'Sereia','lancha',7.5,2.5,0.7,2019,'SP-1004','Coral 28','Coral','Gasolina 280cv'],
    [cids[4],'Delfim','jetski',3.5,1.2,0.4,2022,'SP-1005','Sea-Doo 300','Sea-Doo','Gasolina 300cv'],
    [cids[5],'Mare Alta','lancha',8.0,2.6,0.8,2017,'SP-1006','Ventura 28','Ventura','Gasolina 220cv'],
    [cids[6],'Sol Poente','catamaras',11.0,5.0,0.8,2020,'SP-1007','Leopard 38','Leopard','Diesel 2x55cv'],
    [cids[7],'Tempestade','lancha',13.0,3.5,1.1,2023,'SP-1008','Azimut 45','Azimut','Diesel 2x800cv'],
  ];
  const vids = vesselData.map(v => Number(dbRun('INSERT INTO vessels(client_id,name,type,length,beam,draft,year,registration,model,manufacturer,engine) VALUES(?,?,?,?,?,?,?,?,?,?,?)', v).lastInsertRowid));

  const startDate = daysAgo(180);
  const endDate   = daysAhead(180);
  const ctData = [
    [cids[0],vids[0],1,'seca',3500],
    [cids[1],vids[1],2,'seca',3200],
    [cids[2],vids[2],3,'seca',2800],
    [cids[3],vids[3],4,'seca',2200],
    [cids[4],vids[4],5,'seca',1500],
    [cids[5],vids[5],6,'seca',1800],
    [cids[6],vids[6],91,'molhada',4500],
    [cids[7],vids[7],92,'molhada',5500],
  ];
  const ctids = ctData.map(ct => {
    const r = dbRun(`INSERT INTO contracts(client_id,vessel_id,spot_id,type,start_date,end_date,monthly_value,status) VALUES(?,?,?,?,?,?,?,'active')`,
                    [ct[0], ct[1], ct[2], ct[3], startDate, endDate, ct[4]]);
    dbRun(`UPDATE spots SET status='occupied',vessel_id=? WHERE id=?`, [ct[1], ct[2]]);
    return Number(r.lastInsertRowid);
  });

  // Financial history
  for (let i = 30; i >= 1; i--) {
    const d   = new Date(); d.setDate(d.getDate() - i);
    const ds  = d.toISOString().slice(0, 10);
    if (i % 30 === 0 || i === 30) {
      for (let idx = 0; idx < 8; idx++) {
        const isPaid   = i > 5;
        const month    = d.toLocaleDateString('pt-BR', { month: '2-digit', year: 'numeric' });
        dbRun(`INSERT INTO financial_charges(client_id,contract_id,description,amount,due_date,paid_date,status,payment_method) VALUES(?,?,?,?,?,?,?,?)`,
              [cids[idx], ctids[idx], `Mensalidade ${month}`, ctData[idx][4], ds,
               isPaid ? ds : null, isPaid ? 'paid' : 'pending', isPaid ? 'pix' : null]);
      }
    }
  }

  const extras = [
    [cids[0],null,'Servico de icamento emergencial',850,daysAgo(15),daysAgo(15),'paid','cartao'],
    [cids[1],null,'Limpeza casco completa',420,daysAgo(10),daysAgo(9),'paid','pix'],
    [cids[2],null,'Pernoite embarcacao visitante',200,daysAgo(8),null,'overdue',null],
    [cids[3],null,'Energia eletrica extra',180,daysAgo(6),null,'overdue',null],
    [cids[7],null,'Reforma box armazenagem',1200,daysAhead(5),null,'pending',null],
  ];
  for (const e of extras)
    dbRun(`INSERT INTO financial_charges(client_id,contract_id,description,amount,due_date,paid_date,status,payment_method) VALUES(?,?,?,?,?,?,?,?)`, e);

  for (const cid of cids) recalcLtv(cid);

  const storeItems = [
    ['Oleo Motor 4T 1L','manutencao',45.9,28,30,10,'un'],
    ['Oleo Motor 2T 1L','manutencao',38.5,22,25,10,'un'],
    ['Fluido Hidraulico 1L','manutencao',52,30,20,5,'un'],
    ['Graxa Maritima 500g','manutencao',28.9,15,40,10,'un'],
    ['Fita Isolante Maritima','equipamento',18.5,8,50,15,'un'],
    ['Colete Salva-vidas Adulto','equipamento',220,140,15,5,'un'],
    ['Colete Infantil','equipamento',180,110,8,3,'un'],
    ['Corda Nautica 10m','equipamento',65,35,20,5,'un'],
    ['Ancora 5kg','equipamento',380,250,6,2,'un'],
    ['Extintor CO2 2kg','equipamento',145,90,12,4,'un'],
    ['Cerveja Lata 350ml','bebida',8,3.5,120,30,'un'],
    ['Agua Mineral 500ml','bebida',4,1.5,200,50,'un'],
    ['Refrigerante Lata','bebida',7,3,80,20,'un'],
    ['Energetico 250ml','bebida',12,6,60,15,'un'],
    ['Salgadinho Pacote','alimento',6.5,3,100,20,'un'],
    ['Barra de Cereal','alimento',4.5,2,80,20,'un'],
    ['Protetor Solar FPS60','outros',35,18,45,10,'un'],
    ['Toalha de Praia','outros',55,28,20,5,'un'],
    ['Limpador Embarcacao 1L','limpeza',42,22,30,8,'un'],
    ['Esponja Maritima','limpeza',12,5,60,15,'un'],
  ];
  const iids = storeItems.map(it => Number(dbRun('INSERT INTO store_items(name,category,price,cost,stock,min_stock,unit) VALUES(?,?,?,?,?,?,?)', it).lastInsertRowid));

  dbRun(`INSERT INTO store_pix_config(key,key_type,merchant_name,city,active) VALUES(?,'telefone','Marina One','Sao Paulo',1)`, ['11999990000']);

  const pmts = ['dinheiro', 'pix', 'cartao'];
  for (let i = 25; i >= 1; i--) {
    const d  = new Date(); d.setDate(d.getDate() - i);
    const ds = d.toISOString().replace('T', ' ').slice(0, 19);
    const cidx = Math.floor(Math.random() * 8), vidx = Math.floor(Math.random() * 8);
    const n = Math.floor(Math.random() * 3) + 1;
    const items = [];
    for (let j = 0; j < n; j++) {
      const iidx = Math.floor(Math.random() * storeItems.length);
      items.push({ item_id: iids[iidx], name: storeItems[iidx][0], qty: Math.floor(Math.random() * 2) + 1, price: storeItems[iidx][2] });
    }
    const subtotal = items.reduce((s, x) => s + x.price * x.qty, 0);
    dbRun(`INSERT INTO store_orders(vessel_id,client_id,items,subtotal,discount,total,status,payment_method,created_at) VALUES(?,?,?,?,0,?,'paid',?,?)`,
          [vids[vidx], cids[cidx], JSON.stringify(items), subtotal, subtotal, pmts[Math.floor(Math.random() * 3)], ds]);
  }

  const ops = ['descida', 'subida', 'atracacao'];
  const opers = ['Joao Silva', 'Pedro Santos', 'Maria Oliveira'];
  for (let i = 20; i >= 1; i--) {
    const d  = new Date(); d.setDate(d.getDate() - i);
    const ds = d.toISOString().slice(0, 16).replace('T', ' ') + ':00';
    const de = d.toISOString().slice(0, 16).replace('T', ' ') + ':30';
    const idx = Math.floor(Math.random() * 8);
    dbRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,requested_at,started_at,completed_at,operator) VALUES(?,?,?,'completed',?,?,?,?)`,
          [vids[idx], cids[idx], ops[Math.floor(Math.random() * 3)], ds, ds, de, opers[Math.floor(Math.random() * 3)]]);
  }
  dbRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,priority) VALUES(?,?,'descida','waiting',1)`, [vids[0], cids[0]]);
  dbRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,priority) VALUES(?,?,'subida','in_progress',0)`, [vids[3], cids[3]]);
  dbRun(`INSERT INTO queue_operations(vessel_id,client_id,operation_type,status,priority) VALUES(?,?,'atracacao','waiting',1)`, [vids[6], cids[6]]);

  const maintData = [
    [vids[0],'OS-20240101-001','preventiva','Revisao anual motor','completed','normal',daysAgo(20),daysAgo(18),4,3.5,850,'Joao Mecanico'],
    [vids[1],'OS-20240102-002','preventiva','Troca de oleo e filtros','completed','normal',daysAgo(15),daysAgo(14),2,1.5,320,'Pedro Tecnico'],
    [vids[2],'OS-20240103-003','corretiva','Reparo no sistema de direcao','in_progress','high',daysAgo(5),null,6,null,1200,'Joao Mecanico'],
    [vids[3],'OS-20240104-004','corretiva','Substituicao bomba dagua','open','urgent',todayStr(),null,3,null,650,null],
    [vids[4],'OS-20240105-005','preventiva','Lubrificacao geral e revisao','open','normal',daysAhead(7),null,2,null,280,null],
    [vids[7],'OS-20240106-006','preventiva','Revisao eletrica completa','open','high',daysAhead(3),null,8,null,2200,'Maria Eletrica'],
  ];
  for (const m of maintData)
    dbRun('INSERT INTO maintenance_os(vessel_id,os_number,type,description,status,priority,scheduled_date,completed_date,estimated_hours,actual_hours,cost,technician) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', m);

  const alertsData = [
    ['financeiro','2 cobrancas em atraso - total R$ 380,00','warning'],
    ['manutencao','OS urgente: Substituicao bomba dagua - Sereia','error'],
    ['estoque','Estoque baixo: Ancora 5kg (6 un)','warning'],
    ['contrato','3 contratos vencem em 30 dias','info'],
    ['sistema','Sistema Marina One iniciado com sucesso','info'],
  ];
  for (const a of alertsData)
    dbRun('INSERT INTO alerts(type,message,severity) VALUES(?,?,?)', a);

  console.log('✅ Banco de dados populado com dados de exemplo!');
}

// ── HTTP SERVER ───────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { setCors(res); res.writeHead(204); res.end(); return; }

  const urlPath = req.url.split('?')[0];

  // Static file serving
  if (req.method === 'GET' && !urlPath.startsWith('/api')) {
    const fileName = urlPath === '/' ? 'frontend.html' : urlPath.slice(1);
    const fullPath = path.join(__dirname, fileName);
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      const ext = path.extname(fullPath);
      const ct  = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' }[ext] || 'text/plain';
      setCors(res); res.writeHead(200, { 'Content-Type': ct });
      fs.createReadStream(fullPath).pipe(res);
      return;
    }
    setCors(res); res.writeHead(404); res.end('Not found'); return;
  }

  if (!urlPath.startsWith('/api')) { sendJson(res, { error: 'Not found' }, 404); return; }

  const match = matchRoute(req.method, urlPath);
  if (!match) { sendJson(res, { error: 'Not found' }, 404); return; }

  const user = getAuth(req);
  if (urlPath !== '/api/auth/login' && !user) { sendJson(res, { error: 'Token inválido' }, 401); return; }

  const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await parseBody(req) : {};
  const qs   = getQS(req.url);

  try {
    await match.fn(req, res, { body, params: match.params, qs, user });
  } catch (e) {
    console.error('[Error]', req.method, urlPath, e.message);
    sendJson(res, { error: 'Internal server error' }, 500);
  }
});

// ── START ─────────────────────────────────────────────────────────────
initDb();

function migrateDb() {
  // Add new columns to store_orders (ignore error if already exist)
  try { db.exec(`ALTER TABLE store_orders ADD COLUMN delivery_status TEXT DEFAULT NULL`); } catch(e) {}
  try { db.exec(`ALTER TABLE store_orders ADD COLUMN whatsapp_sent INTEGER DEFAULT 0`); } catch(e) {}
  // Add client users
  const pwd = sha256('senha123');
  const logins = [
    ['carlos@marinaone.com','Carlos Eduardo Souza'],
    ['ana@marinaone.com','Ana Paula Ferreira'],
    ['roberto@marinaone.com','Roberto Alves Lima'],
    ['mariana@marinaone.com','Mariana Costa Pinto'],
    ['fernando@marinaone.com','Fernando Oliveira'],
    ['juliana@marinaone.com','Juliana Santos Cruz'],
    ['marcelo@marinaone.com','Marcelo Rodrigues'],
    ['patricia@marinaone.com','Patricia Mendes Luz'],
  ];
  for (const [email,name] of logins) {
    try { dbRun('INSERT INTO users(email,password_hash,name,role) VALUES(?,?,?,?)',[email,pwd,name,'client']); }
    catch(e) {}
  }
}
migrateDb();

// Run seed (wrapped to catch & report errors clearly)
try { seedDb(); }
catch (e) { console.error('[Seed Error]', e.message); process.exit(1); }

server.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log('  ⚓  Marina One — Sistema de Gestao de Marina');
  console.log('='.repeat(50));
  console.log(`\n✅ Rodando em: http://localhost:${PORT}`);
  console.log(`   Acesse  : http://localhost:${PORT}/frontend.html`);
  console.log(`   Login   : admin@marina.com / marina123`);
  console.log('\n   Ctrl+C para encerrar.\n');
});
