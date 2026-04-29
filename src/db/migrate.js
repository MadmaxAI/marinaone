'use strict';
// ============================================================
//  Runner de migrações + provisionamento de tenant
// ============================================================
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getGlobalPool, getTenantPool, slugToSchema } = require('./pool');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const SAAS_SCHEMA    = path.join(__dirname, 'saas_schema.sql');

// ── SHA-256 simples (usado para senha inicial) ────────────────────────
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// ── Inicializa schema global saas ─────────────────────────────────────
async function initSaasSchema() {
  const pool = getGlobalPool();
  const sql  = fs.readFileSync(SAAS_SCHEMA, 'utf8');
  await pool.unsafe(sql);

  // Garante que o super-admin padrão existe
  const adminEmail = process.env.SUPER_ADMIN_EMAIL || 'arthur@marinaone.com.br';
  const adminPwd   = process.env.SUPER_ADMIN_PASSWORD || 'SaaS@Marina2025!';
  const adminName  = 'Arthur Noli (SaaS Admin)';
  const hash       = sha256(adminPwd);

  await pool.unsafe(
    `INSERT INTO saas.super_admins(email, password_hash, name)
     VALUES($1, $2, $3)
     ON CONFLICT (email) DO NOTHING`,
    [adminEmail, hash, adminName]
  );
  console.log('[migrate] Schema saas inicializado.');
}

// ── Executa migrações para um schema de tenant ────────────────────────
async function runMigrations(tenantSlug) {
  const pool       = getTenantPool(tenantSlug);
  const schemaName = slugToSchema(tenantSlug); // hífens → underscores

  // Garante que o schema existe
  await pool.unsafe(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);
  await pool.unsafe(`SET search_path TO "${schemaName}", public`);

  // Lê arquivos de migração em ordem
  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    // Verifica se já foi aplicada (tabela _migrations pode não existir ainda)
    let alreadyApplied = false;
    try {
      const rows = await pool.unsafe(
        `SELECT 1 FROM _migrations WHERE filename = $1`,
        [file]
      );
      alreadyApplied = rows.length > 0;
    } catch (_) {
      // Tabela _migrations ainda não existe — primeira migração cria ela
    }

    if (alreadyApplied) continue;

    const sqlContent = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
    await pool.unsafe(sqlContent);

    // Registra migração aplicada
    try {
      await pool.unsafe(
        `INSERT INTO _migrations(filename) VALUES($1) ON CONFLICT DO NOTHING`,
        [file]
      );
    } catch (_) {}

    console.log(`[migrate] ${tenantSlug}: migração ${file} aplicada.`);
  }
}

// ── Seed de dados iniciais para o tenant ─────────────────────────────
async function seedTenant(tenantSlug, opts = {}) {
  const pool = getTenantPool(tenantSlug);

  // Verifica se já tem usuários
  const rows = await pool.unsafe(`SELECT COUNT(*) as n FROM users`);
  const count = Number(rows[0].n);
  if (count > 0) return; // já tem dados

  const adminEmail = opts.adminEmail || 'admin@marina.com';
  const adminName  = opts.adminName  || 'Administrador';
  const adminPwd   = opts.adminPassword || 'marina123';

  // Admin principal
  await pool.unsafe(
    `INSERT INTO users(email, password_hash, name, role, active)
     VALUES($1, $2, $3, 'admin', 1)`,
    [adminEmail, sha256(adminPwd), adminName]
  );

  // Operador padrão
  await pool.unsafe(
    `INSERT INTO users(email, password_hash, name, role, active)
     VALUES($1, $2, 'Operador Padrão', 'operador', 1)
     ON CONFLICT (email) DO NOTHING`,
    ['operador@marina.com', sha256('operador123')]
  );

  // Usuário loja
  await pool.unsafe(
    `INSERT INTO users(email, password_hash, name, role, active)
     VALUES($1, $2, 'Atendente Loja', 'loja', 1)
     ON CONFLICT (email) DO NOTHING`,
    ['loja@marina.com', sha256('loja123')]
  );

  // Permissões padrão
  await seedDefaultPermissions(pool);

  // Configurações padrão
  const marinaName = opts.marinaName || 'Marina One';
  const defSettings = [
    ['marina_name',  marinaName],
    ['marina_logo',  opts.logo_base64 || ''],
    ['marina_cnpj', '00.000.000/0001-00'],
    ['marina_address', 'Av. do Porto, 100'],
    ['marina_phone', '(11) 99999-0000'],
    ['marina_whatsapp', '5511999990000'],
    ['marina_email', 'contato@marinaone.com'],
    ['marina_city', 'São Paulo'],
    ['marina_state', 'SP'],
    ['marina_cep', '01000-000'],
    ['bank_name', 'Banco do Brasil'],
    ['bank_agency', '1234-5'],
    ['bank_account', '00000-0'],
    ['bank_pix_key', '11999990000'],
    ['bank_pix_type', 'telefone'],
    ['bank_pix_beneficiary', `${marinaName} LTDA`],
    ['store_whatsapp', '5511999990000'],
    ['store_whatsapp_template', 'Olá {cliente}! Segue seu orçamento da {marina}:\n\n🛥️ Embarcação: {embarcacao}\n📋 Itens: {itens}\n💰 Total: {total}\n\nPara pagamento via PIX:\nChave: {pix_key}\n\nApós o pagamento, envie o comprovante para este número. Obrigado!'],
    ['license_plan', 'professional'],
    ['license_valid_until', '2027-12-31'],
    ['avg_time_descida_pequena', '20'], ['avg_time_descida_media', '35'], ['avg_time_descida_grande', '60'],
    ['avg_time_subida_pequena', '20'],  ['avg_time_subida_media', '35'],  ['avg_time_subida_grande', '60'],
    ['avg_time_atracacao_pequena', '15'], ['avg_time_atracacao_media', '25'], ['avg_time_atracacao_grande', '40'],
    ['maneuver_time_min', '10'],
    ['ops_start_time', '07:00'],
    ['ops_end_time', '18:00'],
    ['checklist_descida', '["Verificar condições do cais e amarras","Conferir equipamentos de içamento","Checar comunicação com a equipe","Confirmar profundidade e maré","Verificar documentação da embarcação"]'],
    ['checklist_subida', '["Verificar condições do cais e amarras","Confirmar disponibilidade de vaga em terra","Checar equipamentos de içamento","Avisar cliente sobre retirada","Inspecionar casco antes de içar"]'],
    ['checklist_atracacao', '["Verificar disponibilidade da vaga","Conferir amarras e defensas","Checar condições climáticas","Confirmar calado da embarcação","Orientar tripulação sobre manobra"]'],
  ];

  for (const [k, v] of defSettings) {
    await pool.unsafe(
      `INSERT INTO settings(key, value) VALUES($1, $2) ON CONFLICT (key) DO NOTHING`,
      [k, v]
    );
  }

  console.log(`[seed] Tenant ${tenantSlug}: dados iniciais criados.`);
}

// ── Permissões padrão por role ────────────────────────────────────────
async function seedDefaultPermissions(pool) {
  const perms = {
    operador: {
      dashboard: [1,0,0,0], queue: [1,1,1,1], clients: [1,1,1,0], vessels: [1,1,1,0],
      spots: [1,0,0,0], contracts: [0,0,0,0], financial: [0,0,0,0], store: [1,1,1,0],
      maintenance: [1,1,1,1], analytics: [0,0,0,0], alerts: [1,0,1,0], settings: [0,0,0,0],
    },
    loja: {
      dashboard: [1,0,0,0], queue: [0,0,0,0], clients: [1,0,0,0], vessels: [1,0,0,0],
      spots: [0,0,0,0], contracts: [0,0,0,0], financial: [0,0,0,0], store: [1,1,1,0],
      maintenance: [0,0,0,0], analytics: [0,0,0,0], alerts: [1,0,0,0], settings: [0,0,0,0],
    },
    cliente: {
      dashboard: [1,0,0,0], queue: [1,0,0,0], clients: [1,0,0,0], vessels: [1,0,0,0],
      spots: [1,0,0,0], contracts: [1,0,0,0], financial: [1,0,0,0], store: [1,1,0,0],
      maintenance: [1,0,0,0], analytics: [0,0,0,0], alerts: [1,0,0,0], settings: [0,0,0,0],
    },
  };

  for (const [role, modules] of Object.entries(perms)) {
    for (const [mod, [v, c, e, d]] of Object.entries(modules)) {
      await pool.unsafe(
        `INSERT INTO role_permissions(role, module, can_view, can_create, can_edit, can_delete)
         VALUES($1, $2, $3, $4, $5, $6)
         ON CONFLICT (role, module) DO NOTHING`,
        [role, mod, v, c, e, d]
      );
    }
  }
}

// ── Seed de vagas (secas e molhadas) ─────────────────────────────────
async function seedSpots(tenantSlug, opts = {}) {
  const pool     = getTenantPool(tenantSlug);
  const qtdSeca  = parseInt(opts.spots_seca   || 0, 10);
  const qtdMolh  = parseInt(opts.spots_molhada || 0, 10);

  if (qtdSeca <= 0 && qtdMolh <= 0) return;

  // Verifica se já existem vagas (idempotente)
  const existing = await pool.unsafe(`SELECT COUNT(*) as n FROM spots`);
  if (Number(existing[0]?.n) > 0) {
    console.log(`[spots] Tenant ${tenantSlug}: vagas já existem, pulando seed.`);
    return;
  }

  // Largura do padding baseada no total de vagas de cada tipo
  const pad = (n, total) => String(n).padStart(total > 99 ? 3 : 2, '0');

  for (let i = 1; i <= qtdSeca; i++) {
    await pool.unsafe(
      `INSERT INTO spots(number, type, status) VALUES($1, 'seca', 'available')`,
      [`S${pad(i, qtdSeca)}`]
    );
  }
  for (let i = 1; i <= qtdMolh; i++) {
    await pool.unsafe(
      `INSERT INTO spots(number, type, status) VALUES($1, 'molhada', 'available')`,
      [`M${pad(i, qtdMolh)}`]
    );
  }

  console.log(`[spots] Tenant ${tenantSlug}: ${qtdSeca} vagas secas + ${qtdMolh} molhadas criadas.`);
}

// ── Provisiona um novo tenant (cria schema + migra + seed) ───────────
async function provisionTenant(slug, opts = {}) {
  console.log(`[provision] Provisionando tenant: ${slug}`);

  // 1. Registra no schema saas
  const globalPool = getGlobalPool();
  const existing = await globalPool.unsafe(
    `SELECT id FROM saas.tenants WHERE slug = $1`,
    [slug]
  );
  if (existing.length === 0) {
    await globalPool.unsafe(
      `INSERT INTO saas.tenants(slug, name, plan) VALUES($1, $2, $3)`,
      [slug, opts.marinaName || slug, opts.plan || 'professional']
    );
  }

  // 2. Cria schema + roda migrações
  await runMigrations(slug);

  // 3. Seed dados iniciais (usuários, permissões, configurações)
  await seedTenant(slug, opts);

  // 4. Seed de vagas (se informado)
  await seedSpots(slug, opts);

  console.log(`[provision] Tenant ${slug} pronto!`);
}

module.exports = { initSaasSchema, runMigrations, provisionTenant, seedTenant, seedSpots, seedDefaultPermissions };
