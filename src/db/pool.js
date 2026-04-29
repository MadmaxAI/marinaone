'use strict';
// ============================================================
//  Pool de conexões PostgreSQL — um pool por tenant
//  Usa postgres.js (porsager/postgres) — tag template API
// ============================================================
const postgres = require('postgres');

const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) throw new Error('DATABASE_URL não definida no ambiente');

// Pool compartilhado para operações globais (schema saas)
let _globalPool = null;

function getGlobalPool() {
  if (!_globalPool) {
    _globalPool = postgres(DB_URL, {
      max: 5,
      idle_timeout: 30,
      connect_timeout: 10,
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    });
  }
  return _globalPool;
}

// Cache: slug → postgres instance com search_path do tenant
const _tenantPools = new Map();

/**
 * Retorna uma instância postgres.js com search_path setado para o schema do tenant.
 * Reutiliza a instância em cache para o mesmo slug.
 */
// Converte slug para nome de schema PostgreSQL válido (sem hífens)
function slugToSchema(tenantSlug) {
  return `marina_${tenantSlug.replace(/-/g, '_')}`;
}

function getTenantPool(tenantSlug) {
  if (!_tenantPools.has(tenantSlug)) {
    const schemaName = slugToSchema(tenantSlug);
    const pool = postgres(DB_URL, {
      max: 10,
      idle_timeout: 30,
      connect_timeout: 10,
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
      connection: {
        search_path: `${schemaName},public`,
      },
    });
    _tenantPools.set(tenantSlug, pool);
  }
  return _tenantPools.get(tenantSlug);
}

/**
 * Remove um tenant do cache de pools (ex: quando é desativado)
 */
async function evictTenantPool(tenantSlug) {
  if (_tenantPools.has(tenantSlug)) {
    await _tenantPools.get(tenantSlug).end();
    _tenantPools.delete(tenantSlug);
  }
}

module.exports = { getGlobalPool, getTenantPool, evictTenantPool, slugToSchema };
