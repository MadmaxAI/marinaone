'use strict';
// ============================================================
//  Camada de compatibilidade SQLite → PostgreSQL
//
//  Mantém a API síncrona do SQLite (dbAll/dbGet/dbRun) mas
//  com versões async que usam postgres.js.
//
//  Conversões automáticas:
//    - Placeholders: ? → $1, $2, ...
//    - INSERT sem RETURNING → append RETURNING id
//    - INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
//    - datetime('now') / CURRENT_TIMESTAMP → NOW()
//    - strftime('%Y-%m-%d','now') → CURRENT_DATE
// ============================================================
const { getTenantPool, getGlobalPool } = require('./pool');

/**
 * Converte placeholders ? para $1, $2, ... (estilo PostgreSQL)
 */
function convertPlaceholders(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

/**
 * Normaliza SQL: converte expressões SQLite para PostgreSQL
 */
function normalizeSql(sql) {
  // Detecta INSERT OR IGNORE para adicionar ON CONFLICT DO NOTHING depois dos VALUES
  let processed = sql;
  const isInsertOrIgnore = /INSERT\s+OR\s+IGNORE\s+INTO/i.test(processed);

  return processed
    // INSERT OR IGNORE INTO → INSERT INTO  (ON CONFLICT adicionado pelo dbRun se necessário)
    .replace(/INSERT\s+OR\s+IGNORE\s+INTO/gi, isInsertOrIgnore ? 'INSERT_OR_IGNORE INTO' : 'INSERT INTO')
    // Marca especial → restaura e adiciona ON CONFLICT
    .replace(/INSERT_OR_IGNORE\s+INTO/gi, 'INSERT INTO')
    // Se era OR IGNORE, injeta ON CONFLICT DO NOTHING antes do RETURNING (se houver) ou no fim
    // Feito via flag no prepareSql
    // datetime('now') → NOW()
    .replace(/datetime\('now'\)/gi, 'NOW()')
    // strftime('%Y-%m-%d','now') → CURRENT_DATE como string
    .replace(/strftime\('%Y-%m-%d',\s*'now'\)/gi, "TO_CHAR(NOW(),'YYYY-MM-DD')")
    // strftime('%Y-%m-%d', campo) → TO_CHAR(campo, 'YYYY-MM-DD')
    .replace(/strftime\('%Y-%m-%d',\s*([^)]+)\)/gi, "TO_CHAR($1,'YYYY-MM-DD')")
    // strftime('%Y-%m', campo) → TO_CHAR(campo, 'YYYY-MM')
    .replace(/strftime\('%Y-%m',\s*([^)]+)\)/gi, "TO_CHAR($1,'YYYY-MM')")
    // DATE(col) — função SQLite → cast PostgreSQL (col)::date
    // Cuidado: não alterar literais de tipo "DATE" em DDL (CREATE TABLE), só chamadas de função
    .replace(/\bDATE\(([^)]+)\)/gi, '($1)::date');
}

/**
 * Retorna true se o SQL original continha INSERT OR IGNORE
 */
function isInsertOrIgnore(sql) {
  return /INSERT\s+OR\s+IGNORE\s+INTO/i.test(sql);
}

/**
 * Sanitiza array de parâmetros: converte undefined → null.
 * postgres.js rejeita undefined; SQLite aceitava silenciosamente.
 */
function sanitizeParams(params) {
  return (params || []).map(v => (v === undefined ? null : v));
}

/**
 * Normaliza um valor retornado pelo postgres.js para tipo JS compatível
 * com o que o SQLite retornava:
 *   - Date   → string ISO "YYYY-MM-DD" (DATE) ou "YYYY-MM-DD HH:MM:SS" (TIMESTAMP)
 *   - BigInt → Number
 *   - outros → inalterado
 */
function normalizeValue(v) {
  if (v instanceof Date) {
    // Se não tem componente de hora significativa → só a data
    if (v.getUTCHours() === 0 && v.getUTCMinutes() === 0 && v.getUTCSeconds() === 0 && v.getUTCMilliseconds() === 0) {
      return v.toISOString().slice(0, 10);
    }
    return v.toISOString().replace('T', ' ').slice(0, 19);
  }
  if (typeof v === 'bigint') return Number(v);
  return v;
}

/**
 * Normaliza todos os valores de uma linha retornada pelo banco.
 */
function normalizeRow(row) {
  const out = {};
  for (const key of Object.keys(row)) out[key] = normalizeValue(row[key]);
  return out;
}

/**
 * Prepara SQL para execução: normaliza + converte placeholders.
 * Se o SQL original era INSERT OR IGNORE, injeta ON CONFLICT DO NOTHING.
 */
function prepareSql(sql) {
  const wasIgnore = isInsertOrIgnore(sql);
  let pg = convertPlaceholders(normalizeSql(sql));
  if (wasIgnore && !/ON\s+CONFLICT/i.test(pg)) {
    // Insere ON CONFLICT DO NOTHING antes de RETURNING (se houver) ou no fim
    pg = pg.replace(/(RETURNING\s+\w+)/i, 'ON CONFLICT DO NOTHING $1').trim();
    if (!/ON\s+CONFLICT/i.test(pg)) pg = pg.trimEnd().replace(/;?\s*$/, '') + ' ON CONFLICT DO NOTHING';
  }
  return pg;
}

/**
 * Cria helpers dbAll/dbGet/dbRun para um tenant específico.
 * Todos os métodos são async.
 */
function createDbHelpers(tenantSlugOrPool) {
  const sql = typeof tenantSlugOrPool === 'string'
    ? getTenantPool(tenantSlugOrPool)
    : tenantSlugOrPool;

  /**
   * Executa query e retorna array de linhas
   */
  async function dbAll(query, params = []) {
    const pgQuery = prepareSql(query);
    try {
      const rows = await sql.unsafe(pgQuery, sanitizeParams(params));
      return Array.from(rows).map(normalizeRow);
    } catch (e) {
      console.error('[dbAll] Erro SQL:', pgQuery, '\nParams:', params, '\nErro:', e.message);
      throw e;
    }
  }

  /**
   * Executa query e retorna primeira linha (ou null)
   */
  async function dbGet(query, params = []) {
    const rows = await dbAll(query, params);
    return rows[0] || null;
  }

  /**
   * Executa query de escrita (INSERT/UPDATE/DELETE).
   * Para INSERT, retorna { lastInsertRowid, changes }.
   * Para UPDATE/DELETE, retorna { changes }.
   */
  async function dbRun(query, params = []) {
    const isInsert = /^\s*INSERT/i.test(query.trim());
    let pgQuery = prepareSql(query);

    // Para INSERT sem RETURNING, adiciona RETURNING * automaticamente.
    // Usamos * (não id) pois algumas tabelas usam chaves primárias não-id
    // (ex: settings usa key TEXT PRIMARY KEY, role_permissions usa (role,module)).
    if (isInsert && !/RETURNING/i.test(pgQuery)) {
      pgQuery = pgQuery.trimEnd().replace(/;?\s*$/, '') + ' RETURNING *';
    }

    try {
      const result = await sql.unsafe(pgQuery, sanitizeParams(params));
      const rows = Array.from(result).map(normalizeRow);
      return {
        lastInsertRowid: rows[0]?.id ? Number(rows[0].id) : null,
        changes: result.count || rows.length,
      };
    } catch (e) {
      console.error('[dbRun] Erro SQL:', pgQuery, '\nParams:', sanitizeParams(params), '\nErro:', e.message);
      throw e;
    }
  }

  return { dbAll, dbGet, dbRun, sql };
}

/**
 * Helpers para o schema saas (super-admin)
 */
function createSaasHelpers() {
  const pool = getGlobalPool();

  async function saasAll(query, params = []) {
    const pgQuery = prepareSql(query);
    const rows = await pool.unsafe(pgQuery, sanitizeParams(params));
    return Array.from(rows).map(normalizeRow);
  }

  async function saasGet(query, params = []) {
    const rows = await saasAll(query, params);
    return rows[0] || null;
  }

  async function saasRun(query, params = []) {
    const isInsert = /^\s*INSERT/i.test(query.trim());
    let pgQuery = prepareSql(query);
    if (isInsert && !/RETURNING/i.test(pgQuery)) {
      pgQuery = pgQuery.trimEnd().replace(/;?\s*$/, '') + ' RETURNING *';
    }
    const result = await pool.unsafe(pgQuery, sanitizeParams(params));
    const rows = Array.from(result).map(normalizeRow);
    return {
      lastInsertRowid: rows[0]?.id ? Number(rows[0].id) : null,
      changes: result.count || rows.length,
    };
  }

  return { saasAll, saasGet, saasRun, sql: pool };
}

module.exports = { createDbHelpers, createSaasHelpers };
