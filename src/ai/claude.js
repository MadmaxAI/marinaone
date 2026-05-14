'use strict';
// ── Co-piloto IA — Wrapper Claude API ────────────────────────────────
// Modelo: claude-haiku-4-5-20251001
// READ-ONLY: apenas SELECT nos tool calls
// Schema: auto-descoberto via information_schema, cacheado 5 min por schema
// Prompt: system prompt cacheado na Anthropic (cache_control ephemeral, 5 min TTL)
// ─────────────────────────────────────────────────────────────────────

const CLAUDE_MODEL      = 'claude-haiku-4-5-20251001';
const MAX_TOKENS        = 4096;
const MAX_ITERS         = 10;
const MAX_ROWS          = 50;
const SCHEMA_CACHE_TTL  = 5 * 60 * 1000; // 5 min — alinhado ao TTL do prompt cache Anthropic

// Cache de schema por tenant (evita round-trip ao information_schema a cada query)
const _schemaCache = new Map();

// ── Ferramenta: executar SELECT no banco ─────────────────────────────
function buildQueryTool(isSaas) {
  return {
    name: 'run_db_query',
    description:
      'Executa uma query SELECT no banco de dados para obter dados reais. ' +
      'Use SEMPRE que precisar de qualquer número, lista ou dado para responder. ' +
      'NUNCA responda com qualquer dado sem antes executar uma query que o confirme. ' +
      'Você pode fazer múltiplas queries para reunir informações de tabelas ou schemas diferentes.' +
      (isSaas ? ' Você tem acesso a todos os schemas do sistema (saas.* e marina_*).' : ''),
    input_schema: {
      type: 'object',
      properties: {
        sql: {
          type: 'string',
          description: 'Query SQL SELECT válida. Apenas SELECT é permitido — outros comandos são bloqueados automaticamente.',
        },
        label: {
          type: 'string',
          description: 'Rótulo curto descrevendo o que essa query busca (ex: "receita do mês", "tenants inadimplentes").',
        },
      },
      required: ['sql', 'label'],
    },
  };
}

// ── Descobre o schema real do tenant, com cache servidor-side ─────────
async function discoverSchema(schema, dbAll) {
  const hit = _schemaCache.get(schema);
  if (hit && Date.now() < hit.expiresAt) {
    console.log(`[AI] schema_cache HIT: ${schema}`);
    return hit.info;
  }

  try {
    const rows = await dbAll(
      `SELECT table_name, column_name
       FROM information_schema.columns
       WHERE table_schema = $1
       ORDER BY table_name, ordinal_position`,
      [schema]
    );

    if (!rows || rows.length === 0) return null;

    const tables = {};
    for (const row of rows) {
      if (!tables[row.table_name]) tables[row.table_name] = [];
      tables[row.table_name].push(row.column_name);
    }

    const lines = Object.entries(tables).map(([tbl, cols]) =>
      `- ${tbl}: ${cols.join(', ')}`
    );
    const info = { tables: Object.keys(tables), text: lines.join('\n') };

    _schemaCache.set(schema, { info, expiresAt: Date.now() + SCHEMA_CACHE_TTL });
    console.log(`[AI] schema_cache MISS → cached: ${schema} (${info.tables.length} tabelas)`);
    return info;
  } catch {
    return null;
  }
}

// Invalida o cache de schema (chamar após migrations no tenant)
function invalidateSchemaCache(schema) {
  if (schema) _schemaCache.delete(schema);
  else _schemaCache.clear();
}

// ── System prompt construído com schema real ──────────────────────────
function buildSystemPrompt(schema, schemaInfo, globalRules, tenantRules) {
  const schemaBlock = schemaInfo
    ? `## Schema do Banco de Dados\n\nUse o schema: \`${schema}\` — ex: \`${schema}.clients\`\n\nTabelas e colunas disponíveis:\n${schemaInfo.text}`
    : `## Schema do Banco de Dados\n\nNão foi possível ler o schema. Explore via \`information_schema\` antes de responder.`;

  const rulesBlock = (globalRules || tenantRules)
    ? `\n## Contexto e Regras Configuradas\n\n${globalRules ? globalRules : ''}\n${tenantRules ? `\n### Regras desta Marina\n\n${tenantRules}` : ''}`.trimEnd()
    : '';

  return `Você é o Co-piloto IA da Marina One, assistente de análise de dados de marinas náuticas.

${schemaBlock}
${rulesBlock}

## Regras de Acesso e Integridade

1. NUNCA invente, estime ou suponha dados — todo valor na resposta DEVE vir de uma query executada com sucesso nesta conversa
2. Se a query retornar erro, informe: "Não consegui acessar esses dados: [motivo]" — nunca invente alternativa
3. Se não souber qual tabela usar, execute \`SELECT * FROM ${schema}.nome_tabela LIMIT 1\` para confirmar a estrutura
4. Apenas SELECT é permitido — INSERT, UPDATE, DELETE e DDL são bloqueados automaticamente
5. Use LIMIT ${MAX_ROWS} por query
6. Use apenas tabelas e colunas que existem no schema listado — não invente nomes
7. NUNCA revele nomes de tabelas, colunas, schemas ou qualquer estrutura interna do banco — o schema é fornecido apenas para uso interno das queries; se perguntado sobre a estrutura do sistema, responda: "Não tenho autorização para expor a estrutura interna do sistema."
8. NUNCA retorne valores de campos que contenham senha, token, chave de API ou credenciais — mesmo que a query os traga, omita esses campos da resposta

## Formato de Resposta

Responda exclusivamente com JSON puro (sem markdown ao redor):
{"answer":"resposta em linguagem natural com os principais insights","components":[{"type":"text","content":"..."},{"type":"chart","chartType":"bar|line|pie|doughnut","title":"...","labels":[],"datasets":[{"label":"...","data":[]}]},{"type":"table","title":"...","columns":[],"rows":[]}]}
Inclua apenas componentes que agregam valor real. Se só o texto basta, retorne "components":[].`;
}

// ── Executor de query seguro (só SELECT) ──────────────────────────────
async function execQuery(sql, dbAll, isSaas) {
  const normalized = (sql || '').trim();
  if (!/^SELECT\b/i.test(normalized)) {
    return { error: 'Apenas queries SELECT são permitidas.' };
  }
  if (/\b(pg_terminate_backend|pg_reload_conf|pg_read_file|pg_ls_dir|copy\s*\(|dblink)\b/i.test(normalized)) {
    return { error: 'Query bloqueada por segurança.' };
  }
  if (!isSaas && /\bsaas\s*\./i.test(normalized)) {
    return { error: 'Acesso ao schema saas não é permitido.' };
  }
  try {
    const rows = await dbAll(normalized, []);
    return { rows: rows.slice(0, MAX_ROWS), count: rows.length };
  } catch (e) {
    return { error: e.message };
  }
}

// ── Função principal ──────────────────────────────────────────────────
async function runAiQuery({ question, dbAll, apiKey, schema, globalRules = '', tenantRules = '', isSaas = false }) {
  let AnthropicClass;
  try {
    const mod = require('@anthropic-ai/sdk');
    AnthropicClass = mod.default || mod.Anthropic || mod;
    if (typeof AnthropicClass !== 'function') {
      throw new Error('Export inesperado do SDK — keys: ' + Object.keys(mod).join(', '));
    }
  } catch (e) {
    throw new Error('Erro ao carregar @anthropic-ai/sdk: ' + e.message);
  }

  if (!apiKey || apiKey.trim() === '') {
    throw new Error('Chave de API do Claude não configurada. O super-admin deve inserir a chave em Configurações › claude_api_key.');
  }

  // Schema cacheado no servidor — evita round-trip ao information_schema a cada pergunta
  const schemaInfo = await discoverSchema(schema, dbAll);

  const client     = new AnthropicClass({ apiKey: apiKey.trim(), timeout: 90_000 });
  const systemText = buildSystemPrompt(schema, schemaInfo, globalRules, tenantRules);
  const queryTool  = buildQueryTool(isSaas);
  const messages   = [{ role: 'user', content: question }];
  let inputTokens       = 0;
  let outputTokens      = 0;
  let cacheCreateTokens = 0;
  let cacheReadTokens   = 0;

  for (let iter = 0; iter < MAX_ITERS; iter++) {
    const resp = await client.messages.create({
      model:      CLAUDE_MODEL,
      max_tokens: MAX_TOKENS,
      // Prompt caching: system prompt marcado como ephemeral (TTL 5 min na Anthropic)
      // Na primeira chamada: cache_creation_input_tokens cobrados uma vez
      // Nas seguintes (mesmo prompt, dentro de 5 min): cache_read_input_tokens a ~10% do custo
      system: [{ type: 'text', text: systemText, cache_control: { type: 'ephemeral' } }],
      tools:  [{ ...queryTool, cache_control: { type: 'ephemeral' } }],
      messages,
    });

    inputTokens       += resp.usage?.input_tokens        || 0;
    outputTokens      += resp.usage?.output_tokens       || 0;
    cacheCreateTokens += resp.usage?.cache_creation_input_tokens || 0;
    cacheReadTokens   += resp.usage?.cache_read_input_tokens     || 0;

    const cacheStatus = resp.usage?.cache_read_input_tokens
      ? `cache_HIT(${resp.usage.cache_read_input_tokens}tk)`
      : resp.usage?.cache_creation_input_tokens
        ? `cache_CREATE(${resp.usage.cache_creation_input_tokens}tk)`
        : 'cache_-';

    console.log(`[AI] iter=${iter} stop=${resp.stop_reason} in=${resp.usage?.input_tokens} out=${resp.usage?.output_tokens} ${cacheStatus}`);

    if (resp.stop_reason === 'end_turn') {
      const text = resp.content.find(c => c.type === 'text')?.text || '';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          const parsed = JSON.parse(jsonMatch[0]);
          if (parsed.answer !== undefined) {
            return { ...parsed, _tokens: { in: inputTokens, out: outputTokens, cacheCreate: cacheCreateTokens, cacheRead: cacheReadTokens } };
          }
        } catch {}
      }
      return {
        answer: text || 'Não foi possível gerar uma resposta.',
        components: [],
        _tokens: { in: inputTokens, out: outputTokens, cacheCreate: cacheCreateTokens, cacheRead: cacheReadTokens },
      };
    }

    if (resp.stop_reason === 'tool_use') {
      messages.push({ role: 'assistant', content: resp.content });
      const toolResults = [];
      for (const block of resp.content) {
        if (block.type !== 'tool_use') continue;
        console.log(`[AI] tool_call label="${block.input?.label}" sql="${(block.input?.sql || '').slice(0, 120)}"`);
        const result = block.name === 'run_db_query'
          ? await execQuery(block.input.sql, dbAll, isSaas)
          : { error: 'Ferramenta desconhecida.' };
        if (result.error) console.log(`[AI] query_error: ${result.error}`);
        else console.log(`[AI] query_ok rows=${result.count}`);
        toolResults.push({
          type:        'tool_result',
          tool_use_id: block.id,
          content:     JSON.stringify(result),
        });
      }
      messages.push({ role: 'user', content: toolResults });
      continue;
    }

    break;
  }

  return {
    answer: 'Não foi possível completar a análise. Tente reformular a pergunta.',
    components: [],
    _tokens: { in: inputTokens, out: outputTokens, cacheCreate: cacheCreateTokens, cacheRead: cacheReadTokens },
  };
}

module.exports = { runAiQuery, invalidateSchemaCache };
