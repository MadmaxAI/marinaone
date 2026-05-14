'use strict';
// ── Co-piloto IA — Wrapper Claude API ────────────────────────────────
// Modelo: claude-haiku-4-5-20251001 (custo menor por token)
// Cada resposta retorna: { answer, components[] }
// READ-ONLY: apenas SELECT é aceito nos tool calls
// Schema: auto-descoberto do information_schema real do tenant a cada query
// ─────────────────────────────────────────────────────────────────────

const CLAUDE_MODEL = 'claude-haiku-4-5-20251001';
const MAX_TOKENS   = 4096;
const MAX_ITERS    = 5;

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

// ── Descobre o schema real do tenant via information_schema ───────────
async function discoverSchema(schema, dbAll) {
  try {
    const rows = await dbAll(
      `SELECT table_name, column_name, data_type
       FROM information_schema.columns
       WHERE table_schema = $1
       ORDER BY table_name, ordinal_position`,
      [schema]
    );

    if (!rows || rows.length === 0) return null;

    // Agrupa colunas por tabela
    const tables = {};
    for (const row of rows) {
      if (!tables[row.table_name]) tables[row.table_name] = [];
      tables[row.table_name].push(row.column_name);
    }

    // Formata como lista legível para o prompt
    const lines = Object.entries(tables).map(([tbl, cols]) =>
      `- ${tbl}: ${cols.join(', ')}`
    );
    return { tables: Object.keys(tables), text: lines.join('\n') };
  } catch {
    return null;
  }
}

// ── System prompt construído com schema real ──────────────────────────
function buildSystemPrompt(schema, schemaInfo, globalRules, tenantRules) {
  const schemaBlock = schemaInfo
    ? `SCHEMA REAL DO BANCO (obtido diretamente do banco de dados do tenant — use o schema: ${schema} — ex: ${schema}.clients):
Tabelas e colunas disponíveis:
${schemaInfo.text}`
    : `ATENÇÃO: Não foi possível ler o schema do banco. Use a ferramenta run_db_query para explorar as tabelas via information_schema antes de responder qualquer pergunta.`;

  const rulesBlock = (globalRules || tenantRules)
    ? `\nCONTEXTO E REGRAS DE NEGÓCIO:
${globalRules ? `-- Regras globais do sistema --\n${globalRules}` : ''}
${tenantRules ? `\n-- Regras específicas desta marina --\n${tenantRules}` : ''}`.trim()
    : '';

  return `Você é o Co-piloto IA da Marina One, assistente especializado em análise de dados de marinas náuticas.

${schemaBlock}
${rulesBlock}

REGRAS ABSOLUTAS — NUNCA VIOLE:
1. NUNCA invente, estime ou suponha dados. Todo número, nome ou valor que aparecer na sua resposta DEVE ter vindo de uma query executada com sucesso nesta conversa.
2. Se a query retornar erro (tabela inexistente, coluna inválida, etc.), diga exatamente: "Não consegui acessar esses dados: [motivo do erro]." Não tente responder com dados alternativos inventados.
3. Se não tiver certeza de qual tabela ou coluna usar, execute primeiro uma query de exploração (ex: SELECT * FROM ${schema}.nome_tabela LIMIT 1) para confirmar a estrutura.
4. Use APENAS queries SELECT — INSERT, UPDATE, DELETE e DDL são bloqueados automaticamente pelo sistema.
5. Sempre use LIMIT adequado (máximo 100 linhas por query).
6. Use apenas tabelas e colunas que existem no schema listado acima — não invente nomes.

REGRAS DE FORMATAÇÃO:
- Responda SEMPRE em português brasileiro
- Valores monetários: formato R$ X.XXX,XX — percentuais com %
- Seja direto e preciso — destaque os números mais importantes
- Use funções SQL padrão PostgreSQL (DATE_TRUNC, TO_CHAR, COALESCE, etc.)

FORMATO DE RESPOSTA OBRIGATÓRIO (JSON puro, sem markdown ao redor):
{
  "answer": "resposta em linguagem natural com os principais insights e números",
  "components": [
    { "type": "text", "content": "contexto ou insight adicional" },
    { "type": "chart", "chartType": "bar|line|pie|doughnut", "title": "título", "labels": ["A","B"], "datasets": [{"label": "série", "data": [0,0]}] },
    { "type": "table", "title": "título", "columns": ["Col1","Col2"], "rows": [["v1","v2"]] }
  ]
}
Inclua apenas os componentes que realmente agregam valor. Se só o texto basta, retorne "components": [].`;
}

// ── Executor de query seguro (só SELECT) ──────────────────────────────
async function execQuery(sql, dbAll, isSaas) {
  const normalized = (sql || '').trim();
  if (!/^SELECT\b/i.test(normalized)) {
    return { error: 'Apenas queries SELECT são permitidas.' };
  }
  // Bloqueia funções perigosas mesmo dentro de SELECT
  if (/\b(pg_terminate_backend|pg_reload_conf|pg_read_file|pg_ls_dir|copy\s*\(|dblink)\b/i.test(normalized)) {
    return { error: 'Query bloqueada por segurança.' };
  }
  // Tenant: bloqueia acesso ao schema saas.* e a outros schemas de tenant
  if (!isSaas && /\bsaas\s*\./i.test(normalized)) {
    return { error: 'Acesso ao schema saas não é permitido.' };
  }
  try {
    const rows = await dbAll(normalized, []);
    return { rows: rows.slice(0, 100), count: rows.length };
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

  // Descobre o schema real do tenant antes de qualquer interação com o Claude
  const schemaInfo = await discoverSchema(schema, dbAll);

  const client  = new AnthropicClass({ apiKey: apiKey.trim(), timeout: 90_000 });
  const system  = buildSystemPrompt(schema, schemaInfo, globalRules, tenantRules);
  const queryTool = buildQueryTool(isSaas);
  const messages = [{ role: 'user', content: question }];
  let inputTokens  = 0;
  let outputTokens = 0;

  for (let iter = 0; iter < MAX_ITERS; iter++) {
    const resp = await client.messages.create({
      model:      CLAUDE_MODEL,
      max_tokens: MAX_TOKENS,
      system,
      tools:      [queryTool],
      messages,
    });

    inputTokens  += resp.usage?.input_tokens  || 0;
    outputTokens += resp.usage?.output_tokens || 0;

    if (resp.stop_reason === 'end_turn') {
      const text = resp.content.find(c => c.type === 'text')?.text || '';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          const parsed = JSON.parse(jsonMatch[0]);
          if (parsed.answer !== undefined) {
            return { ...parsed, _tokens: { in: inputTokens, out: outputTokens } };
          }
        } catch {}
      }
      return {
        answer: text || 'Não foi possível gerar uma resposta.',
        components: [],
        _tokens: { in: inputTokens, out: outputTokens },
      };
    }

    if (resp.stop_reason === 'tool_use') {
      messages.push({ role: 'assistant', content: resp.content });
      const toolResults = [];
      for (const block of resp.content) {
        if (block.type !== 'tool_use') continue;
        const result = block.name === 'run_db_query'
          ? await execQuery(block.input.sql, dbAll, isSaas)
          : { error: 'Ferramenta desconhecida.' };
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
    _tokens: { in: inputTokens, out: outputTokens },
  };
}

module.exports = { runAiQuery };
