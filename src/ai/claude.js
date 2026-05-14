'use strict';
// ── Co-piloto IA — Wrapper Claude API ────────────────────────────────
// Modelo: claude-haiku-4-5-20251001 (custo menor por token)
// Cada resposta retorna: { answer, components[] }
// READ-ONLY: apenas SELECT é aceito nos tool calls
// ─────────────────────────────────────────────────────────────────────

const CLAUDE_MODEL = 'claude-haiku-4-5-20251001';
const MAX_TOKENS   = 4096;
const MAX_ITERS    = 5;

// ── Ferramenta: executar SELECT no banco do tenant ────────────────────
const DB_QUERY_TOOL = {
  name: 'run_db_query',
  description:
    'Executa uma query SELECT no banco de dados da marina para obter dados reais. ' +
    'Use sempre que precisar de números, listas ou qualquer dado para responder à pergunta. ' +
    'Você pode fazer múltiplas queries para reunir diferentes informações.',
  input_schema: {
    type: 'object',
    properties: {
      sql: {
        type: 'string',
        description: 'Query SQL SELECT válida. Apenas SELECT é permitido — outros comandos são bloqueados.',
      },
      label: {
        type: 'string',
        description: 'Rótulo curto descrevendo o que essa query busca (ex: "receita do mês", "clientes inadimplentes").',
      },
    },
    required: ['sql', 'label'],
  },
};

// ── System prompt com schema do banco ────────────────────────────────
function buildSystemPrompt(schema) {
  return `Você é o Co-piloto IA da Marina One, assistente especializado em análise de dados de marinas náuticas.

SCHEMA DO BANCO DE DADOS (use o schema: ${schema} — ex: ${schema}.clients):
Tabelas disponíveis:
- clients: id, name, cpf_cnpj, email, phone, tier (standard/gold/vip), ltv, active, created_at
- vessels: id, name, owner_id (= client_id), type, eslora_ft, active, in_water, photo_url
- spots: id, name, type (seca/molhada), status (available/occupied/maintenance), vessel_id
- contracts: id, client_id, vessel_id, spot_id, type (seca/molhada), monthly_value, start_date, end_date, status (active/cancelled)
- financial_charges: id, contract_id, description, amount, due_date, paid_date, status (pending/paid/overdue/cancelled)
- queue_items: id, vessel_id, type (descida/subida/atracacao), status (waiting/in_progress/completed/cancelled), queue_order, scheduled_time, completed_at, created_at
- store_items: id, name, category, price, stock, stock_min, active
- store_orders: id, total, status (open/pending_payment/paid/cancelled), source (totem/self_service/pdv), created_at
- store_order_items: id, order_id, item_id, qty, unit_price
- maintenance_items: id, vessel_id, type, status (open/in_progress/completed), priority, description, created_at, completed_at

REGRAS OBRIGATÓRIAS:
1. Use APENAS queries SELECT — INSERT, UPDATE, DELETE e DDL são bloqueados
2. Sempre use LIMIT adequado (máximo 100 linhas por query)
3. Use funções SQL padrão PostgreSQL (DATE_TRUNC, TO_CHAR, COALESCE, etc.)
4. Responda SEMPRE em português brasileiro
5. Valores monetários: formato R$ X.XXX,XX — percentuais com %
6. Seja direto e preciso — destaque os números mais importantes

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
async function execQuery(sql, dbAll) {
  const normalized = (sql || '').trim();
  if (!/^SELECT\b/i.test(normalized)) {
    return { error: 'Apenas queries SELECT são permitidas.' };
  }
  // Bloqueia funções perigosas mesmo dentro de SELECT
  if (/\b(pg_terminate_backend|pg_reload_conf|pg_read_file|pg_ls_dir|copy\s+\(|dblink)\b/i.test(normalized)) {
    return { error: 'Query bloqueada por segurança.' };
  }
  try {
    const rows = await dbAll(normalized, []);
    return { rows: rows.slice(0, 100), count: rows.length };
  } catch (e) {
    return { error: e.message };
  }
}

// ── Função principal ──────────────────────────────────────────────────
async function runAiQuery({ question, dbAll, apiKey, schema }) {
  let AnthropicClass;
  try {
    const mod = require('@anthropic-ai/sdk');
    // Suporta tanto CJS direto quanto ESM default export
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

  // timeout: 90s — evita loading eterno se a rede falhar
  const client = new AnthropicClass({ apiKey: apiKey.trim(), timeout: 90_000 });
  const system = buildSystemPrompt(schema);
  const messages = [{ role: 'user', content: question }];
  let inputTokens = 0;
  let outputTokens = 0;

  for (let iter = 0; iter < MAX_ITERS; iter++) {
    const resp = await client.messages.create({
      model:      CLAUDE_MODEL,
      max_tokens: MAX_TOKENS,
      system,
      tools:      [DB_QUERY_TOOL],
      messages,
    });

    inputTokens  += resp.usage?.input_tokens  || 0;
    outputTokens += resp.usage?.output_tokens || 0;

    if (resp.stop_reason === 'end_turn') {
      const text = resp.content.find(c => c.type === 'text')?.text || '';
      // Tenta extrair JSON da resposta
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
          ? await execQuery(block.input.sql, dbAll)
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
