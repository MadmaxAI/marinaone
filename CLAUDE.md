# Marina One — Regras Específicas do Projeto

> Regras universais (tratamento CEO, deploy genérico, segurança, design, escalabilidade, impacto sistêmico)
> estão em `~/.claude/CLAUDE.md` e se aplicam a todas as sessões.

---

## Fluxo de Deploy — Marina One

```
Claude altera código
        ↓
Claude roda: testar.bat          ← bumpa versão + reconstrói Docker
        ↓
Claude diz: "Teste em localhost:3000 (vX.Y.Z) e diga 'aprovado'"
        ↓
CEO testa e diz: "aprovado"
        ↓
Claude roda: publicar.bat "descrição"   ← commita e pusha (sem novo bump)
        ↓
Deploy automático no Railway ✅
Localhost e produção ambos em vX.Y.Z ✅
```

- **NUNCA** rodar `publicar.bat` sem aprovação explícita do CEO
- **NUNCA** rodar `testar.bat` depois de `publicar.bat` — bumpa a versão desnecessariamente

Formato obrigatório ao avisar para testar: **"Alteração feita. Teste em http://localhost:3000 (vX.Y.Z) e me diga 'aprovado' para publicar."**

Formato ao confirmar publicação: **"Publicado vX.Y.Z — localhost e produção ambos em vX.Y.Z."**

---

## ⚠️ REGRA CRÍTICA — Consistência Banco + Código

### Princípio
Toda alteração de schema (nova coluna, nova tabela, novo índice) DEVE ter uma migration SQL. **A produção só pode receber código que o banco consegue executar.**

### Regra ao criar migration nova
1. Criar em `src/db/migrations/NNN_descricao.sql` com `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
2. Verificar que o `boot()` em `server.js` roda `runMigrations(slug)` para todos os tenants
3. Testar com `testar.bat` — confirmar nos logs que a migration foi aplicada
4. Nunca alterar `server.js` ou `frontend.html` para usar colunas novas sem a migration correspondente **no mesmo commit**

### O boot DEVE sempre:
1. Inicializar o schema `saas` (`initSaasSchema`)
2. Se `SINGLE_TENANT_SLUG` definido: provisionar o tenant local
3. Rodar `runMigrations(slug)` para **todos** os tenants existentes em `saas.tenants`

### Padrão dos arquivos de migration
```
src/db/migrations/
  001_initial_schema.sql
  002_user_password_reset.sql
  003_vessel_photo_rental.sql
  004_proxima_feature.sql   ← sempre incrementar
```

Cada arquivo deve ser **idempotente** (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`).

### Checklist antes de publicar feature com banco novo:
- [ ] Migration criada com `IF NOT EXISTS`
- [ ] Boot percorre todos os tenants e aplica migrations pendentes
- [ ] `testar.bat` rodado e logs mostram migration aplicada
- [ ] Funcionalidade testada em localhost
- [ ] CEO aprovou

---

## ⚠️ REGRA CRÍTICA — Catálogo de Módulos SaaS

### Princípio
O catálogo de módulos em `saas.modules` representa **funcionalidades reais implementadas no código**. Slug e nome são referenciados diretamente via `requireModule(slug)` e nunca devem ser criados/alterados pela UI — apenas via código.

### Regra obrigatória
**Toda vez que uma nova funcionalidade/módulo for criada ou alterada no sistema, o seguinte DEVE ser atualizado no mesmo commit:**

1. `src/db/saas_schema.sql` — adicionar o módulo no bloco `INSERT INTO saas.modules(...)` com `ON CONFLICT (slug) DO NOTHING`
2. Associar o módulo aos tipos de licença corretos no bloco `DO $$ ... license_type_modules ...`
3. Atualizar o `ROADMAP.md` — catálogo de módulos e tabela de planos
4. Se o módulo tiver gate de acesso: usar `requireModule('slug')` na rota correspondente do `server.js`

### O que é editável via UI (Super Admin):
- Descrição (texto informativo)
- Categoria (agrupamento visual: core / premium / ai / enterprise)
- Flag `has_ext_cost` (se o módulo gera custo externo, ex: Claude API)
- Toggle ativo/inativo (ocultar do catálogo de licenças sem remover do banco)

### O que NUNCA é editável via UI:
- `slug` — identificador usado no código; alterar quebra o `requireModule()`
- `name` — nome canônico do módulo; alterações só via seed/migration

---

## Regras de Produto — Domínio Marina One

### Papéis de usuário (VALID_ROLES)
| Papel | Acesso |
|-------|--------|
| `admin` | Acesso total a todos os módulos |
| `operador` | Operações e fila; sem acesso financeiro |
| `loja` | Loja/PDV e conveniência |
| `cliente` | Somente os próprios dados (vessels, contracts, queue, financial, conveniência) |
| `totem` | Somente módulo totem (conveniência modo kiosk) |

Papel `cliente` é filtrado por `client_id` em **todas** as queries — nunca retornar dados de outros clientes.

### Vagas (spots)
- Tipos válidos: `seca` e `molhada`
- Status válidos: `available` → `occupied` | `maintenance`
- Uma vaga comporta **no máximo uma embarcação** (`spots.vessel_id`)

### Contratos
- **Um contrato ativo por embarcação**
- **Um cliente pode ter múltiplos contratos** — um por embarcação
- Status válidos: `active` → `cancelled`
- **Ao criar contrato com vaga:** atualizar `spots.status='occupied'` e `spots.vessel_id=vessel_id`
- **Ao cancelar contrato:**
  1. Bloquear se houver parcelas vencidas não pagas
  2. Exigir justificativa obrigatória
  3. Cancelar parcelas futuras pendentes (`status='cancelled'`)
  4. Liberar vaga: `spots.status='available'`, `spots.vessel_id=NULL`
  5. Registrar em `system_logs`
- **Ao criar contrato:** gerar mensalidades mensais automaticamente
  - Sem data de término: até 31/12 do ano corrente
  - Com data de término: do início até o término (máximo 60 parcelas)

### Fila de operações
- **State machine:** `waiting` → `in_progress` → `completed` | `cancelled`
- `DELETE /api/queue/:id` faz soft delete: `status='cancelled'` — nunca apaga a linha
- `queue_order ASC` = mais antigo na frente (FIFO)
- `MAX(queue_order)` deve usar `WHERE status NOT IN ('completed','cancelled')`
- **Uma operação ativa por embarcação:** não permitir nova op se já existe `status IN ('waiting','in_progress')`
- `descida` só permitida se embarcação **não** está na água; `subida` só se **está** na água
- Estado da embarcação verificado por `isVesselInWater()` — nunca replicar essa lógica
- Horário de operações configurável: `ops_start_time` / `ops_end_time` (padrão 07:00–18:00)
- Tempo de manobra configurável: `maneuver_time_min`

### Notificações da fila (queue_notices)
- Para `role='cliente'`: exibir **apenas** notices onde o cliente tinha operação com `id <= max_op_id` no momento da criação

### Financeiro
- Status de cobrança: `pending` → `paid` | `overdue` | `cancelled`
- Ao marcar `paid`: preencher `paid_date` automaticamente com a data de hoje

### Loja / Conveniência / Totem
- **Estoque nunca negativo:** usar `GREATEST(0, stock - qty)` ao debitar
- `source` dos pedidos: `totem`, `self_service`, `pdv`
- Status de pedido: `open`, `pending_payment`, `paid`, `cancelled`
- `delivery_status`: `null` → `preparando` → `entregando` → `entregue`
- Conveniência e Totem usam o **mesmo catálogo** (`/api/conveniencia/catalog`) — qualquer alteração na loja reflete em ambos

---

## Arquitetura — Fontes de Verdade (Marina One)

| Dado | Campo canônico | Nunca usar como alternativa |
|------|---------------|----------------------------|
| Vaga de um contrato | `contracts.spot_id` | `spots.vessel_id` para inferir vaga |
| Embarcação de uma vaga | `spots.vessel_id` | Inferir via contrato ativo |
| Estado na água (embarcação) | `isVesselInWater()` em server.js | Replicar essa lógica em outro lugar |
| Permissões de papel | tabela `role_permissions` | Hard-code por role no código |
| Versão do sistema | `package.json` → `APP_VERSION` | Qualquer outra fonte |

### Consistência de API
Toda rota GET deve retornar **todos os campos** que qualquer tela pode precisar. Proibido SELECT parcial por tela.

### Cache do frontend — invalidação obrigatória
| Cache | Zerrar quando |
|-------|--------------|
| `_convCatalog` | `saveItem()`, `deleteItem()` |
| Qualquer cache futuro | Na função `save*()` e `delete*()` correspondente |

### Consultas no contexto de tenant
- Usar **sempre** `ctx.db.dbAll / dbGet / dbRun` nas rotas de tenant
- Nunca chamar o pool global diretamente dentro de uma rota autenticada

---

## Design — Classes CSS do Projeto

| Elemento | Classes disponíveis |
|----------|-------------------|
| Badges | `badge-success` (verde), `badge-info` (azul), `badge-warning` (amarelo), `badge-gray` (neutro), `badge-danger` (vermelho) |
| Botões | `btn-primary`, `btn-ghost`, `btn-danger`, `btn-sm` |
| Tabelas | `thead` fixo + `tbody` scrollável; `colspan` DEVE ser atualizado ao adicionar/remover colunas |
| Layout | `card`, `card-header`, `card-body`; sidebar + topbar fixos |

---

## Segurança — Status Marina One

### Implementado (v2.3.14 — não reverter)
- **Senhas:** bcrypt 10 rounds. Hashes SHA-256 legados migram automaticamente para bcrypt no primeiro login
- **JWT_SECRET:** obrigatório via env var; servidor recusa iniciar sem ela
- **Rate limiting:** 10 tentativas de login por IP a cada 15 minutos

### Pendente (priorizar antes de 10+ tenants)
| Item | Risco |
|------|-------|
| CORS `*` | Baixo — restringir para `*.marinaone.com.br` em produção |
| `?tenant=` em produção | Baixo — desabilitar via Cloudflare Worker |
| Pool por tenant (max 10) | **Alto a 8+ tenants** — PgBouncer ou pool compartilhado |
| `admin_password_plain` em `saas.tenants` | **Alto** — migrar para entrega segura fora do banco |

### Rotas públicas (exatamente estas — não adicionar sem deliberação)
`/api/auth/login`, `/api/version`, `/api/brand`, `/api/conveniencia/catalog`, `/api/conveniencia/order`

---

## Escalabilidade — Contexto Railway Hobby

Estado atual: Railway Hobby (US$5/mês) — adequado para até ~8 tenants ativos.
Limite crítico: pool por tenant `max: 10` conexões — PostgreSQL esgota a ~8–10 tenants.

| Sinal | Ação |
|-------|------|
| 8+ tenants ativos | PgBouncer ou pool compartilhado |
| 2+ instâncias Railway | Redis para `_tenantCache` e rate limiting |

---

## Decisões Técnicas Relevantes

### Por que `compat.js` existe
Migração de SQLite para PostgreSQL. A camada traduz sintaxe SQLite (`?`, `INSERT OR IGNORE`, `datetime('now')`) para PostgreSQL. É intencional — não remover.

### Timezone UTC-3 fixo
`BRT_OFFSET_MS = -3 * 60 * 60 * 1000` é **intencional**. Brasil aboliu horário de verão em 2019. Não "corrigir" para biblioteca de timezone.

### `admin_password_plain` em `saas.tenants`
Existe para o painel super-admin exibir credenciais de acesso de cada marina ao CEO. Não remover sem solução alternativa de exibição.

### Adicionar pacote npm — procedimento obrigatório
Docker usa volume anônimo para `node_modules` que não é atualizado no rebuild normal.
```bash
docker compose rm -fsv app   # remove container + volume anônimo
docker compose up -d          # recria com o novo pacote
```

### Histórico de inconsistências já corrigidas (não reincidir)
| Inconsistência | Solução |
|---------------|---------|
| Contratos mostrando vaga sem `spot_id` | Removido fallback; `contracts.spot_id` é fonte única |
| Fotos ausentes em conveniência/totem | Todo SELECT de recurso compartilhado retorna campos completos |
| Fila com ordem invertida | `WHERE status NOT IN ('completed','cancelled')` |
| Trator do calendário parado | `_updateCalTractor()` via DOM a cada 20s, independente de fetch |
| Cache de catálogo desatualizado | `_convCatalog = null` em `saveItem()` e `deleteItem()` |

---

## Comandos Disponíveis

| Comando | Quando usar |
|---------|------------|
| `testar.bat` | Após cada alteração — bumpa versão + aplica no Docker local |
| `publicar.bat "msg"` | Somente após aprovação do CEO (patch: X.Y.Z → X.Y.Z+1) |
| `publicar.bat "msg" minor` | Nova funcionalidade aprovada |
| `publicar.bat "msg" major` | Mudança grande aprovada |

## Ambientes

| Ambiente | URL | Banco |
|----------|-----|-------|
| Local (Docker) | http://localhost:3000 | PostgreSQL local (marinaone_db) |
| Produção (Railway) | https://marinaone.com.br | PostgreSQL Railway |

## Tenant local
`SINGLE_TENANT_SLUG=demo` — acessar direto sem `?tenant=`.

## Stack
- Node.js 20 + PostgreSQL (postgres.js)
- Docker Compose para dev local
- Railway + GitHub Actions para produção
