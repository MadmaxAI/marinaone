# Marina One — Guia para o Claude Code

## Regra de comunicação — tratamento

Sempre chamar o usuário de **CEO** (nunca "usuário", "você" genérico, etc.).

## Regra principal — NUNCA publicar em produção sem aprovação

Após qualquer alteração de código, o Claude deve:
1. Aplicar as mudanças nos arquivos
2. Rodar `testar.bat` — já faz o bump de versão (patch por padrão) e reconstrói o Docker
3. Informar ao CEO: **"Alteração feita. Teste em http://localhost:3000 (vX.Y.Z) e me diga 'aprovado' para publicar."**
4. **AGUARDAR** o CEO dizer "aprovado" (ou variações: "ok", "pode publicar", "publish", "deploy")
5. Somente então rodar `publicar.bat "descrição"` — commita e pusha a versão já bumpad

## NUNCA fazer isso sozinho
- Nunca rodar `publicar.bat` sem aprovação explícita do CEO
- Nunca fazer `git push` diretamente
- Nunca fazer `railway up` sem aprovação

## Fluxo obrigatório

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

## Regra de comunicação — versão obrigatória

SEMPRE informar a versão em dois momentos:

1. **Ao avisar para testar localmente:**
   - Exemplo: **"Alteração feita. Teste em http://localhost:3000 (v2.3.3) e me diga 'aprovado' para publicar."**

2. **Ao confirmar publicação em produção:**
   - Exemplo: **"Publicado v2.3.3 — localhost e produção ambos em v2.3.3."**

## ⚠️ REGRA CRÍTICA — Consistência Banco + Código (PRODUÇÃO NÃO PODE PARAR)

### Princípio
Toda alteração de schema (nova coluna, nova tabela, novo índice) DEVE ser acompanhada de uma migration SQL no padrão do projeto. **A produção só pode receber código que o banco consegue executar.**

### Regra obrigatória ao criar qualquer migration nova

1. **Criar o arquivo** em `src/db/migrations/NNN_descricao.sql` usando `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (nunca sem o `IF NOT EXISTS`)
2. **Verificar** se o `boot()` em `server.js` já aplica as migrations em todos os tenants existentes (bloco "passo 3" no boot — se não existir, adicionar)
3. **Testar localmente** com `testar.bat` — confirmar nos logs que a migration foi aplicada
4. **Nunca** alterar `server.js` ou `frontend.html` para usar colunas novas sem ter a migration correspondente criada **no mesmo commit**

### O boot DEVE sempre:
1. Inicializar o schema `saas` (`initSaasSchema`)
2. Se `SINGLE_TENANT_SLUG` definido: provisionar o tenant local
3. **Rodar `runMigrations(slug)` para TODOS os tenants existentes na tabela `saas.tenants`** — isso garante que tenants antigos recebam colunas novas sem intervenção manual

### Checklist antes de publicar qualquer feature com banco novo:
- [ ] Migration criada com `IF NOT EXISTS` (idempotente)
- [ ] Boot percorre todos os tenants e aplica migrations pendentes
- [ ] `testar.bat` rodado e logs mostram migration aplicada
- [ ] Funcionalidade testada em localhost (salvar, editar, listar)
- [ ] CEO aprovou o teste

### Padrão dos arquivos de migration
```
src/db/migrations/
  001_initial_schema.sql    ← tabelas base
  002_user_password_reset.sql
  003_vessel_photo_rental.sql
  004_proxima_feature.sql   ← sempre incrementar
```

Cada arquivo deve ser **idempotente** — pode rodar N vezes sem erro (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`).

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

Regra crítica: papel `cliente` é filtrado por `client_id` em **todas** as queries — nunca retornar dados de outros clientes.

### Vagas (spots)
- Tipos válidos: `seca` (garagem terrestre) e `molhada` (flutuante/atracação)
- Status válidos: `available` → `occupied` | `maintenance`
- Uma vaga comporta **no máximo uma embarcação** (`spots.vessel_id`)

### Contratos
- **Um contrato ativo por embarcação** — uma embarcação não pode ter dois contratos com `status='active'`
- **Um cliente pode ter múltiplos contratos** — um por cada embarcação que mantém na marina
- Status válidos: `active` → `cancelled`
- Tipo do contrato (`seca` ou `molhada`) reflete o tipo da vaga associada
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
- `MAX(queue_order)` deve sempre usar `WHERE status NOT IN ('completed','cancelled')` para não colidir com ops ativas em `in_progress`
- **Uma operação ativa por embarcação:** não permitir nova op se já existe `status IN ('waiting','in_progress')`
- Tipos de operação: `descida` (colocar na água), `subida` (tirar da água), outros
  - `descida` só permitida se embarcação **não** está na água
  - `subida` só permitida se embarcação **está** na água
  - Estado da embarcação verificado por `isVesselInWater()` — nunca replicar essa lógica
- Horário de operações configurável por tenant: `ops_start_time` / `ops_end_time` (padrão 07:00–18:00)
- Tempo de manobra configurável: `maneuver_time_min`

### Notificações da fila (queue_notices)
- Para `role='cliente'`: exibir **apenas** notices onde o cliente tinha operação com `id <= max_op_id` no momento da criação
- Nunca exibir notice para cliente que entrou na fila depois da mudança de horário

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

## Arquitetura — Fontes de Verdade

### Regra principal
Cada relacionamento tem **um único campo canônico**. Nunca criar lógica de fallback que leia de dois campos distintos para o mesmo dado — isso gera inconsistência silenciosa.

### Mapa de fontes de verdade

| Dado | Campo canônico | Nunca usar como alternativa |
|------|---------------|----------------------------|
| Vaga de um contrato | `contracts.spot_id` | `spots.vessel_id` para inferir vaga |
| Embarcação de uma vaga | `spots.vessel_id` | Inferir via contrato ativo |
| Estado na água (embarcação) | `isVesselInWater()` em server.js | Replicar essa lógica em outro lugar |
| Permissões de papel | tabela `role_permissions` | Hard-code por role no código |
| Versão do sistema | `package.json` → `APP_VERSION` | Qualquer outra fonte |

### Consistência de API — campos por rota
Toda rota GET que expõe um recurso deve retornar **todos os campos** que qualquer tela do frontend pode precisar. Proibido criar SELECTs parciais por tela. Exemplo do erro a evitar: `/api/conveniencia/catalog` que omitia `photo_url` presente na tabela.

### Cache do frontend — regra de invalidação
Todo cache client-side deve ser zerado (`= null`) imediatamente após qualquer operação que altere o dado correspondente.

| Cache | Zerrar quando |
|-------|--------------|
| `_convCatalog` | `saveItem()`, `deleteItem()` |
| Qualquer cache futuro | Na função `save*()` e `delete*()` correspondente |

### Consultas no contexto de tenant
- Usar **sempre** `ctx.db.dbAll / dbGet / dbRun` nas rotas de tenant
- Nunca chamar o pool global diretamente dentro de uma rota autenticada de tenant
- O schema correto já está resolvido pelo `tenantMiddleware` antes de chegar na rota

### Resolução de tenant (ordem de prioridade)
1. Header `X-Tenant-Slug`
2. Subdomínio: `porto-belo.marinaone.com.br`
3. Query string: `?tenant=porto-belo`
4. Env `SINGLE_TENANT_SLUG` (modo single-tenant local/Docker)

---

## Comandos disponíveis

| Comando | Quando usar |
|---------|------------|
| `testar.bat` | Após cada alteração — aplica no Docker local |
| `publicar.bat "msg"` | Somente após aprovação do CEO |
| `publicar.bat "msg" minor` | Nova funcionalidade aprovada |
| `publicar.bat "msg" major` | Mudança grande aprovada |

## Ambientes

| Ambiente | URL | Banco |
|----------|-----|-------|
| Local (Docker) | http://localhost:3000 | PostgreSQL local (marinaone_db) |
| Produção (Railway) | https://marinaone.com.br (demo: https://demo.marinaone.com.br) | PostgreSQL Railway |

## Tenant local
O ambiente local usa `SINGLE_TENANT_SLUG=demo` — acesse direto sem `?tenant=`.

## Stack
- Node.js 20 + PostgreSQL (postgres.js)
- Docker Compose para dev local
- Railway + GitHub Actions para produção
- Dockerfile como base de build
