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

## Design de Interface

### Princípios obrigatórios
- **Mobile-first:** toda tela deve ser usável em 375px de largura mínima
- **SPA:** navegação sempre via `nav('pagina')` e `pages.*` — nunca `location.reload()`
- **Feedback imediato:** `toast()` para toda ação do usuário (salvar, excluir, erro, sucesso)
- **Estado vazio:** toda lista/tabela deve ter mensagem quando não há dados
- **Sem surpresas:** ações destrutivas pedem confirmação com `confirm()`

### Classes CSS padrão (não criar variantes novas sem necessidade)
| Elemento | Classes disponíveis |
|----------|-------------------|
| Badges | `badge-success` (verde), `badge-info` (azul), `badge-warning` (amarelo), `badge-gray` (neutro), `badge-danger` (vermelho) |
| Botões | `btn-primary`, `btn-ghost`, `btn-danger`, `btn-sm` |
| Tabelas | `thead` fixo + `tbody` scrollável; `colspan` DEVE ser atualizado ao adicionar/remover colunas |
| Layout | `card`, `card-header`, `card-body`; sidebar + topbar fixos |

### Consistência entre telas
- A mesma ação deve ter o mesmo visual e comportamento em todas as telas
- Módulos que exibem o mesmo recurso (ex: loja → conveniência → totem) devem mostrar os mesmos campos — inclusive foto, preço, estoque
- Ao adicionar campo novo em uma tela, verificar todas as outras que exibem o mesmo dado

---

## Padrões Técnicos — Frontend

### Dados em tempo real (padrão mtime)
Para manter telas atualizadas sem onerar tráfego:
1. Criar endpoint leve `GET /api/[recurso]/mtime` → retorna apenas `{ mtime }`
2. Polling a cada 20s comparando mtime anterior vs atual
3. Fetch completo dos dados **somente quando mtime mudar**
4. Atualizações puramente visuais (posição, relógio, progresso) via manipulação DOM direta — sem request ao servidor

Exemplo implementado: calendário de operações (`/api/queue/calendar/mtime` + `_updateCalTractor()`)

### Cache client-side — regra absoluta
Todo cache deve ser invalidado imediatamente na função que altera o dado:
```js
_convCatalog = null; // sempre após saveItem() e deleteItem()
```
Ao criar qualquer novo cache (`let _xxxCache = null`), documentar aqui qual função o invalida.

| Cache | Invalidar em |
|-------|-------------|
| `_convCatalog` | `saveItem()`, `deleteItem()` |

### Colspan em tabelas
Ao adicionar ou remover colunas de uma tabela, atualizar **sempre** o `colspan` do row de estado vazio correspondente. Esquecer isso quebra o layout silenciosamente.

---

## Segurança

### Implementado (v2.3.14 — não reverter)
- **Senhas:** bcrypt 10 rounds. Hashes SHA-256 legados migram automaticamente para bcrypt no primeiro login bem-sucedido — transparente para o usuário
- **JWT_SECRET:** obrigatório via env var; servidor recusa iniciar sem ela
- **Rate limiting:** 10 tentativas de login por IP a cada 15 minutos (tenant e superadmin)

### Pendente — priorizar antes de 10+ tenants
| Item | Risco atual | Ação necessária |
|------|------------|-----------------|
| CORS `*` | Baixo (JWT mitiga) | Restringir para `*.marinaone.com.br` em produção |
| `?tenant=` em produção | Baixo (requer auth válida) | Desabilitar via Cloudflare Worker em produção |
| Pool por tenant (max 10) | **Alto a 8+ tenants** | PgBouncer ou pool compartilhado |
| `admin_password_plain` em `saas.tenants` | **Alto** | Campo existe para o painel super-admin exibir credenciais; migrar para entrega segura fora do banco |

### Regras permanentes
- Nunca logar senhas, tokens ou dados sensíveis no console
- Toda rota autenticada de tenant valida papel via `requireRole()` ou `clientScope()`
- `role='cliente'` SEMPRE filtrado por `client_id` — nunca retornar dados de outros clientes
- Rotas públicas são exatamente: `/api/auth/login`, `/api/version`, `/api/conveniencia/catalog`, `/api/conveniencia/order` — não adicionar sem deliberação

---

## Escalabilidade — Limites e Roadmap

### Estado atual (Railway Hobby — adequado para até ~8 tenants)
- Single Node.js process (sem cluster)
- Pool dedicado por tenant: `max: 10` conexões — PostgreSQL esgota a ~8–10 tenants ativos
- Cache em memória por processo — incompatível com múltiplas instâncias
- Sem compressão gzip nas respostas

### Sinais de que é hora de escalar
| Sinal | Ação |
|-------|------|
| 8+ tenants ativos | PgBouncer ou pool compartilhado com `SET search_path` |
| Queries de analytics lentas | PM2 cluster mode (usa múltiplos cores) |
| 2+ instâncias no Railway | Redis para `_tenantCache` e rate limiting compartilhado |
| Tempo de resposta >500ms em rotas simples | Gzip + Railway Pro |

### O que NÃO fazer prematuramente
- Não adicionar Redis antes de ter 2+ instâncias rodando
- Não migrar para microserviços — o monolito atual é adequado para dezenas de tenants
- Não criar filas/workers assíncronos sem demanda real

### Vantagem arquitetural preservada
Schema-per-tenant permite migrar qualquer tenant para banco PostgreSQL separado no futuro sem alterar uma linha de código — apenas mudar `DATABASE_URL` por tenant.

---

## Decisões Técnicas Relevantes

### Por que `compat.js` existe
O sistema foi migrado de SQLite para PostgreSQL. A camada `compat.js` traduz sintaxe SQLite (`?`, `INSERT OR IGNORE`, `datetime('now')`) para PostgreSQL em tempo real. É intencional e não deve ser removida — o código das rotas usa essa API.

### Timezone UTC-3 fixo — não alterar
`BRT_OFFSET_MS = -3 * 60 * 60 * 1000` em `server.js` é **intencional**. O Brasil aboliu horário de verão em 2019 — UTC-3 é permanente. Não "corrigir" para biblioteca de timezone.

### `admin_password_plain` em `saas.tenants` — não remover
A coluna existe para o painel super-admin exibir as credenciais de acesso de cada marina ao CEO. Remover ou apagar o campo quebra essa funcionalidade. O item já está na lista de pendências de segurança (migrar para entrega segura), mas a remoção só deve acontecer junto com uma solução alternativa de exibição.

### Adicionar pacote npm — procedimento obrigatório
O Docker usa volume anônimo para `node_modules` que **não é atualizado no rebuild normal**.
Ao adicionar qualquer novo pacote (`npm install <pkg> --save`), executar:
```bash
docker compose rm -fsv app   # remove container + volume anônimo de node_modules
docker compose up -d          # recria com o novo pacote instalado
```
Sem isso o servidor não inicia com erro `Cannot find module`.

### Histórico de inconsistências já corrigidas (não reincidir)
| Inconsistência | Como aconteceu | Solução aplicada |
|---------------|---------------|-----------------|
| Contratos mostrando vaga sem `spot_id` | JOIN duplo com fallback via `spots.vessel_id` | Removido fallback; `spot_id` é fonte única |
| Fotos ausentes em conveniência/totem | SELECT parcial omitia `photo_url` | Todo SELECT de recurso compartilhado retorna campos completos |
| Fila com ordem invertida | `MAX(queue_order)` excluía só `completed`, não `cancelled` | `WHERE status NOT IN ('completed','cancelled')` |
| Trator do calendário parado | Atualização só no fetch; sem movimento entre fetches | `_updateCalTractor()` via DOM a cada 20s, independente de fetch |
| Cache de catálogo desatualizado | `saveItem()`/`deleteItem()` não zeravam `_convCatalog` | `_convCatalog = null` em ambas as funções |

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
