# Marina One — Guia para o Claude Code

## Regra principal — NUNCA publicar em produção sem aprovação

Após qualquer alteração de código, o Claude deve:
1. Aplicar as mudanças nos arquivos
2. Rodar `testar.bat` para atualizar o ambiente local
3. Informar ao usuário: **"Alteração feita. Teste em http://localhost:3000 e me diga 'aprovado' para publicar."**
4. **AGUARDAR** o usuário dizer "aprovado" (ou variações: "ok", "pode publicar", "publish", "deploy")
5. Somente então rodar `publicar.bat "descrição"`

## NUNCA fazer isso sozinho
- Nunca rodar `publicar.bat` sem aprovação explícita do usuário
- Nunca fazer `git push` diretamente
- Nunca fazer `railway up` sem aprovação

## Fluxo obrigatório

```
Claude altera código
        ↓
Claude roda: testar.bat
        ↓
Claude diz: "Teste em localhost:3000 (vX.Y.Z) e diga 'aprovado'"
        ↓         ↑ SEMPRE informar a versão atual do package.json
Usuário testa e diz: "aprovado"
        ↓
Claude roda: publicar.bat "descrição da alteração"
        ↓
Deploy automático no Railway ✅
```

## Regra de comunicação — versão obrigatória

Ao finalizar qualquer alteração e avisar o usuário para testar, SEMPRE informar:
- A versão atual (ex: "v2.0.8") que está rodando no ambiente local
- Exemplo: **"Alteração feita. Teste em http://localhost:3000 (v2.0.8) e me diga 'aprovado' para publicar."**

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
- [ ] Usuário aprovou o teste

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

## Comandos disponíveis

| Comando | Quando usar |
|---------|------------|
| `testar.bat` | Após cada alteração — aplica no Docker local |
| `publicar.bat "msg"` | Somente após aprovação do usuário |
| `publicar.bat "msg" minor` | Nova funcionalidade aprovada |
| `publicar.bat "msg" major` | Mudança grande aprovada |

## Ambientes

| Ambiente | URL | Banco |
|----------|-----|-------|
| Local (Docker) | http://localhost:3000 | PostgreSQL local (marinaone_db) |
| Produção (Railway) | https://marina-one-app.up.railway.app | PostgreSQL Railway |

## Tenant local
O ambiente local usa `SINGLE_TENANT_SLUG=demo` — acesse direto sem `?tenant=`.

## Stack
- Node.js 20 + PostgreSQL (postgres.js)
- Docker Compose para dev local
- Railway + GitHub Actions para produção
- Dockerfile como base de build
