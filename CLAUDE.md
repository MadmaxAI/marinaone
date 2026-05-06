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
