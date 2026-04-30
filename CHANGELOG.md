# Changelog — Marina One

Formato: `[versão] — data — tipo — descrição`
Tipos: `feat` (novo), `fix` (correção), `break` (migração manual necessária), `perf` (performance)

---

## [2.0.3] — 2026-04-30 — feat
- GitHub App Railway autorizado — auto-deploy ativo
- Domínio wildcard *.marinaone.com.br configurado no Cloudflare
- BASE_DOMAIN atualizado para marinaone.com.br

## [2.0.2] — 2026-04-29 — fix
- Remove vercel.json (conflito com deploy Railway)
- Railway agora é o único destino de deploy

## [2.0.1] — 2026-04-29 — feat
- Integração GitHub → Railway (deploy automático a cada push)
- Scripts de publicação com versionamento automático (publicar.bat / publicar.sh)
- Deploy SaaS multi-tenant em produção no Railway
- Suporte a subdomain multi-tenant via BASE_DOMAIN injetado no frontend

## [2.0.0] — 2025-04 — break
- Migração completa para SaaS multi-tenant com PostgreSQL
- Arquitetura: schema-per-tenant (`marina_<slug>`) via postgres.js
- Super-admin panel em `/api/superadmin/*` para Arthur gerenciar todas as marinas
- JWT agora inclui `tenant_slug` — tokens vinculados ao tenant (cross-tenant rejeitado)
- `provisionTenant()`: cria schema + migra + seed em um único comando
- Modo single-tenant via `SINGLE_TENANT_SLUG` (zero mudança no frontend)
- Docker Compose + Dockerfile para dev local com PostgreSQL 16
- NGINX config com wildcard `*.marinaone.com.br` → `X-Tenant-Slug` header
- Todos os helpers de DB (dbAll/dbGet/dbRun) agora async
- Suporte a `GREATEST()` em vez de `MAX(0,...)` do SQLite

> **Migração necessária**: requer PostgreSQL e `DATABASE_URL` no `.env`.
> Para single-tenant use `SINGLE_TENANT_SLUG=nome-da-marina`.
> Legado SQLite disponível via `npm run legacy`.

## [1.1.0] — 2025-04 — feat
- Controle de acesso por roles: admin, operador, loja, cliente
- Perfil de acesso vinculado ao cadastro de cliente
- Role `loja` dedicado ao PDV
- Auto-criação/sincronização de usuário ao criar/editar/excluir cliente
- Senha inicial = CPF do cliente
- Layout do Controle de Acesso redesenhado com chips coloridos
- Versão exibida no topbar
- Scripts de update automático (update.sh / update.bat)

## [1.0.0] — 2025-01 — feat
- Versão inicial do sistema
- Módulos: Dashboard, Fila, Clientes, Embarcações, Vagas, Contratos,
  Financeiro, Loja/PDV, Manutenção, Analytics, Alertas, Configurações

---

## Guia de migração entre versões

### Como aplicar uma atualização

**VPS Linux:**
```bash
cd ~/marina-one
bash update.sh
```

**Servidor local Windows:**
```
Duplo clique em update.bat
```

**Manual (qualquer ambiente):**
```bash
# 1. Backup do banco PRIMEIRO
cp marina.db ../backups/marina-$(date +%F).db

# 2. Atualizar código
git pull origin main

# 3. Reiniciar
pm2 restart marina-one

# 4. Verificar
curl http://localhost:3000/api/version
```

### O que NÃO precisa de intervenção manual
- Novas colunas em tabelas existentes → `migrateDb()` aplica automaticamente no startup
- Novos dados de seed (ex: usuário padrão, permissões) → `seedDb()` é idempotente
- Mudanças no frontend → arquivo `frontend.html` substituído pelo git pull

### O que PODE precisar de atenção (marcado como `break`)
- Renomeação de colunas → executar SQL manualmente antes de reiniciar
- Mudança de estrutura de tabela com dados → script de migração incluso na release
- Variáveis de ambiente novas → adicionar ao `.env` ou ao serviço PM2

### Rollback de emergência
```bash
# Restaurar banco do backup
pm2 stop marina-one
cp ../backups/marina-YYYY-MM-DD.db marina.db

# Voltar versão do código
git checkout v1.0.0

# Reiniciar
pm2 restart marina-one
```
