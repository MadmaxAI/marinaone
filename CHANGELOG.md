# Changelog â€” Marina One

## [2.3.124] -- 2026-05-13
- Login SA: logo carregada das configuracoes do super admin; campo de logomarca da plataforma adicionado ao SA

## [2.3.120] -- 2026-05-13
- super admin: paleta Grafite + Cobre com override completo dos tokens do tenant

## [2.3.110] -- 2026-05-12
- fix: criação de tenant agora cria tenant_licenses corretamente; corrige plan slug professional→pro; _syncTenantLicense como ponto único; modal Nova Marina pré-preenchida de proposta; saSaveNewContract abre modal tenant ao invés de auto-ativar; pipeline converted idempotente

## [2.3.85] -- 2026-05-11
- redesign extraordinario fase 1-2-3: ocean depths, sidebar glass island, topbar glassmorphism, KPI bento grid, login cinematic, spring physics, hamburger morph, cascade animations

## [2.3.84] -- 2026-05-11
- redesign visual: fonte Outfit, paleta azul naval unica, icones SVG sidebar, login simplificado, sombras tintadas

## [2.3.83] -- 2026-05-11
- Configuracoes: remove max-width 740px, abas alinhadas com largura total igual as demais telas

## [2.3.79] -- 2026-05-11
- Logs do Sistema: drilldown ano/mes, busca, filtro por acao e modal de detalhe completo

## [2.3.76] -- 2026-05-11
- Grafico receita mensal: 12 meses Jan-Dez com zeros, mes atual em destaque, tooltip em R$

## [2.3.75] -- 2026-05-11
- Fix badge de versao no topbar + saudacao dinamica no Dashboard (Bom dia/tarde/noite + nome do usuario + status da fila)

## [2.3.73] -- 2026-05-11
- Redesign completo do sistema: novo design premium dark SaaS em todas as telas (login glassmorphism, sidebar refinada, KPIs com glow por categoria, modais, fila com color-coding por status, topbar, botoes gradiente)

## [2.3.72] -- 2026-05-10
- login: feedback visual imediato no botão Entrar (spinner + disabled durante autenticação)

## [2.3.69] -- 2026-05-10
- exibe logo da marina na tela de login via endpoint publico /api/brand

## [2.3.66] -- 2026-05-10
- design system fase 1+2: tokens maritimos, Inter font, sidebar gradient+footer usuario, topbar pill, modal animado, toast slide, tabelas zebra

## [2.3.63] -- 2026-05-07
- sidebar: aumenta logomarca para 160x100px

## [2.3.62] -- 2026-05-07
- fila: manobra apos conclusao, nao regressao de cursor; controle de acesso: submódulos alertas e perfis

## [2.3.60] -- 2026-05-07
- gestao de roles: CRUD completo, correcao controle de acesso com roles dinamicas

## [2.3.56] -- 2026-05-07
- corrige agendamento da fila: horario fixo ate chegar no start, shift 1:1 sem manobra extra apos passar o horario

## [2.3.53] -- 2026-05-07
- weather widget centralizado no container com topo alinhado à data

## [2.3.48] -- 2026-05-06
- Módulo de configurações SaaS, geração de contrato de licença profissional com template HTML/PDF, análise preditiva de receita e MRR no Analytics

## [2.3.42] -- 2026-05-06
- SA: clicar na linha da tabela abre detalhes do tenant

## [2.3.40] -- 2026-05-06
- Receita Mes: exibe valor do mes + total acumulado na tabela SA

## [2.3.34] -- 2026-05-06
- Linhas clicaveis em Clientes e Manutencao; grafico Cobranças por Status em portugues

## [2.3.32] -- 2026-05-06
- Separar campos distintos do banco em elementos visuais proprios em todas as tabelas e modais; historico de operacoes em tabela com inicio e termino; corrigir fonte do campo contrato na modal de embarcacao

## [2.3.28] -- 2026-05-06
- Vagas: funcao Resequenciar com preview e confirmacao - renumera spots sem afetar vinculos

## [2.3.27] -- 2026-05-06
- Cronograma: ajustes finais de layout - barras top:10px height:90px, container 120px, linha vermelha 20px abaixo das barras, trator virado para direita na timeline e legenda

## [2.3.18] -- 2026-05-06
- Cronograma: limites fixos por horario de operacao, labels sem overflow na borda final, trator virado para a direita

## [2.3.14] -- 2026-05-06
- docs: enxugar CLAUDE.md - remover secoes universais agora no global

## [2.3.14] -- 2026-05-06
- segurança: bcrypt para senhas, JWT_SECRET obrigatório, rate limit no login

## [2.3.12] -- 2026-05-06
- fotos de produtos visíveis em conveniência e totem; cache do catálogo invalidado ao salvar/remover itens

## [2.3.8] -- 2026-05-06
- migration 012 sincroniza spot_id nos contratos de producao

## [2.3.7] -- 2026-05-06
- coluna contrato em embarcacoes e correcao de consistencia contratos x vagas

## [2.3.5] -- 2026-05-06
- banner aviso fila por cliente e correcao de ordenacao da fila ativa

## [2.3.3] -- 2026-05-06
- Novo fluxo de versao: testar.bat bumpa versao antes do build

## [2.3.2] -- 2026-05-06
- Role totem dedicada com pagina e layout kiosk touch-first para tablet

## [2.3.1] -- 2026-05-06
- Conveniencia layout PDV, foto produto sugestao internet, edicao item corrigida

## [2.3.0] -- 2026-05-05
- Controle de acesso granular por sub-modulo com alinhamento de permissoes

## [2.2.6] -- 2026-05-05
- centraliza tratorzinho na linha vertical do calendario: remove wrapper inline-block

## [2.2.5] -- 2026-05-05
- ajusta posicao do tratorzinho no calendario: alinhado com a base da barra

## [2.2.4] -- 2026-05-05
- corrige bug +3h definitivo: compat.js preserva sufixo Z nos timestamps, pool usa TZ BRT, parse correto de started_at

## [2.2.3] -- 2026-05-05
- corrige bug +3h no calendario: timezone BRT na sessao PostgreSQL, parse correto de started_at como Date object e clamp ao horario limite de operacoes

## [2.2.2] -- 2026-05-04
- fix corrige 3h ao iniciar operacao na fila encode WhatsApp banner avisos PDV recibo

## [2.2.0] -- 2026-05-04
- Avisos de reordenacao de fila: justificativa publica obrigatoria pre-preenchida com template configuravel; banner no calendario para clientes afetados; fix calendario travado; hardening de migrations com 3 camadas de protecao e alertas criticos no boot

## [2.1.1] -- 2026-05-01
- Super Admin: troca de e-mail do administrador da marina

## [2.1.0] -- 2026-05-01
- Financeiro: badges A Vencer/Pendente/Vencido e filtros coerentes; Loja/PDV: ficha e fiado vao direto para preparo sem etapa de aguardando, contas por cliente com quitacao, metodo de pgto pre-selecionado no modal, label Conta no lugar de ficha, filtro de embarcacoes por cliente; Manutencao: correcao do editar OS, nivel do profissional com calculo automatico de valor total, configuracao de custo por nivel em Configuracoes; Migrations 005 e 006

## [2.0.13] -- 2026-05-01
- Ver Detalhes embarcação: dias disponíveis, nº marinheiros, fonte normalizada

## [2.0.12] -- 2026-04-30
- Ver Detalhes de embarcação: layout completo com foto, locação e dados técnicos

## [2.0.11] -- 2026-04-30
- CLAUDE.md: regra crítica de consistência banco+código a cada publicação

## [2.0.10] -- 2026-04-30
- Fix: rodar migrations em todos os tenants no boot (corrige coluna photo em prod)

## [2.0.9] -- 2026-04-30
- Foto e badge de locação na lista de embarcações

## [2.0.8] -- 2026-04-30
- fix encoding UTF-8 acentos + saveVessel com client_id + tooltips nas tabelas

## [2.0.7] -- 2026-04-30
- versao no header do painel super-admin

## [2.0.6] -- 2026-04-30
- fix url producao e credenciais no painel super-admin

## [2.0.5] -- 2026-04-30
- teste de publicacao

## [2.0.4] — 2026-04-30
- versao nas telas de login e sistema + fix login local com tenant em cache

Formato: `[versÃ£o] â€” data â€” tipo â€” descriÃ§Ã£o`
Tipos: `feat` (novo), `fix` (correÃ§Ã£o), `break` (migraÃ§Ã£o manual necessÃ¡ria), `perf` (performance)

---

## [2.0.3] â€” 2026-04-30 â€” feat
- GitHub App Railway autorizado â€” auto-deploy ativo
- DomÃ­nio wildcard *.marinaone.com.br configurado no Cloudflare
- BASE_DOMAIN atualizado para marinaone.com.br

## [2.0.2] â€” 2026-04-29 â€” fix
- Remove vercel.json (conflito com deploy Railway)
- Railway agora Ã© o Ãºnico destino de deploy

## [2.0.1] â€” 2026-04-29 â€” feat
- IntegraÃ§Ã£o GitHub â†’ Railway (deploy automÃ¡tico a cada push)
- Scripts de publicaÃ§Ã£o com versionamento automÃ¡tico (publicar.bat / publicar.sh)
- Deploy SaaS multi-tenant em produÃ§Ã£o no Railway
- Suporte a subdomain multi-tenant via BASE_DOMAIN injetado no frontend

## [2.0.0] â€” 2025-04 â€” break
- MigraÃ§Ã£o completa para SaaS multi-tenant com PostgreSQL
- Arquitetura: schema-per-tenant (`marina_<slug>`) via postgres.js
- Super-admin panel em `/api/superadmin/*` para Arthur gerenciar todas as marinas
- JWT agora inclui `tenant_slug` â€” tokens vinculados ao tenant (cross-tenant rejeitado)
- `provisionTenant()`: cria schema + migra + seed em um Ãºnico comando
- Modo single-tenant via `SINGLE_TENANT_SLUG` (zero mudanÃ§a no frontend)
- Docker Compose + Dockerfile para dev local com PostgreSQL 16
- NGINX config com wildcard `*.marinaone.com.br` â†’ `X-Tenant-Slug` header
- Todos os helpers de DB (dbAll/dbGet/dbRun) agora async
- Suporte a `GREATEST()` em vez de `MAX(0,...)` do SQLite

> **MigraÃ§Ã£o necessÃ¡ria**: requer PostgreSQL e `DATABASE_URL` no `.env`.
> Para single-tenant use `SINGLE_TENANT_SLUG=nome-da-marina`.
> Legado SQLite disponÃ­vel via `npm run legacy`.

## [1.1.0] â€” 2025-04 â€” feat
- Controle de acesso por roles: admin, operador, loja, cliente
- Perfil de acesso vinculado ao cadastro de cliente
- Role `loja` dedicado ao PDV
- Auto-criaÃ§Ã£o/sincronizaÃ§Ã£o de usuÃ¡rio ao criar/editar/excluir cliente
- Senha inicial = CPF do cliente
- Layout do Controle de Acesso redesenhado com chips coloridos
- VersÃ£o exibida no topbar
- Scripts de update automÃ¡tico (update.sh / update.bat)

## [1.0.0] â€” 2025-01 â€” feat
- VersÃ£o inicial do sistema
- MÃ³dulos: Dashboard, Fila, Clientes, EmbarcaÃ§Ãµes, Vagas, Contratos,
  Financeiro, Loja/PDV, ManutenÃ§Ã£o, Analytics, Alertas, ConfiguraÃ§Ãµes

---

## Guia de migraÃ§Ã£o entre versÃµes

### Como aplicar uma atualizaÃ§Ã£o

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

# 2. Atualizar cÃ³digo
git pull origin main

# 3. Reiniciar
pm2 restart marina-one

# 4. Verificar
curl http://localhost:3000/api/version
```

### O que NÃƒO precisa de intervenÃ§Ã£o manual
- Novas colunas em tabelas existentes â†’ `migrateDb()` aplica automaticamente no startup
- Novos dados de seed (ex: usuÃ¡rio padrÃ£o, permissÃµes) â†’ `seedDb()` Ã© idempotente
- MudanÃ§as no frontend â†’ arquivo `frontend.html` substituÃ­do pelo git pull

### O que PODE precisar de atenÃ§Ã£o (marcado como `break`)
- RenomeaÃ§Ã£o de colunas â†’ executar SQL manualmente antes de reiniciar
- MudanÃ§a de estrutura de tabela com dados â†’ script de migraÃ§Ã£o incluso na release
- VariÃ¡veis de ambiente novas â†’ adicionar ao `.env` ou ao serviÃ§o PM2

### Rollback de emergÃªncia
```bash
# Restaurar banco do backup
pm2 stop marina-one
cp ../backups/marina-YYYY-MM-DD.db marina.db

# Voltar versÃ£o do cÃ³digo
git checkout v1.0.0

# Reiniciar
pm2 restart marina-one
```






















































