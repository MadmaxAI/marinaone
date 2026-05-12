# Marina One — Roadmap de Evolução

> Última atualização: 2026-05-11  
> Status geral: **Fase 1 em andamento**

---

## Legenda
- ✅ Concluído
- 🔄 Em andamento
- ⏳ Próximo
- 🔲 Planejado

---

## FASE 1 — Módulos x Licenças *(Foundation)*
> Pré-requisito de tudo. Sem isso nenhum módulo premium tem gate de acesso.

| # | Tarefa | Status |
|---|--------|--------|
| 1.1 | `saas_schema.sql`: tabelas `modules`, `license_types`, `license_type_modules`, `tenant_licenses`, `tenant_module_overrides` | ✅ |
| 1.2 | Seed: catálogo de módulos (core / premium / ai / enterprise) | ✅ |
| 1.3 | Seed: tipos de licença padrão (Starter, Pro, Enterprise) + distribuição de módulos | ✅ |
| 1.4 | API Super Admin: CRUD de módulos (`/api/superadmin/modules`) | ✅ |
| 1.5 | API Super Admin: CRUD de tipos de licença + associação de módulos (`/api/superadmin/license-types`) | ✅ |
| 1.6 | API Super Admin: licença ativa por tenant + overrides individuais (`/api/superadmin/tenants/:slug/license`) | ✅ |
| 1.7 | Middleware `requireModule(slug)` — gate de acesso por módulo | ✅ |
| 1.8 | Frontend Super Admin: aba **Módulos** (catálogo, ativar/desativar) | ✅ |
| 1.9 | Frontend Super Admin: aba **Tipos de Licença** (criar planos, associar módulos, distribuição %) | ✅ |
| 1.10 | Frontend Super Admin: gestão de licença por tenant (trocar plano, overrides, histórico) | ✅ |
| 1.11 | Frontend tenant: bloqueio visual de módulos não licenciados (cadeado + CTA upgrade) | ✅ |

---

## FASE 2 — Precificação & Contratos Automáticos
> Motor completo: proposta → contrato → assinatura → tenant ativo.

| # | Tarefa | Status |
|---|--------|--------|
| 2.1 | `saas_schema.sql`: tabelas `pricing_proposals`, `pricing_proposal_boats`, `pricing_proposal_modules`, `pricing_proposal_history` | ✅ |
| 2.2 | Motor de cálculo de proposta: `Σ(eslora × valor_pé × mult_vaga × fator_categoria)` + descontos por volume e período | ✅ |
| 2.3 | Seed: parâmetros globais de precificação em `saas.settings` | ✅ |
| 2.4 | API Super Admin: CRUD de propostas com cálculo automático | ✅ |
| 2.5 | API Super Admin: reprocessar cálculo ao alterar embarcações ou fatores | ✅ |
| 2.6 | Frontend Super Admin: **wizard de nova proposta** (3 etapas: lead → embarcações → precificação) | ✅ |
| 2.7 | Frontend Super Admin: **pipeline kanban** (rascunho → enviada → negociação → aprovada → convertida/rejeitada) | ✅ |
| 2.8 | Preview HTML imprimível da proposta (PDF via browser print) | ✅ |
| 2.9 | Geração automática de contrato a partir da proposta aprovada/assinada | ✅ |
| 2.10 | Link de aprovação/assinatura digital (página pública `/assinar/:token`) | ✅ |
| 2.11 | **Trigger de ativação automática** na assinatura: cria schema, roda migrations, cria admin, associa licença | ✅ |
| 2.12 | Histórico de versões de proposta (auditoria imutável) | ✅ |

---

## FASE 3 — IA: Quickwins
> Máximo impacto, mínimo custo. Requer módulo `ai_copilot` / `ai_reports` licenciado.

| # | Tarefa | Status |
|---|--------|--------|
| 3.1 | Integração Claude API: wrapper `src/ai/claude.js` com prompt caching | 🔲 |
| 3.2 | **Co-piloto NL→SQL**: chat no dashboard — pergunta em português → SQL → resposta em linguagem natural | 🔲 |
| 3.3 | Widget de chat flutuante no frontend (módulo `ai_copilot`) | 🔲 |
| 3.4 | **Radar climático**: integração Open-Meteo (grátis), alertas automáticos por WhatsApp para armadores | 🔲 |
| 3.5 | **Relatório narrativo mensal**: job dia 1 às 07h → Claude gera texto → e-mail para gestor | 🔲 |
| 3.6 | Contador de uso de IA por tenant (controle de custo por licença) | 🔲 |
| 3.7 | Gate de IA no middleware: `requireModule('ai_copilot')` antes de toda rota de IA | 🔲 |

---

## FASE 4 — IA: Modelos de Risco
> Requer histórico mínimo de 2–3 meses de dados no sistema.

| # | Tarefa | Status |
|---|--------|--------|
| 4.1 | Migration: tabelas `ai_scores`, `ai_score_history` no schema do tenant | 🔲 |
| 4.2 | **Score de inadimplência por armador**: modelo de regras (fase 1) → XGBoost (fase 2) | 🔲 |
| 4.3 | Job diário de recálculo de scores + atualização da tabela | 🔲 |
| 4.4 | **Detector de churn de armador**: sinais fracos (acesso ao portal, padrão de pagamento, tickets) | 🔲 |
| 4.5 | Gatilho automático de retenção: cria tarefa para o gestor + sugere script de abordagem | 🔲 |
| 4.6 | **Motor de alertas inteligentes**: 47 variáveis monitoradas, alertas proativos no dashboard | 🔲 |
| 4.7 | Exibição de score e alertas na ficha do armador (frontend) | 🔲 |

---

## FASE 5 — IA: Predição & Otimização
> Requer serviço Python ML (FastAPI) + histórico de 3–6 meses.

| # | Tarefa | Status |
|---|--------|--------|
| 5.1 | Serviço Python FastAPI em container Docker (adicionar ao `docker-compose.yml`) | 🔲 |
| 5.2 | **Previsão de ocupação** (30/60/90 dias): sazonalidade + eventos + histórico | 🔲 |
| 5.3 | **Precificação dinâmica**: sugestão de preço por vaga/período baseada na previsão | 🔲 |
| 5.4 | **Otimizador de alocação de vagas**: sugere melhor vaga para nova embarcação | 🔲 |
| 5.5 | **Detector de oportunidade de receita**: vagas ociosas, serviços não oferecidos, realocações | 🔲 |
| 5.6 | Gráfico de previsão de ocupação no dashboard (módulo `ai_prediction`) | 🔲 |

---

## FASE 6 — Super Admin Intelligence (Cross-Tenant)
> Visão estratégica da rede de marinas. Módulos exclusivos do Super Admin.

| # | Tarefa | Status |
|---|--------|--------|
| 6.1 | **Painel de benchmarking**: métricas anonimizadas cross-tenant, rankings, outliers | 🔲 |
| 6.2 | **Detector de anomalias cross-tenant**: queda de engajamento, pico de acessos suspeitos, churn de tenant | 🔲 |
| 6.3 | **Previsão de MRR e churn de tenants**: score de saúde por marina + previsão de receita 3 meses | 🔲 |
| 6.4 | **Motor de expansão geográfica**: cruzamento REMI + densidade de marinas + potencial de mercado | 🔲 |
| 6.5 | **Deck executivo automático**: PDF com narrativa IA + gráficos para board/investidores | 🔲 |
| 6.6 | Sugestão automática de ativação de módulos por tenant (receita adicional identificada) | 🔲 |

---

## Dependências entre fases

```
FASE 1 (Licenças)
    └── FASE 2 (Precificação) ← depende do catálogo de módulos
    └── FASE 3 (IA Quickwins) ← gate de módulo licenciado
          └── FASE 4 (IA Risco) ← dados acumulados + infraestrutura Claude
                └── FASE 5 (IA Predição) ← dados 3–6 meses + Python service
                      └── FASE 6 (Super Admin Intel) ← todas as anteriores
```

---

## Stack por fase

| Fase | Tecnologias adicionadas | Custo extra/mês |
|------|------------------------|----------------|
| 1 | Nenhuma (só schema + código) | R$ 0 |
| 2 | Puppeteer (PDF) | R$ 0 |
| 3 | Claude API (Anthropic), Open-Meteo | R$ 100–300 |
| 4 | Redis (jobs), BullMQ | R$ 25–50 |
| 5 | Python FastAPI (container) | R$ 0 (mesmo VPS) |
| 6 | Incluso na infra da Fase 3–5 | R$ 0 |

---

## Catálogo de Módulos

| Slug | Nome | Categoria | Custo externo |
|------|------|-----------|--------------|
| `core_dashboard` | Dashboard | core | Não |
| `core_queue` | Fila de Operações | core | Não |
| `core_clients` | Clientes | core | Não |
| `core_vessels` | Embarcações | core | Não |
| `core_spots` | Vagas | core | Não |
| `core_contracts` | Contratos | core | Não |
| `core_financial` | Financeiro | core | Não |
| `premium_store` | Loja / PDV | premium | Não |
| `premium_conveniencia` | Conveniência & Totem | premium | Não |
| `premium_maintenance` | Manutenção | premium | Não |
| `premium_analytics` | Analytics Avançado | premium | Não |
| `premium_alerts` | Alertas | premium | Não |
| `premium_multi_marina` | Multi-Marina | premium | Não |
| `premium_portal_armador` | Portal do Armador | premium | Não |
| `climate_radar` | Radar Climático | premium | Não (Open-Meteo grátis) |
| `ai_copilot` | Co-piloto IA (chat) | ai | **Sim — Claude API** |
| `ai_reports` | Relatório Narrativo IA | ai | **Sim — Claude API** |
| `ai_scores` | Score de Inadimplência & Churn | ai | Não (modelo local) |
| `ai_prediction` | Previsão de Ocupação | ai | Não (modelo local) |
| `ai_pricing` | Precificação Dinâmica | ai | Não (modelo local) |
| `enterprise_api` | API Pública | enterprise | Não |
| `enterprise_whitelabel` | White-label | enterprise | Não |

---

## Planos padrão — distribuição de módulos

| Módulo | Starter | Pro | Enterprise |
|--------|:-------:|:---:|:----------:|
| core_dashboard | ✓ | ✓ | ✓ |
| core_queue | ✓ | ✓ | ✓ |
| core_clients | ✓ | ✓ | ✓ |
| core_vessels | ✓ | ✓ | ✓ |
| core_spots | ✓ | ✓ | ✓ |
| core_contracts | ✓ | ✓ | ✓ |
| core_financial | ✓ | ✓ | ✓ |
| premium_store | — | ✓ | ✓ |
| premium_conveniencia | — | ✓ | ✓ |
| premium_maintenance | — | ✓ | ✓ |
| premium_analytics | — | ✓ | ✓ |
| premium_alerts | — | ✓ | ✓ |
| premium_multi_marina | — | ✓ | ✓ |
| premium_portal_armador | — | ✓ | ✓ |
| climate_radar | — | ✓ | ✓ |
| ai_scores | — | ✓ | ✓ |
| ai_reports | — | — | ✓ |
| ai_copilot | — | — | ✓ |
| ai_prediction | — | — | ✓ |
| ai_pricing | — | — | ✓ |
| enterprise_api | — | — | ✓ |
| enterprise_whitelabel | — | — | — (Custom) |
