-- ============================================================
--  Marina One SaaS — Schema global (não por tenant)
--  Contém: tenants, super_admins, license_contracts, license_charges
-- ============================================================

CREATE SCHEMA IF NOT EXISTS saas;

CREATE TABLE IF NOT EXISTS saas.tenants (
  id                   BIGSERIAL PRIMARY KEY,
  slug                 TEXT UNIQUE NOT NULL,
  name                 TEXT NOT NULL,
  plan                 TEXT DEFAULT 'professional',
  active               BOOLEAN DEFAULT TRUE,
  admin_email          TEXT,
  admin_password_plain TEXT,
  created_at           TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS admin_email           TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS admin_password_plain  TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS cnpj                  TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS address               TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS city_state            TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS representative_name   TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS representative_cpf    TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS representative_role   TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS copilot_tenant_rules  TEXT;

CREATE TABLE IF NOT EXISTS saas.super_admins (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── Contratos de licença SaaS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saas.license_contracts (
  id                 BIGSERIAL PRIMARY KEY,
  tenant_slug        TEXT NOT NULL REFERENCES saas.tenants(slug) ON DELETE CASCADE,
  plan               TEXT NOT NULL DEFAULT 'professional',
  monthly_value      NUMERIC(10,2) NOT NULL DEFAULT 0,
  start_date         DATE NOT NULL,
  end_date           DATE,
  status             TEXT NOT NULL DEFAULT 'active',
  contract_file_data TEXT,
  contract_file_name TEXT,
  notes              TEXT,
  created_at         TIMESTAMPTZ DEFAULT NOW()
);

-- ── Parcelas/cobranças SaaS ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saas.license_charges (
  id             BIGSERIAL PRIMARY KEY,
  contract_id    BIGINT REFERENCES saas.license_contracts(id) ON DELETE CASCADE,
  tenant_slug    TEXT NOT NULL,
  description    TEXT,
  amount         NUMERIC(10,2) NOT NULL,
  due_date       DATE NOT NULL,
  paid_date      DATE,
  payment_method TEXT,
  status         TEXT NOT NULL DEFAULT 'pending',
  notes          TEXT,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lc_tenant   ON saas.license_contracts(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_lch_tenant  ON saas.license_charges(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_lch_status  ON saas.license_charges(status);
CREATE INDEX IF NOT EXISTS idx_lch_due     ON saas.license_charges(due_date);

-- ══════════════════════════════════════════════════════════════════════
--  MÓDULOS x LICENÇAS
-- ══════════════════════════════════════════════════════════════════════

-- Catálogo de módulos disponíveis no sistema
CREATE TABLE IF NOT EXISTS saas.modules (
  id          BIGSERIAL PRIMARY KEY,
  slug        TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,
  description TEXT,
  category    TEXT NOT NULL DEFAULT 'core', -- core | premium | ai | enterprise
  has_ext_cost BOOLEAN DEFAULT FALSE,       -- gera custo externo (ex: Claude API)
  active      BOOLEAN DEFAULT TRUE,
  is_future   BOOLEAN DEFAULT FALSE,        -- TRUE = roadmap ainda não implementado
  sort_order  INT DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE saas.modules ADD COLUMN IF NOT EXISTS is_future BOOLEAN DEFAULT FALSE;

-- Tipos de licença (planos comerciais)
CREATE TABLE IF NOT EXISTS saas.license_types (
  id            BIGSERIAL PRIMARY KEY,
  slug          TEXT UNIQUE NOT NULL,
  name          TEXT NOT NULL,
  description   TEXT,
  price_monthly NUMERIC(10,2) DEFAULT 0,
  price_yearly  NUMERIC(10,2) DEFAULT 0,
  is_custom     BOOLEAN DEFAULT FALSE,
  active        BOOLEAN DEFAULT TRUE,
  sort_order    INT DEFAULT 0,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Módulos incluídos em cada tipo de licença (com % de distribuição de valor)
CREATE TABLE IF NOT EXISTS saas.license_type_modules (
  license_type_id BIGINT NOT NULL REFERENCES saas.license_types(id) ON DELETE CASCADE,
  module_id       BIGINT NOT NULL REFERENCES saas.modules(id) ON DELETE CASCADE,
  percent_share   NUMERIC(6,3) DEFAULT 0,  -- % do valor total alocado a este módulo
  PRIMARY KEY (license_type_id, module_id)
);

-- Licença ativa por tenant
CREATE TABLE IF NOT EXISTS saas.tenant_licenses (
  id              BIGSERIAL PRIMARY KEY,
  tenant_id       BIGINT NOT NULL REFERENCES saas.tenants(id) ON DELETE CASCADE,
  license_type_id BIGINT NOT NULL REFERENCES saas.license_types(id),
  contract_id     BIGINT REFERENCES saas.license_contracts(id),
  starts_at       DATE NOT NULL DEFAULT CURRENT_DATE,
  ends_at         DATE,
  billing_period  TEXT DEFAULT 'monthly',  -- monthly | yearly
  status          TEXT NOT NULL DEFAULT 'active', -- active | suspended | expired | trial
  trial_ends_at   DATE,
  notes           TEXT,
  created_by_id   BIGINT REFERENCES saas.super_admins(id),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tl_tenant  ON saas.tenant_licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tl_status  ON saas.tenant_licenses(status);

-- Overrides por tenant: adiciona ou remove módulo individualmente
CREATE TABLE IF NOT EXISTS saas.tenant_module_overrides (
  id          BIGSERIAL PRIMARY KEY,
  tenant_id   BIGINT NOT NULL REFERENCES saas.tenants(id) ON DELETE CASCADE,
  module_id   BIGINT NOT NULL REFERENCES saas.modules(id) ON DELETE CASCADE,
  granted     BOOLEAN NOT NULL,    -- TRUE = concede | FALSE = revoga
  reason      TEXT,
  expires_at  DATE,
  granted_by  BIGINT REFERENCES saas.super_admins(id),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, module_id)
);

CREATE INDEX IF NOT EXISTS idx_tmo_tenant ON saas.tenant_module_overrides(tenant_id);

-- ── Seeds: módulos ────────────────────────────────────────────────────
-- is_future=TRUE → apenas no roadmap, sem código implementado
INSERT INTO saas.modules(slug, name, description, category, has_ext_cost, is_future, sort_order) VALUES
  ('core_dashboard',       'Dashboard',               'KPIs em tempo real, ocupação e receita',          'core',       FALSE, FALSE,  10),
  ('core_queue',           'Fila de Operações',       'Descida, subida, atracação e calendário',         'core',       FALSE, FALSE,  20),
  ('core_clients',         'Clientes',                'Cadastro de armadores com tier e LTV',            'core',       FALSE, FALSE,  30),
  ('core_vessels',         'Embarcações',             'Cadastro e histórico de embarcações',             'core',       FALSE, FALSE,  40),
  ('core_spots',           'Vagas',                   'Mapa de vagas secas e molhadas',                  'core',       FALSE, FALSE,  50),
  ('core_contracts',       'Contratos',               'Contratos digitais com geração de cobranças',     'core',       FALSE, FALSE,  60),
  ('core_financial',       'Financeiro',              'Cobranças, pagamentos e inadimplência',           'core',       FALSE, FALSE,  70),
  ('premium_store',        'Loja / PDV',              'Ponto de venda, estoque e pedidos',               'premium',    FALSE, FALSE,  80),
  ('premium_conveniencia', 'Conveniência & Totem',    'Self-service e totem de autoatendimento',         'premium',    FALSE, FALSE,  90),
  ('premium_maintenance',  'Manutenção',              'Ordens de serviço preventivas e corretivas',      'premium',    FALSE, FALSE, 100),
  ('premium_analytics',    'Analytics Avançado',      '40+ KPIs com gráficos e previsões',              'premium',    FALSE, FALSE, 110),
  ('premium_alerts',       'Alertas Inteligentes',    'Alertas automáticos de estoque e inadimplência',  'premium',    FALSE, FALSE, 120),
  ('premium_multi_marina', 'Multi-Marina',            'Gerenciamento de múltiplas unidades',             'premium',    FALSE, TRUE,  130),
  ('premium_portal',       'Portal do Armador',       'App/portal web exclusivo para armadores',         'premium',    FALSE, TRUE,  140),
  ('climate_radar',        'Radar Climático',         'Alertas meteorológicos automáticos via WhatsApp',  'premium',    FALSE, TRUE,  150),
  ('ai_copilot',           'Co-piloto IA',            'Chat NL→SQL: perguntas em português sobre dados', 'ai',         TRUE,  FALSE, 160),
  ('ai_reports',           'Relatório Narrativo IA',  'Relatório mensal gerado automaticamente por IA',  'ai',         TRUE,  TRUE,  170),
  ('ai_scores',            'Score de Risco IA',       'Inadimplência e churn preditivos por armador',    'ai',         FALSE, TRUE,  180),
  ('ai_prediction',        'Previsão de Ocupação',    'Previsão de ocupação 30/60/90 dias com ML',       'ai',         FALSE, TRUE,  190),
  ('ai_pricing',           'Precificação Dinâmica',   'Sugestão de preço por vaga baseada em demanda',   'ai',         FALSE, TRUE,  200),
  ('enterprise_api',       'API Pública',             'Integração com sistemas externos via REST API',   'enterprise', FALSE, TRUE,  210),
  ('enterprise_whitelabel','White-label',             'Marca própria do cliente no sistema',             'enterprise', FALSE, TRUE,  220)
ON CONFLICT (slug) DO UPDATE SET is_future = EXCLUDED.is_future;

-- ── Seeds: tipos de licença ───────────────────────────────────────────
INSERT INTO saas.license_types(slug, name, description, price_monthly, price_yearly, is_custom, sort_order) VALUES
  ('starter',    'Starter',    'Operação básica — vagas, embarcações, contratos e financeiro',    299,   2990, FALSE, 10),
  ('pro',        'Pro',        'Operação completa com loja, analytics, IA básica e multi-marina', 599,   5990, FALSE, 20),
  ('enterprise', 'Enterprise', 'Suite completa com IA avançada, previsão e API pública',         1299, 12990, FALSE, 30),
  ('custom',     'Custom',     'Licença personalizada — módulos negociados individualmente',        0,      0, TRUE,  40)
ON CONFLICT (slug) DO NOTHING;

-- ── Seeds: módulos por tipo de licença (com % de distribuição) ────────
-- Starter: somente core
DO $$
DECLARE
  v_starter    BIGINT; v_pro BIGINT; v_enterprise BIGINT;
  v_mod        BIGINT;
BEGIN
  SELECT id INTO v_starter    FROM saas.license_types WHERE slug='starter';
  SELECT id INTO v_pro        FROM saas.license_types WHERE slug='pro';
  SELECT id INTO v_enterprise FROM saas.license_types WHERE slug='enterprise';

  -- STARTER: 7 módulos core, distribuição igualitária
  FOR v_mod IN SELECT id FROM saas.modules WHERE slug IN
    ('core_dashboard','core_queue','core_clients','core_vessels','core_spots','core_contracts','core_financial')
  LOOP
    INSERT INTO saas.license_type_modules(license_type_id, module_id, percent_share)
    VALUES(v_starter, v_mod, 14.286) ON CONFLICT DO NOTHING;
  END LOOP;

  -- PRO: core + premium + climate + ai_scores + ai_copilot
  FOR v_mod IN SELECT id FROM saas.modules WHERE slug IN
    ('core_dashboard','core_queue','core_clients','core_vessels','core_spots','core_contracts','core_financial',
     'premium_store','premium_conveniencia','premium_maintenance','premium_analytics','premium_alerts',
     'premium_multi_marina','premium_portal','climate_radar','ai_scores','ai_copilot')
  LOOP
    INSERT INTO saas.license_type_modules(license_type_id, module_id, percent_share)
    VALUES(v_pro, v_mod, 6.25) ON CONFLICT DO NOTHING;
  END LOOP;

  -- ENTERPRISE: tudo exceto white-label (custom)
  FOR v_mod IN SELECT id FROM saas.modules WHERE slug != 'enterprise_whitelabel'
  LOOP
    INSERT INTO saas.license_type_modules(license_type_id, module_id, percent_share)
    VALUES(v_enterprise, v_mod, 4.762) ON CONFLICT DO NOTHING;
  END LOOP;
END $$;

-- ── Configurações globais SaaS ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saas.settings (
  key        TEXT PRIMARY KEY,
  value      TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seeds de defaults (não sobrescreve se já existir)
INSERT INTO saas.settings(key, value) VALUES
  ('company_legal_name',          'Marina One Tecnologia Ltda.'),
  ('company_cnpj',                ''),
  ('company_address',             ''),
  ('company_city_state',          ''),
  ('company_representative_name', ''),
  ('company_representative_cpf',  ''),
  ('company_representative_role', 'Sócio-Administrador'),
  ('general_system_name',         'Marina One'),
  ('general_support_email',    ''),
  ('general_default_plan',     'professional'),
  ('plan_price_starter',       '299'),
  ('plan_price_professional',  '599'),
  ('plan_price_enterprise',    '1299'),
  ('weather_provider',         'openweathermap'),
  ('weather_api_key',          ''),
  ('smtp_host',                ''),
  ('smtp_port',                '587'),
  ('smtp_user',                ''),
  ('smtp_pass',                ''),
  ('smtp_from_email',         ''),
  ('smtp_from_name',          'Marina One'),
  ('claude_api_key',          '')
ON CONFLICT (key) DO NOTHING;

-- ── Seeds: parâmetros de precificação ─────────────────────────────────
INSERT INTO saas.settings(key, value) VALUES
  ('pricing_price_per_foot',       '5.00'),   -- R$/pé padrão
  ('pricing_dry_multiplier',       '1.00'),   -- multiplicador vaga seca ao sol
  ('pricing_covered_multiplier',   '1.10'),   -- multiplicador vaga seca coberta
  ('pricing_wet_multiplier',       '1.20'),   -- multiplicador vaga molhada
  ('pricing_setup_fee',            '0.00'),   -- taxa de implantação
  ('pricing_valid_days',           '30')      -- validade da proposta em dias
ON CONFLICT (key) DO NOTHING;

-- ══════════════════════════════════════════════════════════════════════
--  FASE 2 — PRECIFICAÇÃO & PROPOSTAS COMERCIAIS
-- ══════════════════════════════════════════════════════════════════════

-- Proposta comercial
CREATE TABLE IF NOT EXISTS saas.pricing_proposals (
  id                  BIGSERIAL PRIMARY KEY,
  -- Lead (prospect que pode virar tenant)
  lead_name           TEXT NOT NULL,
  lead_cnpj           TEXT,
  lead_email          TEXT,
  lead_phone          TEXT,
  lead_city_state     TEXT,
  lead_contact_name   TEXT,
  lead_contact_role   TEXT,
  -- Tenant vinculado (preenchido na ativação)
  tenant_slug         TEXT REFERENCES saas.tenants(slug) ON DELETE SET NULL,
  -- Tipo de licença selecionado
  license_type_id     BIGINT REFERENCES saas.license_types(id),
  -- Parâmetros de precificação (snapshot no momento da proposta)
  price_per_foot      NUMERIC(10,4) NOT NULL DEFAULT 5.0,
  dry_multiplier      NUMERIC(6,4)  NOT NULL DEFAULT 1.0,
  covered_multiplier  NUMERIC(6,4)  NOT NULL DEFAULT 1.1,
  wet_multiplier      NUMERIC(6,4)  NOT NULL DEFAULT 1.2,
  setup_fee           NUMERIC(10,2) NOT NULL DEFAULT 0,
  billing_period      TEXT NOT NULL DEFAULT 'monthly',  -- monthly | yearly
  volume_discount_pct NUMERIC(6,2)  NOT NULL DEFAULT 0,
  period_discount_pct NUMERIC(6,2)  NOT NULL DEFAULT 0,
  -- Totais calculados
  total_feet          NUMERIC(10,2) NOT NULL DEFAULT 0,
  total_boats         INT           NOT NULL DEFAULT 0,
  base_value          NUMERIC(10,2) NOT NULL DEFAULT 0,
  discount_value      NUMERIC(10,2) NOT NULL DEFAULT 0,
  final_value         NUMERIC(10,2) NOT NULL DEFAULT 0,
  -- Pipeline
  status              TEXT NOT NULL DEFAULT 'draft',  -- draft|sent|negotiation|approved|converted|rejected
  -- Assinatura digital
  signature_token     TEXT UNIQUE,
  signed_at           TIMESTAMPTZ,
  signed_ip           TEXT,
  signed_name         TEXT,
  signed_doc          TEXT,   -- CPF/RG do signatário
  -- Contrato gerado
  contract_id         BIGINT REFERENCES saas.license_contracts(id),
  -- Meta
  notes               TEXT,
  valid_until         DATE,
  created_by_id       BIGINT REFERENCES saas.super_admins(id),
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Embarcações da proposta
CREATE TABLE IF NOT EXISTS saas.pricing_proposal_boats (
  id              BIGSERIAL PRIMARY KEY,
  proposal_id     BIGINT NOT NULL REFERENCES saas.pricing_proposals(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  boat_type       TEXT NOT NULL DEFAULT 'lancha',  -- lancha|veleiro|iate|jet_ski|outro
  spot_type       TEXT NOT NULL DEFAULT 'seca',    -- seca|molhada
  eslora_feet     NUMERIC(8,2) NOT NULL,
  category_factor NUMERIC(6,4) NOT NULL DEFAULT 1.0,
  line_value      NUMERIC(10,2) NOT NULL DEFAULT 0,
  sort_order      INT DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Módulos selecionados na proposta (pode sobrescrever os do tipo de licença)
CREATE TABLE IF NOT EXISTS saas.pricing_proposal_modules (
  proposal_id   BIGINT NOT NULL REFERENCES saas.pricing_proposals(id) ON DELETE CASCADE,
  module_id     BIGINT NOT NULL REFERENCES saas.modules(id) ON DELETE CASCADE,
  percent_share NUMERIC(6,3) DEFAULT 0,
  PRIMARY KEY (proposal_id, module_id)
);

-- Histórico de auditoria imutável
CREATE TABLE IF NOT EXISTS saas.pricing_proposal_history (
  id          BIGSERIAL PRIMARY KEY,
  proposal_id BIGINT NOT NULL REFERENCES saas.pricing_proposals(id) ON DELETE CASCADE,
  action      TEXT NOT NULL,   -- created|status_changed|recalculated|edited|sent|signed|activated
  old_status  TEXT,
  new_status  TEXT,
  snapshot    JSONB,
  notes       TEXT,
  done_by_id  BIGINT REFERENCES saas.super_admins(id),
  done_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Colunas adicionadas após deploy inicial
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS covered_multiplier  NUMERIC(6,4) NOT NULL DEFAULT 1.1;
-- Campos de rastreamento por etapa do pipeline
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS sent_at             TIMESTAMPTZ;
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS sent_to             TEXT;
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS negotiation_notes   TEXT;
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS rejection_reason    TEXT;
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS rejected_at         TIMESTAMPTZ;
ALTER TABLE saas.pricing_proposals ADD COLUMN IF NOT EXISTS approved_at         TIMESTAMPTZ;

-- Vínculo contrato → proposta de origem
ALTER TABLE saas.license_contracts ADD COLUMN IF NOT EXISTS proposal_id BIGINT REFERENCES saas.pricing_proposals(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_pp_status   ON saas.pricing_proposals(status);
CREATE INDEX IF NOT EXISTS idx_pp_tenant   ON saas.pricing_proposals(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_pp_token    ON saas.pricing_proposals(signature_token);
CREATE INDEX IF NOT EXISTS idx_ppb_prop    ON saas.pricing_proposal_boats(proposal_id);
CREATE INDEX IF NOT EXISTS idx_pph_prop    ON saas.pricing_proposal_history(proposal_id);

-- ── Auto-migração: garante tenant_licenses para tenants com plan legado ──
-- Roda a cada boot — idempotente (só cria se ainda não tem licença ativa)
DO $$
DECLARE
  r         RECORD;
  v_lt_id   BIGINT;
  v_slug    TEXT;
BEGIN
  FOR r IN SELECT id, slug, plan FROM saas.tenants WHERE plan IS NOT NULL AND plan <> '' LOOP
    IF NOT EXISTS (
      SELECT 1 FROM saas.tenant_licenses
      WHERE tenant_id = r.id AND status = 'active'
    ) THEN
      v_slug := CASE
        WHEN LOWER(r.plan) IN ('pro', 'professional') THEN 'pro'
        WHEN LOWER(r.plan) = 'starter'                THEN 'starter'
        WHEN LOWER(r.plan) = 'enterprise'             THEN 'enterprise'
        ELSE 'pro'
      END;
      SELECT id INTO v_lt_id FROM saas.license_types WHERE slug = v_slug;
      IF v_lt_id IS NOT NULL THEN
        INSERT INTO saas.tenant_licenses(tenant_id, license_type_id, starts_at, status, notes)
        VALUES(r.id, v_lt_id, CURRENT_DATE, 'active',
               'Migrado automaticamente do campo plan legado: ' || r.plan)
        ON CONFLICT DO NOTHING;
      END IF;
    END IF;
  END LOOP;
END $$;
