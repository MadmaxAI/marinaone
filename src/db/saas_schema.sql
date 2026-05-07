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
  ('smtp_from_name',          'Marina One')
ON CONFLICT (key) DO NOTHING;
