-- ============================================================
--  Marina One SaaS — Schema global (não por tenant)
--  Contém: tenants, super_admins
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

-- Adiciona colunas se a tabela já existia antes desta versão
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS admin_email          TEXT;
ALTER TABLE saas.tenants ADD COLUMN IF NOT EXISTS admin_password_plain TEXT;

CREATE TABLE IF NOT EXISTS saas.super_admins (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
