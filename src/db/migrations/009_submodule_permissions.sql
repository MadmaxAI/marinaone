-- ============================================================
--  Marina One — Migration 009
--  Permissões granulares por sub-módulo (abas internas)
--  Adiciona coluna submodule e recria a PK composta.
-- ============================================================

-- 1. Adiciona coluna submodule (vazia = permissão de módulo inteiro)
ALTER TABLE role_permissions
  ADD COLUMN IF NOT EXISTS submodule TEXT NOT NULL DEFAULT '';

-- 2. Remove a PK antiga (role, module) e cria (role, module, submodule)
ALTER TABLE role_permissions DROP CONSTRAINT IF EXISTS role_permissions_pkey;
ALTER TABLE role_permissions
  ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role, module, submodule);
