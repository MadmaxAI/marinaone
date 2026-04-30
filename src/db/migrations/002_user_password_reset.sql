-- ============================================================
--  Marina One — Migration 002
--  Adiciona CPF e flag de troca obrigatória de senha nos usuários
-- ============================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS cpf               TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0;
