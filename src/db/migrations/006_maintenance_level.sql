-- ============================================================
--  Marina One — Migration 006
--  Nível do profissional em ordens de serviço de manutenção
-- ============================================================

ALTER TABLE maintenance_os ADD COLUMN IF NOT EXISTS technician_level TEXT;
