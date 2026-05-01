-- ============================================================
--  Marina One — Migration 005
--  Colunas de pagamento/comprovante em store_orders
-- ============================================================

ALTER TABLE store_orders ADD COLUMN IF NOT EXISTS pay_notes       TEXT;
ALTER TABLE store_orders ADD COLUMN IF NOT EXISTS comprovante_data TEXT;
ALTER TABLE store_orders ADD COLUMN IF NOT EXISTS comprovante_name TEXT;
