-- ============================================================
--  Marina One — Migration 010
--  Colunas source e customer_name em store_orders
--  Suporte a pedidos de auto-atendimento (Conveniência / Totem)
-- ============================================================

-- Identifica a origem do pedido: pdv (padrão), self_service, totem
ALTER TABLE store_orders ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'pdv';

-- Nome do cliente para pedidos sem conta (auto-atendimento anônimo)
ALTER TABLE store_orders ADD COLUMN IF NOT EXISTS customer_name TEXT;
