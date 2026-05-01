-- ============================================================
--  Marina One — Migration 004
--  Contas abertas de clientes na Loja/PDV (fiado)
-- ============================================================

CREATE TABLE IF NOT EXISTS client_tabs (
  id         BIGSERIAL PRIMARY KEY,
  client_id  BIGINT NOT NULL REFERENCES clients(id),
  status     TEXT NOT NULL DEFAULT 'open',   -- open | closed
  opened_at  TIMESTAMPTZ DEFAULT NOW(),
  closed_at  TIMESTAMPTZ,
  notes      TEXT
);

ALTER TABLE store_orders ADD COLUMN IF NOT EXISTS tab_id BIGINT;
