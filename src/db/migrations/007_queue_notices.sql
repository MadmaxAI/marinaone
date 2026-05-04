-- ============================================================
--  Marina One — Migration 007
--  Avisos de alteração de fila para clientes
-- ============================================================

CREATE TABLE IF NOT EXISTS queue_notices (
    id          BIGSERIAL PRIMARY KEY,
    message     TEXT NOT NULL,
    max_op_id   BIGINT NOT NULL DEFAULT 0,  -- maior ID de op na fila no momento do reorder
    created_by  INTEGER,
    created_by_name TEXT,
    created_at  TIMESTAMP DEFAULT NOW(),
    active      SMALLINT DEFAULT 1
);
