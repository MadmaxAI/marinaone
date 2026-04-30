-- ============================================================
--  Marina One — Migration 003
--  Foto e informações de locação nas embarcações
-- ============================================================

ALTER TABLE vessels ADD COLUMN IF NOT EXISTS photo              TEXT;
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS available_for_rental INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_passengers   INTEGER;
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_sailor       INTEGER DEFAULT 1;
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_days         TEXT;   -- JSON array: ["seg","ter",...]
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_hours_start  TEXT;
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_hours_end    TEXT;
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_price_4h     NUMERIC(10,2);
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_price_6h     NUMERIC(10,2);
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_price_8h     NUMERIC(10,2);
ALTER TABLE vessels ADD COLUMN IF NOT EXISTS rental_notes        TEXT;
