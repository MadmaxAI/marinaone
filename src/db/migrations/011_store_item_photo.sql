-- ============================================================
--  Marina One — Migration 011
--  Foto do produto em store_items
-- ============================================================

ALTER TABLE store_items ADD COLUMN IF NOT EXISTS photo_url TEXT;
