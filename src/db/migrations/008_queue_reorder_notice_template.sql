-- ============================================================
--  Marina One — Migration 008
--  Template padrão de aviso de reordenação de fila
-- ============================================================

INSERT INTO settings(key, value)
VALUES('queue_reorder_notice_template', 'Informamos que houve uma reordenação na fila de operações. Os horários previstos foram ajustados. Agradecemos a compreensão.')
ON CONFLICT (key) DO NOTHING;
