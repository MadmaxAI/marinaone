-- ============================================================
--  Marina One — Migration 014
--  Seeds completos: todos os tipos de alerta × todas as roles
-- ============================================================

-- Novos tipos que ainda não existem em alert_role_config
-- queue_inconsistent
INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('queue_inconsistent', 'admin',    TRUE),
  ('queue_inconsistent', 'operador', TRUE),
  ('queue_inconsistent', 'loja',     FALSE),
  ('queue_inconsistent', 'cliente',  FALSE)
ON CONFLICT DO NOTHING;

-- queue_delayed
INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('queue_delayed', 'admin',    TRUE),
  ('queue_delayed', 'operador', TRUE),
  ('queue_delayed', 'loja',     FALSE),
  ('queue_delayed', 'cliente',  FALSE)
ON CONFLICT DO NOTHING;

-- financial_overdue
INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('financial_overdue', 'admin',    TRUE),
  ('financial_overdue', 'operador', TRUE),
  ('financial_overdue', 'loja',     FALSE),
  ('financial_overdue', 'cliente',  TRUE)
ON CONFLICT DO NOTHING;

-- stock_zero
INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('stock_zero', 'admin',    TRUE),
  ('stock_zero', 'operador', FALSE),
  ('stock_zero', 'loja',     TRUE),
  ('stock_zero', 'cliente',  FALSE)
ON CONFLICT DO NOTHING;

-- stock_low
INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('stock_low', 'admin',    TRUE),
  ('stock_low', 'operador', FALSE),
  ('stock_low', 'loja',     TRUE),
  ('stock_low', 'cliente',  FALSE)
ON CONFLICT DO NOTHING;

-- Garante que queue_warning e queue_overdue também têm entrada para 'cliente'
INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('queue_warning', 'cliente', FALSE),
  ('queue_overdue', 'cliente', FALSE)
ON CONFLICT DO NOTHING;
