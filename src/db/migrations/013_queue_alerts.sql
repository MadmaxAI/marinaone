-- ============================================================
--  Marina One — Migration 013
--  Alertas de fila por papel de usuário
-- ============================================================

CREATE TABLE IF NOT EXISTS queue_alerts (
  id             BIGSERIAL PRIMARY KEY,
  operation_id   BIGINT NOT NULL,
  vessel_name    TEXT,
  client_name    TEXT,
  operation_type TEXT,
  alert_type     TEXT NOT NULL,   -- 'warning' | 'overdue'
  message        TEXT NOT NULL,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  dismissed_at   TIMESTAMPTZ,
  dismissed_by   BIGINT,
  UNIQUE(operation_id, alert_type)
);

CREATE INDEX IF NOT EXISTS idx_qa_op     ON queue_alerts(operation_id);
CREATE INDEX IF NOT EXISTS idx_qa_type   ON queue_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_qa_dismissed ON queue_alerts(dismissed_at);

CREATE TABLE IF NOT EXISTS alert_role_config (
  alert_type TEXT NOT NULL,
  role       TEXT NOT NULL,
  enabled    BOOLEAN DEFAULT TRUE,
  PRIMARY KEY (alert_type, role)
);

INSERT INTO alert_role_config(alert_type, role, enabled) VALUES
  ('queue_warning', 'admin',    TRUE),
  ('queue_warning', 'operador', TRUE),
  ('queue_warning', 'loja',     FALSE),
  ('queue_overdue', 'admin',    TRUE),
  ('queue_overdue', 'operador', TRUE),
  ('queue_overdue', 'loja',     FALSE)
ON CONFLICT DO NOTHING;
