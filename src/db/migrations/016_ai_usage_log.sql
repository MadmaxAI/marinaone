-- 016_ai_usage_log.sql
-- Registro de uso do Co-piloto IA por usuário (por tenant)
CREATE TABLE IF NOT EXISTS ai_usage_log (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT,
  user_name   TEXT,
  question    TEXT    NOT NULL,
  answer      TEXT,
  components  JSONB   DEFAULT '[]',
  tokens_in   INT     DEFAULT 0,
  tokens_out  INT     DEFAULT 0,
  duration_ms INT     DEFAULT 0,
  status      TEXT    NOT NULL DEFAULT 'ok',  -- ok | error
  error_msg   TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_log_user    ON ai_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_log_created ON ai_usage_log(created_at DESC);
