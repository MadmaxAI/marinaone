-- ============================================================
--  Marina One — Migration 015
--  Tabela de roles dinâmica — substitui lista hardcoded
-- ============================================================

CREATE TABLE IF NOT EXISTS roles (
  key         TEXT PRIMARY KEY,
  label       TEXT NOT NULL,
  description TEXT,
  color       TEXT DEFAULT '#6b7280',
  icon        TEXT DEFAULT '👤',
  is_system   BOOLEAN DEFAULT FALSE,
  active      BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Seeds das roles de sistema (is_system = TRUE → não podem ser deletadas)
INSERT INTO roles(key, label, description, color, icon, is_system) VALUES
  ('admin',    'Administrador',  'Acesso irrestrito a todo o sistema',        '#ef4444', '👑', TRUE),
  ('operador', 'Operador',       'Gestão de operações e embarcações',          '#3b82f6', '⚙️', TRUE),
  ('loja',     'Loja / PDV',     'Atendimento e vendas no balcão',             '#f59e0b', '🛒', TRUE),
  ('cliente',  'Cliente',        'Acesso restrito ao próprio cadastro',        '#10b981', '🙍', TRUE),
  ('totem',    'Totem',          'Somente módulo totem (conveniência kiosk)',  '#8b5cf6', '📟', TRUE)
ON CONFLICT DO NOTHING;
