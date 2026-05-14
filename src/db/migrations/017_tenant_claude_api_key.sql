-- Migration 017: Chave de API Claude por tenant
-- Cada marina pode configurar sua própria chave Anthropic nas Configurações do sistema.
INSERT INTO settings(key, value)
VALUES ('claude_api_key', '')
ON CONFLICT (key) DO NOTHING;
