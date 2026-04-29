-- ============================================================
--  Marina One — Schema por Tenant (PostgreSQL)
--  Executado dentro do schema marina_<slug> de cada tenant
-- ============================================================

-- Tabela de controle de migrações (por schema)
CREATE TABLE IF NOT EXISTS _migrations (
  id         BIGSERIAL PRIMARY KEY,
  filename   TEXT UNIQUE NOT NULL,
  applied_at TIMESTAMPTZ DEFAULT NOW()
);

-- Usuários do tenant
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'admin',
  client_id     BIGINT,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Permissões por role
CREATE TABLE IF NOT EXISTS role_permissions (
  role        TEXT NOT NULL,
  module      TEXT NOT NULL,
  can_view    INTEGER DEFAULT 0,
  can_create  INTEGER DEFAULT 0,
  can_edit    INTEGER DEFAULT 0,
  can_delete  INTEGER DEFAULT 0,
  PRIMARY KEY (role, module)
);

-- Clientes da marina
CREATE TABLE IF NOT EXISTS clients (
  id         BIGSERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  email      TEXT,
  phone      TEXT,
  cpf        TEXT,
  tier       TEXT DEFAULT 'standard',
  ltv        NUMERIC(12,2) DEFAULT 0,
  address    TEXT,
  notes      TEXT,
  active     INTEGER DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Embarcações
CREATE TABLE IF NOT EXISTS vessels (
  id           BIGSERIAL PRIMARY KEY,
  client_id    BIGINT NOT NULL REFERENCES clients(id),
  name         TEXT NOT NULL,
  type         TEXT,
  size         TEXT DEFAULT 'media',
  length       NUMERIC(8,2),
  beam         NUMERIC(8,2),
  draft        NUMERIC(8,2),
  year         INTEGER,
  registration TEXT,
  model        TEXT,
  manufacturer TEXT,
  engine       TEXT,
  notes        TEXT,
  active       INTEGER DEFAULT 1,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Vagas
CREATE TABLE IF NOT EXISTS spots (
  id        BIGSERIAL PRIMARY KEY,
  number    TEXT NOT NULL,
  type      TEXT NOT NULL,
  status    TEXT DEFAULT 'available',
  vessel_id BIGINT REFERENCES vessels(id)
);

-- Contratos
CREATE TABLE IF NOT EXISTS contracts (
  id                 BIGSERIAL PRIMARY KEY,
  client_id          BIGINT NOT NULL REFERENCES clients(id),
  vessel_id          BIGINT NOT NULL REFERENCES vessels(id),
  spot_id            BIGINT REFERENCES spots(id),
  type               TEXT NOT NULL,
  start_date         DATE NOT NULL,
  end_date           DATE,
  monthly_value      NUMERIC(12,2) NOT NULL,
  status             TEXT DEFAULT 'active',
  notes              TEXT,
  contract_file      TEXT,
  contract_file_name TEXT,
  created_at         TIMESTAMPTZ DEFAULT NOW()
);

-- Fila de operações
CREATE TABLE IF NOT EXISTS queue_operations (
  id             BIGSERIAL PRIMARY KEY,
  vessel_id      BIGINT NOT NULL REFERENCES vessels(id),
  client_id      BIGINT NOT NULL REFERENCES clients(id),
  operation_type TEXT NOT NULL,
  status         TEXT DEFAULT 'waiting',
  priority       INTEGER DEFAULT 0,
  queue_order    INTEGER,
  requested_at   TIMESTAMPTZ DEFAULT NOW(),
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  operator       TEXT,
  notes          TEXT
);

-- Cobranças financeiras
CREATE TABLE IF NOT EXISTS financial_charges (
  id             BIGSERIAL PRIMARY KEY,
  client_id      BIGINT NOT NULL REFERENCES clients(id),
  contract_id    BIGINT REFERENCES contracts(id),
  description    TEXT NOT NULL,
  amount         NUMERIC(12,2) NOT NULL,
  due_date       DATE NOT NULL,
  paid_date      DATE,
  payment_method TEXT,
  status         TEXT DEFAULT 'pending',
  notes          TEXT,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Itens da loja / PDV
CREATE TABLE IF NOT EXISTS store_items (
  id         BIGSERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  category   TEXT,
  price      NUMERIC(12,2) NOT NULL,
  cost       NUMERIC(12,2) DEFAULT 0,
  stock      INTEGER DEFAULT 0,
  min_stock  INTEGER DEFAULT 5,
  unit       TEXT DEFAULT 'un',
  active     INTEGER DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Pedidos da loja
CREATE TABLE IF NOT EXISTS store_orders (
  id              BIGSERIAL PRIMARY KEY,
  vessel_id       BIGINT REFERENCES vessels(id),
  client_id       BIGINT REFERENCES clients(id),
  items           TEXT NOT NULL,
  subtotal        NUMERIC(12,2) NOT NULL,
  discount        NUMERIC(12,2) DEFAULT 0,
  total           NUMERIC(12,2) NOT NULL,
  status          TEXT DEFAULT 'open',
  payment_method  TEXT,
  pix_txid        TEXT,
  notes           TEXT,
  delivery_status TEXT,
  delivery_notes  TEXT,
  paid_date       DATE,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Config PIX da loja
CREATE TABLE IF NOT EXISTS store_pix_config (
  id            BIGSERIAL PRIMARY KEY,
  key           TEXT NOT NULL,
  key_type      TEXT NOT NULL,
  merchant_name TEXT NOT NULL,
  city          TEXT NOT NULL,
  active        INTEGER DEFAULT 1
);

-- Ordens de serviço de manutenção
CREATE TABLE IF NOT EXISTS maintenance_os (
  id               BIGSERIAL PRIMARY KEY,
  vessel_id        BIGINT REFERENCES vessels(id),
  os_number        TEXT NOT NULL,
  type             TEXT NOT NULL,
  description      TEXT NOT NULL,
  status           TEXT DEFAULT 'open',
  priority         TEXT DEFAULT 'normal',
  scheduled_date   DATE,
  completed_date   DATE,
  estimated_hours  NUMERIC(6,2),
  actual_hours     NUMERIC(6,2),
  cost             NUMERIC(12,2) DEFAULT 0,
  technician       TEXT,
  parts_used       TEXT,
  notes            TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Alertas do sistema
CREATE TABLE IF NOT EXISTS alerts (
  id          BIGSERIAL PRIMARY KEY,
  type        TEXT NOT NULL,
  message     TEXT NOT NULL,
  severity    TEXT DEFAULT 'info',
  entity_type TEXT,
  entity_id   BIGINT,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  read_at     TIMESTAMPTZ
);

-- Configurações do tenant
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Logs de pagamentos
CREATE TABLE IF NOT EXISTS payment_logs (
  id                BIGSERIAL PRIMARY KEY,
  charge_id         BIGINT NOT NULL,
  client_id         BIGINT,
  client_name       TEXT,
  description       TEXT,
  amount            NUMERIC(12,2),
  payment_method    TEXT,
  pay_notes         TEXT,
  comprovante_data  TEXT,
  comprovante_name  TEXT,
  user_id           BIGINT,
  user_email        TEXT,
  user_name         TEXT,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- Logs de auditoria
CREATE TABLE IF NOT EXISTS system_logs (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT,
  user_name  TEXT,
  action     TEXT,
  details    TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Índices de performance
CREATE INDEX IF NOT EXISTS idx_vessels_client    ON vessels(client_id);
CREATE INDEX IF NOT EXISTS idx_contracts_client  ON contracts(client_id);
CREATE INDEX IF NOT EXISTS idx_contracts_vessel  ON contracts(vessel_id);
CREATE INDEX IF NOT EXISTS idx_contracts_status  ON contracts(status);
CREATE INDEX IF NOT EXISTS idx_queue_status      ON queue_operations(status);
CREATE INDEX IF NOT EXISTS idx_queue_vessel      ON queue_operations(vessel_id);
CREATE INDEX IF NOT EXISTS idx_charges_client    ON financial_charges(client_id);
CREATE INDEX IF NOT EXISTS idx_charges_status    ON financial_charges(status);
CREATE INDEX IF NOT EXISTS idx_charges_due       ON financial_charges(due_date);
CREATE INDEX IF NOT EXISTS idx_orders_status     ON store_orders(status);
CREATE INDEX IF NOT EXISTS idx_alerts_read       ON alerts(read_at);
CREATE INDEX IF NOT EXISTS idx_users_client      ON users(client_id);
