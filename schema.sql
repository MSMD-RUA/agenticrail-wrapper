CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'live',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  FOREIGN KEY (client_id) REFERENCES clients(client_id)
);

CREATE TABLE IF NOT EXISTS usage_logs (
  log_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  sequence_id TEXT NOT NULL,
  decision TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix
ON api_keys(key_prefix);

CREATE INDEX IF NOT EXISTS idx_api_keys_client_id
ON api_keys(client_id);

CREATE INDEX IF NOT EXISTS idx_usage_logs_client_id
ON usage_logs(client_id);

CREATE INDEX IF NOT EXISTS idx_usage_logs_key_id
ON usage_logs(key_id);

CREATE INDEX IF NOT EXISTS idx_usage_logs_sequence_id
ON usage_logs(sequence_id);

CREATE INDEX IF NOT EXISTS idx_usage_logs_created_at
ON usage_logs(created_at);

CREATE TABLE IF NOT EXISTS execution_log (
  exec_id     TEXT NOT NULL PRIMARY KEY,
  pack_id     TEXT NOT NULL UNIQUE,
  sequence_id TEXT NOT NULL,
  step        TEXT NOT NULL,
  action_type TEXT NOT NULL,
  status      TEXT NOT NULL,
  result_json TEXT,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_execution_log_sequence_id
ON execution_log(sequence_id);

CREATE INDEX IF NOT EXISTS idx_execution_log_pack_id
ON execution_log(pack_id);

CREATE TABLE IF NOT EXISTS sequence_state (
  sequence_id TEXT NOT NULL PRIMARY KEY,
  state_json  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);