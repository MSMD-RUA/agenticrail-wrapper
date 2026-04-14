INSERT INTO clients (
  client_id,
  email,
  email_verified,
  status,
  created_at
) VALUES (
  'cli_demo_001',
  'you@example.com',
  1,
  'active',
  '2026-04-14T10:30:00+12:00'
);

INSERT INTO api_keys (
  key_id,
  client_id,
  key_prefix,
  key_hash,
  mode,
  status,
  created_at,
  last_used_at
) VALUES (
  'key_demo_001',
  'cli_demo_001',
  'ar_live_DEMO1',
  'PASTE_REAL_SHA256_OF_FULL_KEY_HERE',
  'live',
  'active',
  '2026-04-14T10:30:00+12:00',
  NULL
);