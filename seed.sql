-- Development seed — ONE ROW PER TABLE.
-- This file is for local setup and CI only. Never run against production.
--
-- Test API key (full key, for use in Authorization header):
--   ar_live_DEMO1.dev_only_seed_key_not_for_production
--
-- key_hash = SHA-256(full key above) using UTF-8 encoding.
-- Recompute if you change the key:
--   echo -n "ar_live_DEMO1.dev_only_seed_key_not_for_production" | sha256sum

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
  'aa68d23870b43636cf946453666f872125ec8759efbec046b29888b850b44221',
  'live',
  'active',
  '2026-04-14T10:30:00+12:00',
  NULL
);
