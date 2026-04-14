README.md
# AgenticRail Wrapper

Thin wrapper in front of AgenticRail.

## What it is

This service sits between the client and the rail.

Flow:

Client  
→ Wrapper  
→ AgenticRail Gate  
→ AgenticRail Core  
→ ALLOW / DENY / HALT + signed receipt  
→ Wrapper executor (only if ALLOW)

The wrapper is the front door.  
The rail remains the enforcement engine.

## Routes

- `GET /v1/health`
- `POST /v1/evaluate`

## What it does

- checks bearer auth
- validates external request shape
- normalises external requests into rail payloads
- calls AgenticRail
- checks returned function / action_type on ALLOW
- if decision = ALLOW, triggers thin executor
- logs usage to D1
- returns clean client-facing response

## Auth modes

### 1. DB-backed API keys (preferred)

The wrapper looks up the presented API key in D1.

Expected key shape:

```text
ar_live_TEST.abc123secret
prefix = ar_live_TEST
full key is hashed with SHA-256
only hash is stored
key status must be active
client status must be active
2. Shared secret fallback (temporary only)

WRAPPER_SHARED_SECRET still works as a fallback during transition.

This is only for setup/testing.
Remove it once D1-backed keys are live.

D1 tables expected
clients
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  email_verified INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT
);
api_keys
CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  mode TEXT DEFAULT 'live',
  status TEXT DEFAULT 'active',
  created_at TEXT,
  last_used_at TEXT
);
usage_logs
CREATE TABLE IF NOT EXISTS usage_logs (
  log_id TEXT PRIMARY KEY,
  client_id TEXT,
  key_id TEXT,
  sequence_id TEXT,
  decision TEXT,
  created_at TEXT
);
External request contract

Client sends a simpler request:

{
  "sequence_id": "seq_001",
  "step": "execution",
  "action_type": "SUBMIT_PAYMENT",
  "action": "submit payment",
  "inputs": {
    "amount": 100,
    "to": "acct_123"
  }
}

The wrapper adds:

schema_version
model_id
function = step
nonce
ts_ms

Then forwards the full payload to the rail.

External response contract

Wrapper returns:

{
  "decision": "ALLOW",
  "executed": true,
  "reasons": [],
  "sequence_id": "seq_001",
  "step": "execution",
  "action_type": "SUBMIT_PAYMENT",
  "result": {
    "status": "submitted",
    "message": "Mock payment submitted"
  },
  "receipt": {
    "pack_id": "abc123",
    "key_id": "k1_2026-02-22_01",
    "signature": "...",
    "signature_alg": "Ed25519",
    "payload_hash": "...",
    "prev_receipt_id": "...",
    "ts_ms": 1712830000000,
    "version": "slp8_receipt_v2"
  }
}
Executor rule

The rail does not perform real-world actions directly.

It only decides:

ALLOW
DENY
HALT

If the decision is ALLOW, the wrapper may trigger an executor.

Current mock executors:

SUBMIT_PAYMENT
SEND_EMAIL
Run
Edit wrangler.toml
Paste the real database_id
Set RAIL_URL
Optionally set WRAPPER_SHARED_SECRET during transition
Run:
wrangler dev

or deploy:

wrangler deploy
Minimum manual setup still required
1. Paste the D1 database ID

In wrangler.toml:

database_id = "PASTE_DB_ID_HERE"
2. Insert at least one client row
3. Insert at least one API key row

The wrapper cannot authenticate against D1 until real rows exist.

Notes
Keep this separate from the rail repo
Wrapper = front door
Rail = enforcement engine
DB-backed keys are the target
Shared secret is temporary only
Keep the wrapper thin
Do not move enforcement logic out of the rail

Current source files referenced: :contentReference[oaicite:0]{index=0} :contentReference[oaicite:1]{index=1}