# AgenticRail Wrapper

Front-door Worker for AgenticRail. Handles auth, request normalisation, executor, and usage logging.

## Flow

```
Client (Bearer token)
  → POST /v1/evaluate
  → Wrapper: auth + normalise + forward
  → Gate Worker (x-slp8-key injected by wrapper)
  → Core Worker (internal binding)
  → ALLOW / DENY / HALT + signed receipt
  → Wrapper executor (ALLOW only) → D1 execution_log
  → Client response
```

## Routes

- `GET /v1/health`
- `POST /v1/evaluate`

## What it does

1. Authenticates Bearer token against D1 `api_keys` table
2. Validates external request shape
3. Normalises into rail payload (adds `schema_version`, `model_id`, `function`, `nonce`, `ts_ms`)
4. Calls AgenticRail gate
5. On ALLOW: triggers executor, writes `execution_log` + `sequence_state` to D1
6. Logs usage to D1 `usage_logs`
7. Returns flat client-facing response

## Executor coverage

All 8 MSMD canonical action_types are handled:

| action_type | Behaviour |
|---|---|
| `RECORD_RESULT` | Writes result to `execution_log` |
| `CHECK_STATE` | Reads `sequence_state` (no write) |
| `VALIDATE_INPUT` | Counts and validates input keys |
| `CLARIFY_NEXT_STEP` | Derives next step from MSMD order |
| `SELECT_NEXT_STEP` | Writes `next_step` to `sequence_state` |
| `WAIT_FOR_SIGNAL` | Writes `waiting` status + signal key |
| `PAUSE_CYCLE` | Writes `paused` status + timestamp |
| `REDUCE_STIMULUS` | Writes `cooldown` state |

Idempotency: each execution keyed on `pack_id` (UNIQUE in `execution_log`). Duplicate requests return cached result.

## Auth

### D1-backed API keys (primary)

Key format: `ar_live_<prefix>.<secret>` — only SHA-256 hash stored.

### Shared secret fallback

`WRAPPER_SHARED_SECRET` env var — for setup/testing only.

## External request contract

Client sends:

```json
{
  "sequence_id": "seq_001",
  "step": "execution",
  "action_type": "RECORD_RESULT",
  "action": "record payment result",
  "inputs": { "result": "payment_complete" }
}
```

Wrapper adds: `schema_version`, `model_id`, `function`, `nonce`, `ts_ms`.

## Response contract

```json
{
  "decision": "ALLOW",
  "executed": true,
  "reasons": [],
  "sequence_id": "seq_001",
  "step": "execution",
  "action_type": "RECORD_RESULT",
  "result": { "status": "recorded", "exec_id": "..." },
  "receipt": { "pack_id": "...", "signature": "...", "version": "slp8_receipt_v2" }
}
```

## D1 schema

See `schema.sql`. Tables: `clients`, `api_keys`, `usage_logs`, `execution_log`, `sequence_state`.

## Deploy

```bash
cd agenticrail-wrapper
# Edit wrangler.toml: paste real database_id
npx wrangler deploy
```

Seed with `schema.sql` + `seed.sql` for API key rows.

## Principles

- Wrapper = front door only
- Enforcement logic stays in the rail (gate + core)
- Never move policy or DO state here
