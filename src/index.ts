export interface Env {
  RAIL: Fetcher;
  RAIL_PUBLIC_KEY?: string;
  RAIL_SHARED_SECRET?: string;
  DEMO_KEY?: string;
  DB: D1Database;
  RATE_LIMITER: DurableObjectNamespace;
  CORS_ALLOW_ORIGIN?: string;
}

// ── Global Durable Object rate limiter ───────────────────────────────────────
// One DO instance per rate-limit key (e.g. "demo:1.2.3.4", "prod:key_abc").
// Single-threaded per-instance: no races, truly global across Workers instances.
export class RateLimiter {
  private count = 0;
  private windowStart = 0;

  constructor(_state: DurableObjectState) {}

  async fetch(req: Request): Promise<Response> {
    const { limitPerMin } = await req.json<{ limitPerMin: number }>();
    const now = Date.now();
    if (!this.windowStart || now - this.windowStart > 60_000) {
      this.count = 1;
      this.windowStart = now;
      return Response.json({ ok: true });
    }
    if (this.count >= limitPerMin) return Response.json({ ok: false });
    this.count++;
    return Response.json({ ok: true });
  }
}

async function rateLimitOk(ns: DurableObjectNamespace, key: string, limitPerMin: number): Promise<boolean> {
  try {
    const id = ns.idFromName(key);
    const stub = ns.get(id);
    const res = await stub.fetch('https://rl.internal/check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ limitPerMin }),
    });
    const data = await res.json<{ ok: boolean }>();
    return data.ok;
  } catch (e) {
    // DO unavailable — fail open to preserve availability; log so outages are visible
    console.warn("rate_limiter_unavailable", { key, error: e instanceof Error ? e.message : String(e) });
    return true;
  }
}

// Convenience wrappers
async function demoRateLimitOk(ns: DurableObjectNamespace, ip: string): Promise<boolean>    { return rateLimitOk(ns, `demo:${ip}`, 300); }
async function prodRateLimitOk(ns: DurableObjectNamespace, keyId: string): Promise<boolean> { return rateLimitOk(ns, `prod:${keyId}`, 3000); }

type ExternalEvaluateRequest = {
  sequence_id: string;
  step: string;
  function?: string;
  action_type: string;
  action?: string;
  inputs?: Record<string, unknown>;
  nonce?: string;
  spine?: "msmd" | "hokianga";
  step_order?: string[];
};

type RailRequest = {
  schema_version: "1.0";
  model_id: string;
  sequence_id: string;
  step: string;
  function: string;
  action_type: string;
  nonce: string;
  ts_ms: number;
  action: string;
  inputs: Record<string, unknown>;
  step_order?: string[];
};

type RailResponse = {
  decision: "ALLOW" | "DENY" | "HALT";
  executed?: boolean;
  reasons?: string[];
  meta?: {
    action_type?: string;
    function?: string;
    model_id?: string;
    sequence_id?: string;
    step?: string;
    policy_map_ids?: string[];
  };
  pack_id?: string;
  key_id?: string;
  signature?: string;
  signature_alg?: string;
  payload_hash?: string;
  prev_receipt_id?: string;
  ts_ms?: number;
  version?: string;
};

type ExecutorResult = {
  status: "submitted" | "skipped" | "failed";
  message?: string;
  data?: Record<string, unknown>;
  exec_id?: string;
  idempotent?: boolean;
};

type ApiKeyRecord = {
  key_id: string;
  client_id: string;
  key_hash: string;
  key_prefix: string;
  key_status: string;
  client_status: string;
};

type AuthSuccess = {
  ok: true;
  keyId: string;
  clientId: string;
};

type AuthFailure = {
  ok: false;
  status: number;
  error: string;
  message: string;
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const corsOrigin = env.CORS_ALLOW_ORIGIN || "*";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": corsOrigin,
          "access-control-allow-methods": "POST, GET, OPTIONS",
          "access-control-allow-headers": "content-type, authorization",
          "access-control-max-age": "86400",
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/v1/health") {
      return jsonResponse(200, {
        ok: true,
        service: "agenticrail-wrapper",
        now: Date.now(),
      }, corsOrigin);
    }

    if (request.method === "POST" && url.pathname === "/v1/evaluate") {
      try {
        const auth = request.headers.get("authorization") || "";
        const token = getBearerToken(auth);

        if (!token) {
          return jsonResponse(401, {
            error: "missing_bearer_token",
            message: "Authorization: Bearer <token> required",
          }, corsOrigin);
        }

        // Demo key bypass — no D1 lookup, fixed auth result
        let authResult: AuthSuccess | AuthFailure;
        if (env.DEMO_KEY && token === env.DEMO_KEY) {
          const ip = request.headers.get("cf-connecting-ip") || "demo";
          if (env.RATE_LIMITER && !await demoRateLimitOk(env.RATE_LIMITER, ip)) {
            return jsonResponse(429, { error: "rate_limited", message: "Demo limit: 60 req/min per IP" }, corsOrigin);
          }
          authResult = { ok: true, keyId: "key_demo", clientId: "demo" };
        } else {
          authResult = await authenticateApiKey(token, env);
        }
        if (!authResult.ok) {
          return jsonResponse(authResult.status, {
            error: authResult.error,
            message: authResult.message,
          }, corsOrigin);
        }

        // Production key rate limit (300 req/min per key_id — globally enforced via DO)
        if (authResult.clientId !== "demo" && env.RATE_LIMITER && !await prodRateLimitOk(env.RATE_LIMITER, authResult.keyId)) {
          return jsonResponse(429, { error: "rate_limited", message: "Rate limit: 300 req/min per key" }, corsOrigin);
        }

        // Rail config check: production requests need RAIL_SHARED_SECRET.
        // Without it, the gate rejects with 401. Routing uses the RAIL service binding — no endpoint URL needed.
        if (authResult.clientId !== "demo" && !env.RAIL_SHARED_SECRET) {
          return jsonResponse(500, {
            error: "rail_not_configured",
            message: "RAIL_SHARED_SECRET is not configured. Set this environment variable to the Gate's API key.",
          }, corsOrigin);
        }

        const parsedBody =
          await parseJsonBody<Partial<ExternalEvaluateRequest>>(request);
        if (!parsedBody.ok) {
          return jsonResponse(400, {
            error: "invalid_json",
            message: parsedBody.message,
          }, corsOrigin);
        }

        const body = parsedBody.data;
        const validationError = validateExternalRequest(body);
        if (validationError) {
          return jsonResponse(400, {
            error: "invalid_request",
            message: validationError,
          }, corsOrigin);
        }

        const ext = normalizeExternalRequest(body as ExternalEvaluateRequest);

        // Demo isolation: ensure sequence_id has demo- prefix
        const isDemo = authResult.clientId === "demo";
        if (isDemo && !ext.sequence_id.startsWith("demo-")) {
          ext.sequence_id = "demo-" + ext.sequence_id;
        }

        // DO isolation: model_id is prefixed by spine so Hokianga and MSMD
        // sequences never share a Durable Object (core keys the DO as
        // `${model_id}::${sequence_id}`, recomputed on every request).
        // "settle" appears in both spines — callers in a Hokianga sequence
        // MUST pass spine: "hokianga" so the settle step hits the same DO
        // as the preceding Hokianga steps. Without it, detectSpine("settle")
        // falls back to "msmd" and the final step lands on a different DO,
        // producing a guaranteed SEQUENCE_VIOLATION.
        const spine = ext.spine ?? detectSpine(ext.step);
        const modelIdPrefix = spine === "hokianga" ? "hokianga" : "client";

        const railPayload: RailRequest = {
          schema_version: "1.0",
          model_id: `${modelIdPrefix}:${authResult.clientId}`,
          sequence_id: ext.sequence_id,
          step: ext.step,
          function: ext.function ?? ext.step,
          action_type: ext.action_type,
          nonce: ext.nonce ?? crypto.randomUUID(),
          ts_ms: Date.now(),
          action: ext.action ?? `run ${ext.function ?? ext.step}`,
          inputs: ext.inputs ?? {},
          step_order: ext.step_order,
        };

        const railHeaders: Record<string, string> = {
          "content-type": "application/json",
        };

        // Demo mode: use gate's demo key so gate skips its response cache.
        // This ensures replay scenarios reach the Durable Object nonce check.
        const railKey = isDemo ? (env.DEMO_KEY || "") : (env.RAIL_SHARED_SECRET || "");
        if (railKey) railHeaders["x-slp8-key"] = railKey;

        const railRes = await env.RAIL.fetch("https://rail.internal/evaluate", {
          method: "POST",
          headers: railHeaders,
          body: JSON.stringify(railPayload),
        });

        const railText = await railRes.text();
        let rawRailJson: unknown = null;

        try {
          rawRailJson = railText ? JSON.parse(railText) : null;
        } catch {
          rawRailJson = null;
        }

        const railJson = parseRailResponse(rawRailJson);

        if (!railRes.ok || !railJson) {
          console.warn("rail_unavailable", { status: railRes.status, body: typeof rawRailJson === "string" ? rawRailJson.slice(0, 200) : rawRailJson });
          return jsonResponse(502, {
            error: "rail_unavailable",
            message: "Rail did not return a valid response",
          }, corsOrigin);
        }

        if (env.RAIL_PUBLIC_KEY) {
          if (!railJson.signature) {
            return jsonResponse(502, {
              error: "rail_signature_missing",
              message:
                "RAIL_PUBLIC_KEY is configured but rail returned no signature",
            }, corsOrigin);
          }

          const verified = await verifyRailReceipt(
            env.RAIL_PUBLIC_KEY,
            railJson,
          );
          if (!verified) {
            return jsonResponse(502, {
              error: "rail_signature_invalid",
              message: "Rail response signature failed verification",
            }, corsOrigin);
          }
        }

        const expectedFunction = railPayload.function;
        const expectedAction = railPayload.action_type;
        const expectedSequenceId = railPayload.sequence_id;
        const expectedStep = railPayload.step;

        const returnedFunction = railJson.meta?.function;
        const returnedAction = railJson.meta?.action_type;
        const returnedSequenceId = railJson.meta?.sequence_id;
        const returnedStep = railJson.meta?.step;

        if (
          railJson.decision === "ALLOW" &&
          ((returnedFunction !== undefined &&
            returnedFunction !== expectedFunction) ||
            (returnedAction !== undefined &&
              returnedAction !== expectedAction) ||
            (returnedSequenceId !== undefined &&
              returnedSequenceId !== expectedSequenceId) ||
            (returnedStep !== undefined && returnedStep !== expectedStep))
        ) {
          return jsonResponse(502, {
            error: "rail_meta_mismatch",
            message: "ALLOW returned but meta does not match expected payload",
            expected: {
              function: expectedFunction,
              action_type: expectedAction,
              sequence_id: expectedSequenceId,
              step: expectedStep,
            },
            received: {
              function: returnedFunction ?? null,
              action_type: returnedAction ?? null,
              sequence_id: returnedSequenceId ?? null,
              step: returnedStep ?? null,
            },
          }, corsOrigin);
        }

        if (
          railJson.decision !== "ALLOW" &&
          ((returnedSequenceId !== undefined &&
            returnedSequenceId !== expectedSequenceId) ||
            (returnedStep !== undefined && returnedStep !== expectedStep))
        ) {
          console.warn("rail_meta_mismatch_on_non_allow", {
            expected: {
              sequence_id: expectedSequenceId,
              step: expectedStep,
            },
            received: {
              sequence_id: returnedSequenceId ?? null,
              step: returnedStep ?? null,
            },
            decision: railJson.decision,
          });
        }

        let executorResult: ExecutorResult = {
          status: "skipped",
          message: "No execution triggered",
        };

        if (railJson.decision === "ALLOW") {
          executorResult = await runExecutor(railPayload, railJson.pack_id ?? "", env, spine);
        }

        const wrapperExecuted = executorResult.status === "submitted";

        const logResult = await safeLogUsage(env, {
          log_id: crypto.randomUUID(),
          client_id: authResult.clientId,
          key_id: authResult.keyId,
          sequence_id: railPayload.sequence_id,
          decision: railJson.decision,
          created_at: new Date().toISOString(),
        });

        return jsonResponse(200, {
          decision: railJson.decision,
          executed: wrapperExecuted,
          pack_id: railJson.pack_id ?? null,
          reasons: Array.isArray(railJson.reasons) ? railJson.reasons : [],
          sequence_id: railPayload.sequence_id,
          step: railPayload.step,
          function: railPayload.function,
          action_type: railPayload.action_type,
          model_id: railPayload.model_id,
          result: executorResult,
          receipt: {
            pack_id: railJson.pack_id ?? null,
            key_id: railJson.key_id ?? null,
            signature: railJson.signature ?? null,
            signature_alg: railJson.signature_alg ?? null,
            payload_hash: railJson.payload_hash ?? null,
            prev_receipt_id: railJson.prev_receipt_id ?? null,
            ts_ms: railJson.ts_ms ?? null,
            version: railJson.version ?? null,
          },
          log: {
            ok: logResult.ok,
            error: logResult.ok ? null : "usage_log_failed",
          },
        }, corsOrigin);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Unknown wrapper error";
        return jsonResponse(500, {
          error: "wrapper_error",
          message,
        }, corsOrigin);
      }
    }

    return jsonResponse(404, {
      error: "not_found",
      message: "Route not found",
    }, corsOrigin);
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const cutoff90d = new Date(event.scheduledTime - 90 * 24 * 60 * 60 * 1000).toISOString();
    const cutoff30d = new Date(event.scheduledTime - 30 * 24 * 60 * 60 * 1000).toISOString();
    const results = await Promise.allSettled([
      env.DB.prepare("DELETE FROM usage_logs WHERE created_at < ?").bind(cutoff90d).run(),
      env.DB.prepare("DELETE FROM execution_log WHERE created_at < ?").bind(cutoff90d).run(),
      env.DB.prepare("DELETE FROM sequence_state WHERE updated_at < ?").bind(cutoff30d).run(),
    ]);
    for (const [i, r] of results.entries()) {
      if (r.status === "rejected") {
        console.error(`d1_retention_cleanup[${i}] failed`, String(r.reason));
      } else {
        console.log(`d1_retention_cleanup[${i}] ok`, { changes: r.value.meta?.changes ?? 0 });
      }
    }
  },
};

async function authenticateApiKey(
  token: string,
  env: Env,
): Promise<AuthSuccess | AuthFailure> {
  const keyParts = splitPresentedApiKey(token);
  if (!keyParts) {
    return {
      ok: false,
      status: 401,
      error: "invalid_api_key",
      message: "Malformed API key",
    };
  }

  const keyHash = await sha256Hex(token);

  const row = await env.DB.prepare(
    `
    SELECT
      ak.key_id,
      ak.client_id,
      ak.key_hash,
      ak.key_prefix,
      ak.status AS key_status,
      c.status AS client_status
    FROM api_keys ak
    LEFT JOIN clients c ON c.client_id = ak.client_id
    WHERE ak.key_prefix = ?
    LIMIT 1
    `,
  )
    .bind(keyParts.prefix)
    .first<ApiKeyRecord>();

  if (!row) {
    return {
      ok: false,
      status: 401,
      error: "invalid_api_key",
      message: "Key not found",
    };
  }

  if (row.key_hash !== keyHash) {
    return {
      ok: false,
      status: 401,
      error: "invalid_api_key",
      message: "Key mismatch",
    };
  }

  if (row.key_status !== "active") {
    return {
      ok: false,
      status: 403,
      error: "key_disabled",
      message: "API key disabled",
    };
  }

  if (row.client_status && row.client_status !== "active") {
    return {
      ok: false,
      status: 403,
      error: "client_disabled",
      message: "Client account disabled",
    };
  }

  try {
    await env.DB.prepare(
      `
      UPDATE api_keys
      SET last_used_at = ?
      WHERE key_id = ?
      `,
    )
      .bind(new Date().toISOString(), row.key_id)
      .run();
  } catch (err) {
    console.warn("last_used_at update failed", {
      key_id: row.key_id,
      error: err instanceof Error ? err.message : "unknown_error",
    });
  }

  return {
    ok: true,
    keyId: row.key_id,
    clientId: row.client_id,
  };
}

function getBearerToken(authHeader: string): string | null {
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function splitPresentedApiKey(fullKey: string): { prefix: string } | null {
  const dotIndex = fullKey.indexOf(".");
  if (dotIndex <= 0) return null;
  if (dotIndex !== fullKey.lastIndexOf(".")) return null;

  const prefix = fullKey.slice(0, dotIndex).trim();
  const secret = fullKey.slice(dotIndex + 1).trim();
  if (!prefix || !secret) return null;

  return { prefix };
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function parseJsonBody<T>(
  request: Request,
): Promise<{ ok: true; data: T } | { ok: false; message: string }> {
  try {
    const data = (await request.json()) as T;
    return { ok: true, data };
  } catch {
    return {
      ok: false,
      message: "Request body must be valid JSON",
    };
  }
}

function validateExternalRequest(
  body: Partial<ExternalEvaluateRequest>,
): string | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "Body must be JSON object";
  }

  if (!isNonEmptyString(body.sequence_id)) {
    return "sequence_id is required";
  }

  if (!isNonEmptyString(body.step)) {
    return "step is required";
  }

  if (body.function !== undefined && !isNonEmptyString(body.function)) {
    return "function must be a non-empty string if provided";
  }

  if (!isNonEmptyString(body.action_type)) {
    return "action_type is required";
  }

  if (body.action !== undefined && !isNonEmptyString(body.action)) {
    return "action must be a non-empty string if provided";
  }

  if (body.nonce !== undefined && !isNonEmptyString(body.nonce)) {
    return "nonce must be a non-empty string if provided";
  }

  if (body.inputs !== undefined && !isPlainObject(body.inputs)) {
    return "inputs must be an object if provided";
  }

  if (body.spine !== undefined && body.spine !== "msmd" && body.spine !== "hokianga") {
    return "spine must be 'msmd' or 'hokianga' if provided";
  }

  return null;
}

function normalizeExternalRequest(
  body: ExternalEvaluateRequest,
): ExternalEvaluateRequest {
  return {
    sequence_id: body.sequence_id.trim(),
    step: body.step.trim(),
    function: body.function?.trim(),
    action_type: body.action_type.trim(),
    action: body.action?.trim(),
    inputs: body.inputs ?? {},
    nonce: body.nonce?.trim(),
    spine: body.spine,
    step_order: Array.isArray(body.step_order) ? body.step_order.map(s => String(s).trim()).filter(Boolean) : undefined,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function parseRailResponse(value: unknown): RailResponse | null {
  if (!isPlainObject(value)) return null;

  // Check for new rail response shape: { status: "OK", pack: { ... }, pack_id: ... }
  let rawDecision: unknown;
  let reasons: string[] | undefined;
  let executed: boolean | undefined;
  let meta: RailResponse["meta"] | undefined;
  let pack_id: string | undefined;
  let key_id: string | undefined;
  let signature: string | undefined;
  let signature_alg: string | undefined;
  let payload_hash: string | undefined;
  let prev_receipt_id: string | undefined;
  let ts_ms: number | undefined;
  let version: string | undefined;

  if (value.status === "OK" && isPlainObject(value.pack)) {
    // New shape
    const pack = value.pack;
    rawDecision = pack.decision;
    // decision validation will happen later

    if (pack.reasons !== undefined) {
      if (
        !Array.isArray(pack.reasons) ||
        pack.reasons.some((v) => typeof v !== "string")
      ) {
        return null;
      }
      reasons = pack.reasons;
    }

    if (pack.executed !== undefined) {
      if (typeof pack.executed !== "boolean") return null;
      executed = pack.executed;
    }

    if (pack.meta !== undefined) {
      if (!isPlainObject(pack.meta)) return null;

      const metaFields = [
        "action_type",
        "function",
        "model_id",
        "sequence_id",
        "step",
      ] as const;

      for (const field of metaFields) {
        const fieldValue = pack.meta[field];
        if (fieldValue !== undefined && typeof fieldValue !== "string") {
          return null;
        }
      }

      if (pack.meta.policy_map_ids !== undefined) {
        if (
          !Array.isArray(pack.meta.policy_map_ids) ||
          pack.meta.policy_map_ids.some((v) => typeof v !== "string")
        ) {
          return null;
        }
      }

      meta = {
        action_type: pack.meta.action_type,
        function: pack.meta.function,
        model_id: pack.meta.model_id,
        sequence_id: pack.meta.sequence_id,
        step: pack.meta.step,
        policy_map_ids: pack.meta.policy_map_ids,
      };
    }

    // Top-level optional fields
    if (value.pack_id !== undefined) {
      if (typeof value.pack_id !== "string") return null;
      pack_id = value.pack_id;
    }
    if (value.key_id !== undefined) {
      if (typeof value.key_id !== "string") return null;
      key_id = value.key_id;
    }
    if (value.signature !== undefined) {
      if (typeof value.signature !== "string") return null;
      signature = value.signature;
    }
    if (value.signature_alg !== undefined) {
      if (typeof value.signature_alg !== "string") return null;
      signature_alg = value.signature_alg;
    }
    if (value.payload_hash !== undefined) {
      if (typeof value.payload_hash !== "string") return null;
      payload_hash = value.payload_hash;
    }
    if (value.prev_receipt_id !== undefined) {
      if (typeof value.prev_receipt_id !== "string") return null;
      prev_receipt_id = value.prev_receipt_id;
    }
    if (value.ts_ms !== undefined) {
      if (typeof value.ts_ms !== "number") return null;
      ts_ms = value.ts_ms;
    }
    if (value.version !== undefined) {
      if (typeof value.version !== "string") return null;
      version = value.version;
    }
  } else {
    // Legacy shape
    rawDecision = value.decision ?? value.status;

    if (value.reasons !== undefined) {
      if (
        !Array.isArray(value.reasons) ||
        value.reasons.some((v) => typeof v !== "string")
      ) {
        return null;
      }
      reasons = value.reasons;
    } else {
      const derivedReasons: string[] = [];
      if (typeof value.reason_code === "string") {
        derivedReasons.push(value.reason_code);
      }
      if (typeof value.reason_detail === "string") {
        derivedReasons.push(value.reason_detail);
      }
      if (derivedReasons.length > 0) {
        reasons = derivedReasons;
      }
    }

    if (value.meta !== undefined) {
      if (!isPlainObject(value.meta)) return null;

      const metaFields = [
        "action_type",
        "function",
        "model_id",
        "sequence_id",
        "step",
      ] as const;

      for (const field of metaFields) {
        const fieldValue = value.meta[field];
        if (fieldValue !== undefined && typeof fieldValue !== "string") {
          return null;
        }
      }

      if (value.meta.policy_map_ids !== undefined) {
        if (
          !Array.isArray(value.meta.policy_map_ids) ||
          value.meta.policy_map_ids.some((v) => typeof v !== "string")
        ) {
          return null;
        }
      }

      meta = {
        action_type: value.meta.action_type,
        function: value.meta.function,
        model_id: value.meta.model_id,
        sequence_id: value.meta.sequence_id,
        step: value.meta.step,
        policy_map_ids: value.meta.policy_map_ids,
      };
    }

    const optionalStringFields = [
      "pack_id",
      "key_id",
      "signature",
      "signature_alg",
      "payload_hash",
      "prev_receipt_id",
      "version",
    ] as const;

    for (const field of optionalStringFields) {
      const fieldValue = (value as Record<string, unknown>)[field];
      if (fieldValue !== undefined && typeof fieldValue !== "string") {
        return null;
      }
    }

    if (value.executed !== undefined && typeof value.executed !== "boolean") {
      return null;
    }

    if (value.ts_ms !== undefined && typeof value.ts_ms !== "number") {
      return null;
    }

    pack_id = typeof value.pack_id === "string" ? value.pack_id : undefined;
    key_id = typeof value.key_id === "string" ? value.key_id : undefined;
    signature = typeof value.signature === "string" ? value.signature : undefined;
    signature_alg =
      typeof value.signature_alg === "string" ? value.signature_alg : undefined;
    payload_hash =
      typeof value.payload_hash === "string" ? value.payload_hash : undefined;
    prev_receipt_id =
      typeof value.prev_receipt_id === "string"
        ? value.prev_receipt_id
        : undefined;
    ts_ms = typeof value.ts_ms === "number" ? value.ts_ms : undefined;
    version = typeof value.version === "string" ? value.version : undefined;
    executed =
      typeof value.executed === "boolean" ? value.executed : undefined;
  }

  // Validate decision (common for both shapes)
  if (
    rawDecision !== "ALLOW" &&
    rawDecision !== "DENY" &&
    rawDecision !== "HALT"
  ) {
    return null;
  }

  return {
    decision: rawDecision as "ALLOW" | "DENY" | "HALT",
    executed,
    reasons,
    meta,
    pack_id,
    key_id,
    signature,
    signature_alg,
    payload_hash,
    prev_receipt_id,
    ts_ms,
    version,
  };
}

async function verifyRailReceipt(
  publicKeyString: string,
  railJson: RailResponse,
): Promise<boolean> {
  try {
    if (!railJson.signature) return false;

    const signatureBytes = base64ToBytes(railJson.signature);
    const publicKeyBytes = base64ToBytes(publicKeyString);

    const keyData =
      publicKeyBytes.length === 32
        ? buildEd25519SpkiFromRaw(publicKeyBytes)
        : publicKeyBytes;

    const publicKey = await crypto.subtle.importKey(
      "spki",
      keyData,
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    const signedReceipt = buildSignedReceiptPayload(railJson);
    const signedBytes = new TextEncoder().encode(canonicalJson(signedReceipt));

    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signatureBytes,
      signedBytes,
    );
  } catch (err) {
    console.warn("rail receipt verification failed", {
      error: err instanceof Error ? err.message : "unknown_error",
    });
    return false;
  }
}

function buildSignedReceiptPayload(
  railJson: RailResponse,
): Record<string, unknown> {
  const { signature: _signature, ...rest } =
    railJson as RailResponse & Record<string, unknown>;

  return rest;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

function base64ToBytes(base64OrUrl: string): Uint8Array {
  const normalized = base64OrUrl
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/\s+/g, "");

  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

function buildEd25519SpkiFromRaw(rawKey: Uint8Array): ArrayBuffer {
  const prefix = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);

  const out = new Uint8Array(prefix.length + rawKey.length);
  out.set(prefix, 0);
  out.set(rawKey, prefix.length);
  return out.buffer;
}

function jsonResponse(status: number, data: unknown, corsOrigin = "*"): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": corsOrigin,
    },
  });
}

async function safeLogUsage(
  env: Env,
  row: {
    log_id: string;
    client_id: string;
    key_id: string;
    sequence_id: string;
    decision: string;
    created_at: string;
  },
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await logUsage(env, row);
    return { ok: true };
  } catch (err) {
    console.warn("usage log failed", {
      log_id: row.log_id,
      error: err instanceof Error ? err.message : "unknown_error",
    });
    return {
      ok: false,
      error: err instanceof Error ? err.message : "usage_log_failed",
    };
  }
}

async function logUsage(
  env: Env,
  row: {
    log_id: string;
    client_id: string;
    key_id: string;
    sequence_id: string;
    decision: string;
    created_at: string;
  },
): Promise<void> {
  await env.DB.prepare(
    `
    INSERT INTO usage_logs (
      log_id,
      client_id,
      key_id,
      sequence_id,
      decision,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    `,
  )
    .bind(
      row.log_id,
      row.client_id,
      row.key_id,
      row.sequence_id,
      row.decision,
      row.created_at,
    )
    .run();
}

// ── Executor context ──────────────────────────────────────────────────────────

type ExecutorContext = {
  payload: RailRequest;
  packId: string;
  env: Env;
  spine: "msmd" | "hokianga";
};

// ── Idempotency check ─────────────────────────────────────────────────────────

async function getExistingExecution(
  packId: string,
  env: Env,
): Promise<ExecutorResult | null> {
  if (!packId || !env.DB) return null;
  try {
    const row = await env.DB
      .prepare(
        "SELECT status, result_json FROM execution_log WHERE pack_id = ? LIMIT 1",
      )
      .bind(packId)
      .first<{ status: string; result_json: string | null }>();

    if (!row) return null;

    const data = row.result_json
      ? (JSON.parse(row.result_json) as Record<string, unknown>)
      : undefined;

    return {
      status: row.status as "submitted" | "failed",
      data,
      idempotent: true,
    };
  } catch {
    return null;
  }
}

// ── Execution log write ───────────────────────────────────────────────────────

async function writeExecutionLog(
  ctx: ExecutorContext,
  status: "ok" | "failed",
  result: Record<string, unknown>,
): Promise<string> {
  const exec_id = crypto.randomUUID();
  await ctx.env.DB
    .prepare(
      `INSERT INTO execution_log
         (exec_id, pack_id, sequence_id, step, action_type, status, result_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      exec_id,
      ctx.packId,
      ctx.payload.sequence_id,
      ctx.payload.step,
      ctx.payload.action_type,
      status,
      JSON.stringify(result),
      new Date().toISOString(),
    )
    .run();
  return exec_id;
}

// ── Handler: RECORD_RESULT ────────────────────────────────────────────────────

async function handleRecordResult(ctx: ExecutorContext): Promise<ExecutorResult> {
  const result = ctx.payload.inputs.result;
  if (result === undefined) {
    return {
      status: "failed",
      message: "inputs.result is required for RECORD_RESULT",
    };
  }
  const exec_id = await writeExecutionLog(ctx, "ok", { result });
  return { status: "submitted", exec_id, data: { result } };
}

// ── Handler: CHECK_STATE ──────────────────────────────────────────────────────

async function handleCheckState(ctx: ExecutorContext): Promise<ExecutorResult> {
  if (!ctx.env.DB) {
    return { status: "skipped", message: "DB not bound" };
  }
  const row = await ctx.env.DB
    .prepare(
      "SELECT state_json FROM sequence_state WHERE sequence_id = ? LIMIT 1",
    )
    .bind(ctx.payload.sequence_id)
    .first<{ state_json: string }>();

  const state = row?.state_json
    ? (JSON.parse(row.state_json) as Record<string, unknown>)
    : null;

  return { status: "submitted", data: { state } };
}

// ── Step-order spines (used by CLARIFY_NEXT_STEP and model_id isolation) ─────

const MSMD_STEPS = [
  "intake", "disruption", "instability", "state_read",
  "internal_driver", "execution", "boundary", "settle",
] as const;

const HOKIANGA_STEPS = [
  "dialect_request", "hapuu_identity", "corpus_query", "provenance_token",
  "compression_check", "kaitiaki_gate", "output_authorised", "settle",
] as const;

// Returns the spine for a given step name. Falls back to "msmd" for any step
// not explicitly listed in a known non-MSMD spine.
function detectSpine(step: string): "hokianga" | "msmd" {
  // "settle" appears in both spines — the MSMD check wins, which is correct
  // for MSMD sequences. Hokianga sequences are identified by their earlier steps.
  if ((HOKIANGA_STEPS as readonly string[]).includes(step) &&
      !(MSMD_STEPS as readonly string[]).includes(step)) {
    return "hokianga";
  }
  return "msmd";
}

// ── sequence_state upsert ─────────────────────────────────────────────────────

async function upsertSequenceState(
  ctx: ExecutorContext,
  state: Record<string, unknown>,
): Promise<void> {
  await ctx.env.DB
    .prepare(
      `INSERT INTO sequence_state (sequence_id, state_json, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(sequence_id) DO UPDATE
         SET state_json = excluded.state_json,
             updated_at = excluded.updated_at`,
    )
    .bind(ctx.payload.sequence_id, JSON.stringify(state), new Date().toISOString())
    .run();
}

// ── Handler: VALIDATE_INPUT ───────────────────────────────────────────────────

async function handleValidateInput(ctx: ExecutorContext): Promise<ExecutorResult> {
  const inputs = ctx.payload.inputs;
  const userKeys = Object.keys(inputs).filter((k) => !k.startsWith("_"));
  const valid = userKeys.length > 0;
  const result = valid
    ? { valid: true, field_count: userKeys.length }
    : { valid: false, errors: ["inputs contains no user-supplied fields"] };
  const exec_id = await writeExecutionLog(ctx, "ok", result);
  return { status: "submitted", exec_id, data: result };
}

// ── Handler: CLARIFY_NEXT_STEP ────────────────────────────────────────────────
// Pure read — derives next recommended step from execution_log. No write.
// Spine is selected from the current payload step so that Hokianga sequences
// get Hokianga step guidance and MSMD sequences get MSMD step guidance.

async function handleClarifyNextStep(ctx: ExecutorContext): Promise<ExecutorResult> {
  if (!ctx.env.DB) {
    return { status: "skipped", message: "DB not bound" };
  }

  const activeSpine: readonly string[] =
    ctx.spine === "hokianga" ? HOKIANGA_STEPS : MSMD_STEPS;

  const row = await ctx.env.DB
    .prepare(
      `SELECT step FROM execution_log
       WHERE sequence_id = ? AND status = 'ok'
       ORDER BY created_at DESC LIMIT 1`,
    )
    .bind(ctx.payload.sequence_id)
    .first<{ step: string }>();

  const currentStep = row?.step ?? null;
  const currentIndex = currentStep ? activeSpine.indexOf(currentStep) : -1;
  const nextIndex = currentIndex + 1;
  const nextStep = nextIndex < activeSpine.length ? activeSpine[nextIndex] : null;

  return {
    status: "submitted",
    data: { current_step: currentStep, current_index: currentIndex, next_step: nextStep },
  };
}

// ── Handler: SELECT_NEXT_STEP ─────────────────────────────────────────────────

async function handleSelectNextStep(ctx: ExecutorContext): Promise<ExecutorResult> {
  const nextStep = ctx.payload.inputs.next_step;
  if (typeof nextStep !== "string" || !nextStep.trim()) {
    return { status: "failed", message: "inputs.next_step is required for SELECT_NEXT_STEP" };
  }
  const state = { selected_step: nextStep.trim(), selected_at: Date.now() };
  await upsertSequenceState(ctx, state);
  const exec_id = await writeExecutionLog(ctx, "ok", state);
  return { status: "submitted", exec_id, data: state };
}

// ── Handler: WAIT_FOR_SIGNAL ──────────────────────────────────────────────────

async function handleWaitForSignal(ctx: ExecutorContext): Promise<ExecutorResult> {
  const signalKey = typeof ctx.payload.inputs.signal_key === "string"
    ? ctx.payload.inputs.signal_key.trim()
    : `signal:${ctx.payload.sequence_id}:${ctx.payload.step}`;
  const state = { status: "waiting", signal_key: signalKey, waiting_since: Date.now() };
  await upsertSequenceState(ctx, state);
  const exec_id = await writeExecutionLog(ctx, "ok", state);
  return { status: "submitted", exec_id, data: state };
}

// ── Handler: PAUSE_CYCLE ──────────────────────────────────────────────────────

async function handlePauseCycle(ctx: ExecutorContext): Promise<ExecutorResult> {
  const state = { status: "paused", paused_at: Date.now() };
  await upsertSequenceState(ctx, state);
  const exec_id = await writeExecutionLog(ctx, "ok", state);
  return { status: "submitted", exec_id, data: state };
}

// ── Handler: REDUCE_STIMULUS ──────────────────────────────────────────────────

async function handleReduceStimulus(ctx: ExecutorContext): Promise<ExecutorResult> {
  const cooldownMs = typeof ctx.payload.inputs.cooldown_ms === "number"
    ? Math.max(0, ctx.payload.inputs.cooldown_ms)
    : 5000;
  const until_ms = Date.now() + cooldownMs;
  const state = { status: "cooldown", cooldown_ms: cooldownMs, until_ms };
  await upsertSequenceState(ctx, state);
  const exec_id = await writeExecutionLog(ctx, "ok", state);
  return { status: "submitted", exec_id, data: state };
}

// ── runExecutor ───────────────────────────────────────────────────────────────

async function runExecutor(
  payload: RailRequest,
  packId: string,
  env: Env,
  spine: "msmd" | "hokianga",
): Promise<ExecutorResult> {
  const existing = await getExistingExecution(packId, env);
  if (existing) return existing;

  const ctx: ExecutorContext = { payload, packId, env, spine };

  try {
    switch (payload.action_type) {
      case "RECORD_RESULT":       return await handleRecordResult(ctx);
      case "CHECK_STATE":         return await handleCheckState(ctx);
      case "VALIDATE_INPUT":      return await handleValidateInput(ctx);
      case "CLARIFY_NEXT_STEP":   return await handleClarifyNextStep(ctx);
      case "SELECT_NEXT_STEP":    return await handleSelectNextStep(ctx);
      case "WAIT_FOR_SIGNAL":     return await handleWaitForSignal(ctx);
      case "PAUSE_CYCLE":         return await handlePauseCycle(ctx);
      case "REDUCE_STIMULUS":     return await handleReduceStimulus(ctx);
      default:
        return {
          status: "skipped",
          message: `No executor wired for action_type=${payload.action_type}`,
        };
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : "executor_error";
    console.error("runExecutor failed", {
      action_type: payload.action_type,
      pack_id: packId,
      message,
    });
    return { status: "failed", message };
  }
}