export interface Env {
  RAIL_URL: string;
  RAIL_PUBLIC_KEY?: string;
  WRAPPER_SHARED_SECRET?: string; // optional fallback during transition
  DB: D1Database;
}

const FALLBACK_CLIENT_ID = "__fallback_shared_secret__";
const FALLBACK_KEY_ID = "__fallback_shared_secret__";

type ExternalEvaluateRequest = {
  sequence_id: string;
  step: string;
  function?: string;
  action_type: string;
  action?: string;
  inputs?: Record<string, unknown>;
  nonce?: string;
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

    if (request.method === "GET" && url.pathname === "/v1/health") {
      return jsonResponse(200, {
        ok: true,
        service: "agenticrail-wrapper",
        now: Date.now(),
      });
    }

    if (request.method === "POST" && url.pathname === "/v1/evaluate") {
      try {
        const auth = request.headers.get("authorization") || "";
        const token = getBearerToken(auth);

        if (!token) {
          return jsonResponse(401, {
            error: "missing_bearer_token",
            message: "Authorization: Bearer <token> required",
          });
        }

        const authResult = await authenticateApiKey(token, env);
        if (!authResult.ok) {
          return jsonResponse(authResult.status, {
            error: authResult.error,
            message: authResult.message,
          });
        }

        const parsedBody = await parseJsonBody<Partial<ExternalEvaluateRequest>>(request);
        if (!parsedBody.ok) {
          return jsonResponse(400, {
            error: "invalid_json",
            message: parsedBody.message,
          });
        }

        const body = parsedBody.data;
        const validationError = validateExternalRequest(body);
        if (validationError) {
          return jsonResponse(400, {
            error: "invalid_request",
            message: validationError,
          });
        }

        const ext = normalizeExternalRequest(body as ExternalEvaluateRequest);

        const railPayload: RailRequest = {
          schema_version: "1.0",
          model_id: `client:${authResult.clientId}`,
          sequence_id: ext.sequence_id,
          step: ext.step,
          function: ext.function ?? ext.step,
          action_type: ext.action_type,
          nonce: ext.nonce ?? crypto.randomUUID(),
          ts_ms: Date.now(),
          action: ext.action ?? `run ${ext.function ?? ext.step}`,
          inputs: ext.inputs ?? {},
        };

        const railRes = await fetch(env.RAIL_URL, {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify(railPayload),
        });

        const rawRailJson = await safeJson<unknown>(railRes);
        const railJson = parseRailResponse(rawRailJson);

        if (!railRes.ok || !railJson) {
          return jsonResponse(502, {
            error: "rail_unavailable",
            message: "Rail did not return a valid response",
            rail_status: railRes.status,
          });
        }

        if (env.RAIL_PUBLIC_KEY) {
          if (!railJson.signature) {
            return jsonResponse(502, {
              error: "rail_signature_missing",
              message: "RAIL_PUBLIC_KEY is configured but rail returned no signature",
            });
          }

          const verified = await verifyRailReceipt(env.RAIL_PUBLIC_KEY, railJson);
          if (!verified) {
            return jsonResponse(502, {
              error: "rail_signature_invalid",
              message: "Rail response signature failed verification",
            });
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
          (
            returnedFunction !== expectedFunction ||
            returnedAction !== expectedAction ||
            returnedSequenceId !== expectedSequenceId ||
            returnedStep !== expectedStep
          )
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
          });
        }

        if (
          railJson.decision !== "ALLOW" &&
          (
            returnedSequenceId !== expectedSequenceId ||
            returnedStep !== expectedStep
          )
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
          executorResult = await runExecutor(railPayload);
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
        });
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Unknown wrapper error";
        return jsonResponse(500, {
          error: "wrapper_error",
          message,
        });
      }
    }

    return jsonResponse(404, {
      error: "not_found",
      message: "Route not found",
    });
  },
};

async function authenticateApiKey(
  token: string,
  env: Env,
): Promise<AuthSuccess | AuthFailure> {
  if (env.WRAPPER_SHARED_SECRET && token === env.WRAPPER_SHARED_SECRET) {
    return {
      ok: true,
      keyId: FALLBACK_KEY_ID,
      clientId: FALLBACK_CLIENT_ID,
    };
  }

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

function splitPresentedApiKey(
  fullKey: string,
): { prefix: string } | null {
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

  const decision = value.decision;
  if (decision !== "ALLOW" && decision !== "DENY" && decision !== "HALT") {
    return null;
  }

  if (value.reasons !== undefined) {
    if (!Array.isArray(value.reasons) || value.reasons.some((v) => typeof v !== "string")) {
      return null;
    }
  }

  if (value.meta !== undefined) {
    if (!isPlainObject(value.meta)) return null;

    const metaFields = ["action_type", "function", "model_id", "sequence_id", "step"];
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
    const fieldValue = value[field];
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

  return value as RailResponse;
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

function buildSignedReceiptPayload(railJson: RailResponse): Record<string, unknown> {
  // Spread passes all fields through — if RailResponse gains new fields,
  // they must also be present on the rail's signing payload or verification breaks.
  const {
    signature: _signature,
    ...rest
  } = railJson as RailResponse & Record<string, unknown>;

  return rest;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }

  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`).join(",")}}`;
  }

  return JSON.stringify(value);
}

function base64ToBytes(base64OrUrl: string): Uint8Array {
  const normalized = base64OrUrl
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/\s+/g, "");

  const padded =
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

function buildEd25519SpkiFromRaw(rawKey: Uint8Array): ArrayBuffer {
  const prefix = new Uint8Array([
    0x30, 0x2a,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x03, 0x21, 0x00,
  ]);

  const out = new Uint8Array(prefix.length + rawKey.length);
  out.set(prefix, 0);
  out.set(rawKey, prefix.length);
  return out.buffer;
}

async function safeJson<T>(res: Response): Promise<T | null> {
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

function jsonResponse(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
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

async function runExecutor(payload: RailRequest): Promise<ExecutorResult> {
  switch (payload.action_type) {
    case "SUBMIT_PAYMENT":
      return submitPayment(payload.inputs);

    case "SEND_EMAIL":
      return sendEmail(payload.inputs);

    default:
      return {
        status: "skipped",
        message: `No executor wired for action_type=${payload.action_type}`,
      };
  }
}

async function submitPayment(
  inputs: Record<string, unknown>,
): Promise<ExecutorResult> {
  const amount = Number(inputs.amount ?? 0);
  const to = String(inputs.to ?? "").trim();

  if (!Number.isFinite(amount) || amount <= 0 || !to) {
    return {
      status: "failed",
      message: "Missing or invalid amount or destination",
    };
  }

  console.log("SUBMIT_PAYMENT", { amount, to });

  return {
    status: "submitted",
    message: "Mock payment submitted",
    data: { amount, to },
  };
}

async function sendEmail(
  inputs: Record<string, unknown>,
): Promise<ExecutorResult> {
  const to = String(inputs.to ?? "").trim();
  const subject = String(inputs.subject ?? "").trim();

  if (!to || !subject) {
    return {
      status: "failed",
      message: "Missing to or subject",
    };
  }

  console.log("SEND_EMAIL", { to, subject });

  return {
    status: "submitted",
    message: "Mock email submitted",
    data: { to, subject },
  };
}