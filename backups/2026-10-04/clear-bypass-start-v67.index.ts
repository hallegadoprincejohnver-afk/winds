import { createClient } from "npm:@supabase/supabase-js@2.95.0";

const SITE_URL = "https://clearb.space";
const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") || "").trim().replace(/\/$/, "");
const BYPASS_API_URL = "https://kys.linkvertise.lol/api/v2/bck/publishers";
const ALLOWED_ORIGINS = new Set([
  "https://clearb.space",
  "https://clearb.vercel.app",
]);

function getSecret(...names: string[]): string {
  for (const name of names) {
    const value = (Deno.env.get(name) || "").trim();
    if (value) return value;
  }
  return "";
}

function serverKey(): string {
  const legacy = (Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "").trim();
  if (legacy) return legacy;
  try {
    const keys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") || "{}");
    return String(keys.default || Object.values(keys)[0] || "");
  } catch {
    return "";
  }
}

async function stateSessionHash(state: string, secret: string): Promise<string | null> {
  try {
    const parts = state.split(".");
    if (parts.length < 2) return null;
    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
    if (typeof payload?.sid === "string" && payload.sid.length >= 32) return payload.sid;
    return await sha256("clear-bypass-legacy-session-v1:" + secret + ":" + state);
  } catch {
    return null;
  }
}

async function createBypassSession(
  sessionHash: string,
  provider: "lvdynamic" | "lootlabs",
): Promise<boolean> {
  const key = serverKey();
  if (!SUPABASE_URL || !key) return false;
  const db = createClient(SUPABASE_URL, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { error } = await db.from("clear_bypass_sessions").insert({
    session_hash: sessionHash,
    provider,
    expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
  });
  if (error && error.code !== "23505") {
    console.error("clear_bypass_session_create_failed", { provider, code: error.code });
    return false;
  }
  return true;
}

async function hasCompletedStep1(sessionHash: string, provider: "lvdynamic" | "lootlabs"): Promise<boolean> {
  const key = serverKey();
  if (!SUPABASE_URL || !key) return false;
  const db = createClient(SUPABASE_URL, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await db
    .from("clear_bypass_sessions")
    .select("step_1_completed_at,step_1_return_verified_at,expires_at")
    .eq("session_hash", sessionHash)
    .eq("provider", provider)
    .maybeSingle();
  if (error || !data) return false;
  return Boolean(data.step_1_completed_at) &&
    Boolean(data.step_1_return_verified_at) &&
    new Date(data.expires_at).getTime() > Date.now();
}

function json(req: Request, body: unknown, status = 200): Response {
  const origin = req.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.has(origin) || origin === "http://localhost:5173" || origin === "http://localhost:3000";
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Access-Control-Allow-Origin": allowed ? origin : SITE_URL,
      "Access-Control-Allow-Headers": "content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "Vary": "Origin",
    },
  });
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function utf8Base64Url(value: string): string {
  return base64Url(new TextEncoder().encode(value));
}

function clientIp(req: Request): string {
  const forwarded = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  return (req.headers.get("cf-connecting-ip") || req.headers.get("x-real-ip") || forwarded || "").trim().toLowerCase();
}

async function hmacSha256(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value),
  );
  return base64Url(new Uint8Array(signature));
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createState(
  secret: string,
  provider: "lvdynamic" | "lootlabs",
  stage: 1 | 2,
  sessionHash: string,
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + 30 * 60;
  const nonce = base64Url(crypto.getRandomValues(new Uint8Array(24)));
  const payload = { v: 5, p: provider, stage, exp, n: nonce, sid: sessionHash };
  const body = utf8Base64Url(JSON.stringify(payload));
  const sig = await hmacSha256(secret, body);
  return body + "." + sig;
}

function protectionConfig(provider: "lvdynamic" | "lootlabs") {
  const detections: Record<string, unknown> = {
    Referer: true,
    Presets: {
      "BYPASS.VIP": true,
      "BYPASS.CITY": true,
      "TRW-API": true,
    },
    RenueveBooster: {
      BlockVPNS: provider === "lvdynamic",
      BlockIncognito: provider === "lvdynamic",
      BlockAdBlocks: provider === "lvdynamic",
      CaptchaRequired: provider === "lvdynamic",
      RenueveForcer: provider === "lvdynamic",
      Max_Renueve: false,
    },
    // Linkvertise-only timing guard. Known Evade flows commonly wait ~10s;
    // require 12s so that timing-based spoof completions are reported.
    // Linkvertise uses Red Square's native enforcement for detected bypasses.
    MinTime: provider === "lvdynamic" ? "20" : "1",
    DetectUserscripts: true,
    UnicodeDetect: true,
    SpoofCompletion: true,
    RS_Invisible: false,
    // Do not allow detected bypasses to continue to our destination.
    // ManualDetectionZ intentionally remains disabled for Linkvertise.
    ManualDetectionZ: false,
    VMConfig: {
      enabled: true,
      VMode: provider === "lvdynamic" ? "high" : "medium",
    },
  };

  if (provider === "lootlabs") {
    // LootLabs is enforced as two sequential protected steps.
    // Each B.Y.P.A.S.S link requires exactly one LootLabs task.
    // Stage 2 is generated only after stage 1 returns to our server.
    detections.MaxTasks = "1";
    detections.tier_id = 3;
  }

  return detections;
}

async function createProtectedLink(
  req: Request,
  provider: "lvdynamic" | "lootlabs",
  step: 1 | 2,
  sessionHash?: string,
): Promise<Response> {
  const bypassApiKey = getSecret("BYPASS_C_API_KEY", "BYPASS_API_KEY", "RED_SQUARE_API_KEY", "RS_C_API_KEY");
  const linkvertiseUserId = getSecret("CLEAR_LINKVERTISE_USER_ID", "LINKVERTISE_USER_ID", "LINKVERTISE_PKEY");
  const lootlabsApiKey = getSecret("CLEAR_LOOTLABS_API_KEY", "LOOTLABS_API_KEY", "LOOTLABS_PKEY");
  const signingSecret = getSecret("LICENSE_SIGNING_SECRET");

  if (!bypassApiKey) {
    return json(req, { success: false, error: "B.Y.P.A.S.S integration is not configured." }, 500);
  }
  if (provider === "lootlabs" && !signingSecret) {
    return json(req, { success: false, error: "LootLabs integration is not configured." }, 500);
  }

  let pikey = "";
  let destination = "";
  let effectiveSessionHash = sessionHash || "";

  if (step === 1) {
    const seed = base64Url(crypto.getRandomValues(new Uint8Array(24)));
    effectiveSessionHash = await sha256("clear-bypass-session-v1:" + signingSecret + ":" + seed);
    if (!(await createBypassSession(effectiveSessionHash, provider))) {
      return json(req, { success: false, error: "Could not create the verification session." }, 500);
    }
  }

  if (!effectiveSessionHash) {
    return json(req, { success: false, error: "Verification session is missing." }, 403);
  }

  let linkvertiseState = "";

  if (provider === "lvdynamic") {
    if (step !== 1 && step !== 2) {
      return json(req, { success: false, error: "A Linkvertise step (1 or 2) is required." }, 400);
    }
    if (!linkvertiseUserId) {
      return json(req, { success: false, error: "Linkvertise provider is not configured." }, 500);
    }
    if (!signingSecret) {
      return json(req, { success: false, error: "Linkvertise integration is not configured." }, 500);
    }

    pikey = linkvertiseUserId;
    linkvertiseState = await createState(
      signingSecret,
      "lvdynamic",
      step,
      effectiveSessionHash,
    );
      const guardScriptUrl =
        SUPABASE_URL +
        "/functions/v1/clear-linkvertise-guard?state=" +
        encodeURIComponent(linkvertiseState);
    // Red Square/B.Y.P.A.S.S is the Linkvertise anti-bypass layer.
    // The client receives only the Red Square protected Linkvertise URL.
    destination =
      SUPABASE_URL +
      "/functions/v1/clear-bypass-linkvertise-complete?stage=" +
      step +
      "&state=" +
      encodeURIComponent(linkvertiseState);
  } else {
    if (!lootlabsApiKey) {
      return json(req, { success: false, error: "LootLabs provider is not configured." }, 500);
    }
    const requestedStep = step === 2 ? 2 : 1;
    pikey = lootlabsApiKey;
    const state = await createState(signingSecret, "lootlabs", requestedStep as 1 | 2, effectiveSessionHash);
    destination =
      SUPABASE_URL +
      "/functions/v1/clear-bypass-lootlabs-complete?stage=" +
      String(requestedStep) +
      "&state=" +
      encodeURIComponent(state);
  }

  const body = {
    url: destination,
    pikey,
    provider,
    Identificator: "clear",
    ads_script_url: provider === "lvdynamic"
      ? (SUPABASE_URL + "/functions/v1/clear-linkvertise-guard?state=" + encodeURIComponent(linkvertiseState))
      : "",
    jsonDetections: protectionConfig(provider),
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const response = await fetch(BYPASS_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "c-api-key": bypassApiKey,
      },
      body: JSON.stringify(body),
      cache: "no-store",
      signal: controller.signal,
    });

    const result = await response.json().catch(() => null);

    const generatedLink = typeof result?.data?.link === "string"
      ? result.data.link
      : typeof result?.link === "string"
        ? result.link
        : "";
    const createdAt = typeof result?.data?.Ntimestamp === "number"
      ? result.data.Ntimestamp
      : typeof result?.Ntimestamp === "number"
        ? result.Ntimestamp
        : null;

    if (!response.ok || result?.success !== true || !generatedLink) {
      console.error("clear_bypass_create_failed", {
        provider,
        status: response.status,
      });
      return json(
        req,
        {
          success: false,
          error: "Could not create the protected provider link.",
        },
        response.status === 429 ? 429 : 502,
      );
    }

    return json(req, {
      success: true,
      provider,
      step: step ?? null,
      url: generatedLink,
      expires_at: typeof createdAt === "number"
        ? new Date((createdAt + 1800) * 1000).toISOString()
        : null,
    });
  } catch (error) {
    console.error("clear_bypass_create_fatal", {
      provider,
      timeout: error instanceof DOMException && error.name === "AbortError",
    });
    return json(
      req,
      { success: false, error: "Protected link creation timed out." },
      504,
    );
  } finally {
    clearTimeout(timeout);
  }
}


function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(normalized);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function verifyCheckpointToken(
  token: string,
  secret: string,
  provider: "lvdynamic" | "lootlabs",
): Promise<string | null> {
  const parts = token.split(".");
  if (parts.length !== 2 && parts.length !== 3) return null;

  const [body, stateSignature, checkpointSignature] = parts;
  if (stateSignature !== await hmacSha256(secret, body)) return null;

  if (parts.length === 3) {
    const state = body + "." + stateSignature;
    if (checkpointSignature !== await hmacSha256(secret, state)) return null;
  }

  try {
    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(body)));
    if (
      (payload?.v !== 5 && payload?.v !== 4) ||
      payload?.p !== provider ||
      payload?.stage !== 1 ||
      typeof payload?.exp !== "number" ||
      payload.exp <= Math.floor(Date.now() / 1000) ||
      typeof payload?.n !== "string" ||
      payload.n.length < 16
    ) return null;

    return await stateSessionHash(body + "." + stateSignature, secret);
  } catch {
    return null;
  }
}
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    const origin = req.headers.get("Origin") || "";
    const allowed = ALLOWED_ORIGINS.has(origin) || origin === "http://localhost:5173" || origin === "http://localhost:3000";
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": allowed ? origin : SITE_URL,
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Cache-Control": "no-store",
        "Vary": "Origin",
      },
    });
  }
  if (req.method !== "POST") return json(req, { success: false, error: "Method not allowed." }, 405);

  try {
    const origin = req.headers.get("Origin") || "";
    if (origin && !ALLOWED_ORIGINS.has(origin) && origin !== "http://localhost:5173" && origin !== "http://localhost:3000") {
      return json(req, { success: false, error: "Origin not allowed." }, 403);
    }

    const body = await req.json().catch(() => null);
    const provider = body?.provider === "lootlabs" ? "lootlabs" : body?.provider === "lvdynamic" ? "lvdynamic" : "";
    const step = Number(body?.step);

    if (provider === "lvdynamic" || provider === "lootlabs") {
      const requestedStep = step === 2 ? 2 : 1;

      if (requestedStep === 1) {
        return await createProtectedLink(req, provider, 1);
      }

      const checkpointToken =
        typeof body?.checkpoint_token === "string" ? body.checkpoint_token.trim() :
        typeof body?.checkpointToken === "string" ? body.checkpointToken.trim() :
        typeof body?.bypass_token === "string" ? body.bypass_token.trim() :
        typeof body?.bypassToken === "string" ? body.bypassToken.trim() : "";

      const signingSecret = getSecret("LICENSE_SIGNING_SECRET");
      const sessionHash = checkpointToken && signingSecret
        ? await verifyCheckpointToken(checkpointToken, signingSecret, provider)
        : null;

      if (!sessionHash || !(await hasCompletedStep1(sessionHash, provider))) {
        return json(
          req,
          {
            success: false,
            error: provider === "lvdynamic"
              ? "Complete Linkvertise Step 1 first."
              : "Complete LootLabs Step 1 first.",
          },
          403,
        );
      }

      return await createProtectedLink(req, provider, 2, sessionHash);
    }

    return json(req, {
      success: false,
      error: "Invalid provider. Use lvdynamic or lootlabs.",
    }, 400);
  } catch (error) {
    console.error("clear_bypass_start_fatal", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return json(req, { success: false, error: "B.Y.P.A.S.S start server error." }, 500);
  }
});
