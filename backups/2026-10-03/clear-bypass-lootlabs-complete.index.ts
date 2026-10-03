import { createClient } from "npm:@supabase/supabase-js@2.95.0";

const SITE_URL = "https://clearb.space";
const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") || "").trim().replace(/\/$/, "");

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


function clientIp(req: Request): string {
  const forwarded = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  return (
    (req.headers.get("cf-connecting-ip") ||
      req.headers.get("x-real-ip") ||
      forwarded ||
      "").trim().toLowerCase()
  );
}

function getSecret(...names: string[]): string {
  for (const n of names) {
    const v = (Deno.env.get(n) || "").trim();
    if (v) return v;
  }
  return "";
}

function redirectTo(path: string): Response {
  return new Response(null, {
    status: 302,
    headers: {
      Location: path,
      "Cache-Control": "no-store",
    },
  });
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(normalized);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
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
  let binary = "";
  for (const b of new Uint8Array(signature)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function verifyState(state: string, secret: string, expectedStage: 1 | 2): Promise<boolean> {
  const parts = state.split(".");
  if (parts.length !== 2) return false;
  const [body, signature] = parts;
  if (signature !== await hmacSha256(secret, body)) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(body)));
    if (
      (payload?.v !== 5 && payload?.v !== 4) ||
      payload?.p !== "lootlabs" ||
      payload?.stage !== expectedStage ||
      typeof payload?.exp !== "number" ||
      payload.exp <= Math.floor(Date.now() / 1000) ||
      typeof payload?.n !== "string" ||
      payload.n.length < 16
    ) return false;
    if (payload?.v === 5 && (typeof payload?.sid !== "string" || payload.sid.length < 32)) return false;
    return true;
  } catch {
    return false;
  }
}


async function getSessionHashFromState(state: string, secret: string): Promise<string | null> {
  try {
    const parts = state.split(".");
    if (parts.length !== 2) return null;
    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
    if (payload?.v === 5 && typeof payload?.sid === "string" && payload.sid.length >= 32) return payload.sid;
    if (payload?.v === 4) return await sha256("clear-bypass-legacy-session-v1:" + secret + ":" + state);
    return null;
  } catch {
    return null;
  }
}

async function ensureBypassSession(supabase: ReturnType<typeof createClient>, sessionHash: string, provider: "lootlabs", expiresAt: string): Promise<boolean> {
  const { error } = await supabase.from("clear_bypass_sessions").insert({ session_hash: sessionHash, provider, expires_at: expiresAt });
  if (error && error.code !== "23505") {
    console.error("clear_bypass_session_create_failed", { provider, code: error.code });
    return false;
  }
  return true;
}

async function getBypassSession(supabase: ReturnType<typeof createClient>, sessionHash: string, provider: "lootlabs") {
  const { data, error } = await supabase.from("clear_bypass_sessions").select("step_1_completed_at,step_2_completed_at,expires_at").eq("session_hash", sessionHash).eq("provider", provider).maybeSingle();
  if (error || !data) return null;
  if (new Date(data.expires_at).getTime() <= Date.now()) return null;
  return data;
}

async function markStep1Completed(supabase: ReturnType<typeof createClient>, sessionHash: string): Promise<boolean> {
  const { data, error } = await supabase.from("clear_bypass_sessions").update({ step_1_completed_at: new Date().toISOString() }).eq("session_hash", sessionHash).eq("provider", "lootlabs").gt("expires_at", new Date().toISOString()).select("session_hash").maybeSingle();
  return !error && Boolean(data);
}

async function markStep2Completed(supabase: ReturnType<typeof createClient>, sessionHash: string): Promise<boolean> {
  const { data, error } = await supabase.from("clear_bypass_sessions").update({ step_2_completed_at: new Date().toISOString() }).eq("session_hash", sessionHash).eq("provider", "lootlabs").gt("expires_at", new Date().toISOString()).select("session_hash").maybeSingle();
  return !error && Boolean(data);
}
function randomHex(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function makeKey(): string {
  const value = randomHex(16).toUpperCase();
  return `CLEAR-${value.slice(0, 8)}-${value.slice(8, 16)}-${value.slice(16, 24)}-${value.slice(24, 32)}`;
}

async function makeClaim(supabase: ReturnType<typeof createClient>, licenseKey: string): Promise<string | null> {
  const claimToken = randomHex(32);
  const claimHash = await sha256(claimToken);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  const { error } = await supabase.from("getkey_claims").insert({
    claim_hash: claimHash,
    license_key: licenseKey,
    expires_at: expiresAt,
  });

  return error ? null : claimToken;
}

Deno.serve(async (req) => {
  if (req.method !== "GET") {
    return redirectTo(`${SITE_URL}/key-complete?error=method_not_allowed`);
  }

  try {
    const url = new URL(req.url);
    const stage = url.searchParams.get("stage") === "1"
      ? 1
      : url.searchParams.get("stage") === "2"
        ? 2
        : 0;
    const state = (url.searchParams.get("state") || "").trim();
    const signingSecret = getSecret("LICENSE_SIGNING_SECRET");

    if (!stage || !state || signingSecret.length < 32 || !SUPABASE_URL) {
      return redirectTo(`${SITE_URL}/key-complete?error=server_configuration_error`);
    }

    if (!(await verifyState(state, signingSecret, stage as 1 | 2))) {
      return redirectTo(`${SITE_URL}/key-complete?error=invalid_lootlabs_state`);
    }

    const serviceKey = serverKey();
    if (!serviceKey) {
      return redirectTo(`${SITE_URL}/key-complete?error=server_configuration_error`);
    }

    const supabase = createClient(SUPABASE_URL, serviceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const sessionHash = await getSessionHashFromState(state, signingSecret);
    if (!sessionHash) {
      return redirectTo(SITE_URL + "/key-complete?error=invalid_lootlabs_session");
    }

    try {
      const parts = state.split(".");
      const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
      const exp = Number(payload?.exp);
      if (!Number.isFinite(exp)) throw new Error("invalid_exp");
      if (!(await ensureBypassSession(supabase, sessionHash, "lootlabs", new Date(exp * 1000).toISOString()))) {
        return redirectTo(SITE_URL + "/key-complete?error=server_error");
      }
    } catch {
      return redirectTo(SITE_URL + "/key-complete?error=invalid_lootlabs_state");
    }

    const session = await getBypassSession(supabase, sessionHash, "lootlabs");
    if (!session) {
      return redirectTo(SITE_URL + "/key-complete?error=invalid_lootlabs_session");
    }

    if (stage === 2 && !session.step_1_completed_at) {
      return redirectTo(SITE_URL + "/key-complete?error=complete_step_1_first&provider=lootlabs&stage=2");
    }

    if (stage === 1) {
      if (!(await markStep1Completed(supabase, sessionHash))) {
        console.error("clear_bypass_step1_session_update_failed", { provider: "lootlabs" });
        return redirectTo(SITE_URL + "/key-complete?error=server_error");
      }
      // Step 1 is ONLY a checkpoint. Never create a key here.
      const checkpoint = await hmacSha256(signingSecret, state);
      const checkpointToken = `${state}.${checkpoint}`;
      return redirectTo(
        `${SITE_URL}/key-complete?provider=lootlabs&checkpoint=1&bypass_token=${encodeURIComponent(checkpointToken)}`,
      );
    }

    // The stage-2 state itself is cryptographically signed and expires.
    // It was only issued by clear-bypass-start after a valid step-1 checkpoint.
    const finalHash = await sha256("clear-lootlabs-v4:" + signingSecret + ":" + state);

    const { data: existing, error: lookupError } = await supabase
      .from("licenses")
      .select("license_key, active, expires_at")
      .eq("source_hash", finalHash)
      .eq("whitelist_source", "lootlabs")
      .maybeSingle();

    if (lookupError) {
      console.error("clear_bypass_lootlabs_lookup_failed", { code: lookupError.code });
      return redirectTo(`${SITE_URL}/key-complete?error=server_error`);
    }

    let licenseKey = "";

    if (
      existing?.license_key &&
      existing.active &&
      existing.expires_at &&
      new Date(existing.expires_at).getTime() > Date.now()
    ) {
      licenseKey = String(existing.license_key);
    } else {
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();

      for (let i = 0; i < 5; i++) {
        const candidate = makeKey();
        const { error } = await supabase.from("licenses").insert({
          license_key: candidate,
          active: true,
          expires_at: expiresAt,
          script_name: "main.lua",
          discord_user_id: null,
          redeemed_at: now.toISOString(),
          source_hash: finalHash,
          whitelist_source: "lootlabs",
          whitelist_reason: "LootLabs key redemption via Clear",
          whitelist_started_at: now.toISOString(),
          whitelist_duration_seconds: 86400,
        });

        if (!error) {
          licenseKey = candidate;
          break;
        }

        if (error.code !== "23505") {
          console.error("clear_bypass_lootlabs_license_insert_failed", { code: error.code });
          return redirectTo(`${SITE_URL}/key-complete?error=key_creation_failed`);
        }
      }
    }

    if (!licenseKey) {
      return redirectTo(`${SITE_URL}/key-complete?error=key_creation_failed`);
    }

    const claimToken = await makeClaim(supabase, licenseKey);
    if (!claimToken) {
      return redirectTo(`${SITE_URL}/key-complete?error=claim_creation_failed`);
    }

        if (stage === 2) {
      if (!(await markStep2Completed(supabase, sessionHash))) {
        console.error("clear_bypass_step2_session_update_failed", { provider: "lootlabs" });
        return redirectTo(SITE_URL + "/key-complete?error=server_error");
      }
    }
return redirectTo(`${SITE_URL}/key-complete?claim=${encodeURIComponent(claimToken)}`);
  } catch (error) {
    console.error("clear_bypass_lootlabs_complete_fatal", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return redirectTo(`${SITE_URL}/key-complete?error=server_error`);
  }
});
