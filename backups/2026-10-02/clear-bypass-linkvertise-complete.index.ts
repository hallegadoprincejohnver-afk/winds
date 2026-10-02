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
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Pragma: "no-cache",
    },
  });
}



function decodeBase64Url(value: string): Uint8Array {
  const normalized =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(normalized);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
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
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
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

async function hasRedSquareGuardDetection(
  supabase: SupabaseClient,
  sessionHash: string,
  stage: 1 | 2,
): Promise<boolean> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const { data, error } = await supabase
      .from("clear_security_events")
      .select("created_at,metadata")
      .eq("event_type", "linkvertise_guard_detected")
      .eq("severity", "critical")
      .order("created_at", { ascending: false })
      .limit(30);

    if (!error && Array.isArray(data)) {
      const detected = data.some((row) => {
        const metadata = row?.metadata;
        if (!metadata || typeof metadata !== "object") return false;
        return metadata.session_hash === sessionHash &&
          metadata.provider === "lvdynamic" &&
          Number(metadata.stage) === stage &&
          metadata.detector === "red_square_iframe_canary";
      });
      if (detected) return true;
    }

    if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 300));
  }

  return false;
}

function bypassResponse(details: Record<string, unknown>): Response {
  return new Response(null, {
    status: 303,
    headers: {
      Location: SITE_URL + "/key-complete?error=linkvertise_verification_failed",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Pragma: "no-cache",
    },
  });
}

async function verifyRedSquareManualReport(token: string): Promise<{
  ok: boolean;
  report: Record<string, unknown>;
}> {
  const value = token.trim();
  if (!value || value.length > 1024) return { ok: false, report: {} };

  try {
    const endpoint = new URL("https://kys.linkvertise.lol/api/v2/ManualReport");
    endpoint.searchParams.set("tk", value);

    const response = await fetch(endpoint.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return { ok: false, report: {} };
    const data = await response.json().catch(() => null);
    if (!data || data.success !== true || typeof data.FinalReport !== "object" || data.FinalReport === null) {
      return { ok: false, report: {} };
    }

    return { ok: true, report: data.FinalReport as Record<string, unknown> };
  } catch (error) {
    console.error("clear_linkvertise_redsquare_manual_report_failed", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return { ok: false, report: {} };
  }
}

function hasHighConfidenceRedSquareDetection(report: Record<string, unknown>): string[] {
  const zeroFalsePositiveFlags = [
    "Userscript_DET1",
    "LV_SPOOFED_COMPLETION",
    "DeadHand_MagnusX5",
    "DeadHand_MagnusX6",
    "DeadHand_MagnusX8",
    "DeadHand_MagnusX9",
    "DeadHand_MagnusX10",
    "TRW_API_Detected",
    "BYPASS_CITY_DETECTED",
    "FAST_COMPLETION",
  ];
  return zeroFalsePositiveFlags.filter((name) => report[name] === true);
}

function randomHex(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function makeKey(): string {
  const value = randomHex(16).toUpperCase();
  return "CLEAR-" +
    value.slice(0, 8) + "-" +
    value.slice(8, 16) + "-" +
    value.slice(16, 24) + "-" +
    value.slice(24, 32);
}

type SupabaseClient = ReturnType<typeof createClient>;

async function makeClaim(
  supabase: SupabaseClient,
  licenseKey: string,
): Promise<string | null> {
  for (let i = 0; i < 3; i++) {
    const claimToken = randomHex(32);
    const claimHash = await sha256(claimToken);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    const { error } = await supabase.from("getkey_claims").insert({
      claim_hash: claimHash,
      license_key: licenseKey,
      expires_at: expiresAt,
    });

    if (!error) return claimToken;
    if (error.code !== "23505") {
      console.error("clear_bypass_linkvertise_claim_insert_failed", {
        code: error.code,
      });
      return null;
    }
  }

  return null;
}

async function verifyStatePayload(
  state: string,
  secret: string,
  expectedStage: 1 | 2,
): Promise<Record<string, unknown> | null> {
  const parts = state.split(".");
  if (parts.length !== 2) return null;

  const [body, signature] = parts;
  const expectedSignature = await hmacSha256(secret, body);
  if (signature !== expectedSignature) return null;

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(body)),
    );

    if (payload?.v !== 4 && payload?.v !== 5) return null;
    if (
      payload?.p !== "lvdynamic" ||
      payload?.stage !== expectedStage ||
      typeof payload?.exp !== "number" ||
      payload.exp <= Math.floor(Date.now() / 1000) ||
      typeof payload?.n !== "string" ||
      payload.n.length < 16 ||
      typeof payload?.sid !== "string" ||
      !/^[a-f0-9]{64}$/.test(payload.sid)
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method !== "GET") {
    return redirectTo(SITE_URL + "/key-complete?error=method_not_allowed");
  }

  try {
    const url = new URL(req.url);
    const stage =
      url.searchParams.get("stage") === "1"
        ? 1
        : url.searchParams.get("stage") === "2"
          ? 2
          : 0;
    const state = (url.searchParams.get("state") || "").trim();
    const signingSecret = getSecret("LICENSE_SIGNING_SECRET");

    if (!stage || !state || signingSecret.length < 32 || !SUPABASE_URL) {
      return redirectTo(
        SITE_URL + "/key-complete?error=server_configuration_error",
      );
    }

    const statePayload = await verifyStatePayload(
      state,
      signingSecret,
      stage as 1 | 2,
    );

    if (!statePayload) {
      return redirectTo(
        SITE_URL + "/key-complete?error=invalid_linkvertise_state",
      );
    }

    const redSquareEvaluationToken = (url.searchParams.get("RS_EvaluationDT") || "").trim();
    if (redSquareEvaluationToken) {
      const manualReport = await verifyRedSquareManualReport(redSquareEvaluationToken);
      if (!manualReport.ok) {
        console.warn("clear_linkvertise_redsquare_manual_report_invalid", { stage });
        return bypassResponse({ invalid_report: true, stage });
      }

      const detections = hasHighConfidenceRedSquareDetection(manualReport.report);
      if (detections.length > 0) {
        console.warn("clear_linkvertise_redsquare_bypass_detected", {
          stage,
          detections,
        });
        return bypassResponse({ detections, stage });
      }
    }

    const key = serverKey();
    if (!key) {
      console.error("clear_bypass_linkvertise_server_key_missing");
      return redirectTo(
        SITE_URL + "/key-complete?error=server_configuration_error",
      );
    }

    const supabase = createClient(SUPABASE_URL, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const sessionHash = String(statePayload.sid);
    const now = new Date().toISOString();

    if (await hasRedSquareGuardDetection(
      supabase,
      sessionHash,
      stage as 1 | 2,
    )) {
      console.warn("clear_linkvertise_redsquare_guard_blocked", { stage });
      return bypassResponse({
        detector: "red_square_iframe_canary",
        stage,
      });
    }

    const { data: session, error: sessionError } = await supabase
      .from("clear_bypass_sessions")
      .select(
        "id,session_hash,provider,step_1_completed_at,step_2_completed_at,expires_at,created_at",
      )
      .eq("session_hash", sessionHash)
      .eq("provider", "lvdynamic")
      .maybeSingle();

    if (sessionError) {
      console.error("clear_bypass_linkvertise_session_lookup_failed", {
        code: sessionError.code,
      });
      return redirectTo(SITE_URL + "/key-complete?error=server_error");
    }

    if (!session || new Date(session.expires_at).getTime() <= Date.now()) {
      return redirectTo(
        SITE_URL + "/key-complete?error=linkvertise_session_invalid",
      );
    }

    // Defense-in-depth against direct callback/instant-completion bypasses.
    // Normal Linkvertise completions have to spend time inside the protected
    // flow; a signed Clear state alone is never sufficient proof of completion.
    const sessionCreatedAt = new Date(String(session.created_at)).getTime();
    if (!Number.isFinite(sessionCreatedAt)) {
      console.error("clear_linkvertise_session_created_at_invalid");
      return redirectTo(
        SITE_URL + "/key-complete?error=linkvertise_session_invalid",
      );
    }

    const elapsedSeconds = (Date.now() - sessionCreatedAt) / 1000;
    if (elapsedSeconds < 20) {
      console.warn("clear_linkvertise_fast_completion_blocked", {
        stage,
        elapsed_ms: Math.max(0, Date.now() - sessionCreatedAt),
      });
      return bypassResponse({
        FAST_COMPLETION: true,
        DIRECT_CALLBACK: true,
      });
    }

    if (stage === 1) {
      if (session.step_2_completed_at) {
        return redirectTo(
          SITE_URL + "/key-complete?error=linkvertise_session_completed",
        );
      }

      if (!session.step_1_completed_at) {
        const { data: updated, error } = await supabase
          .from("clear_bypass_sessions")
          .update({ step_1_completed_at: now })
          .eq("session_hash", sessionHash)
          .eq("provider", "lvdynamic")
          .is("step_1_completed_at", null)
          .is("step_2_completed_at", null)
          .select("session_hash")
          .maybeSingle();

        if (error || !updated) {
          console.error("clear_linkvertise_step1_save_failed", {
            code: error?.code || "no_row",
          });
          return redirectTo(
            SITE_URL + "/key-complete?error=linkvertise_session_save_failed",
          );
        }
      }

      const checkpointSignature = await hmacSha256(signingSecret, state);
      const checkpointToken = state + "." + checkpointSignature;

      return redirectTo(
        SITE_URL +
          "/key-complete?provider=lvdynamic&checkpoint=1&bypass_token=" +
          encodeURIComponent(checkpointToken),
      );
    }

    if (!session.step_1_completed_at || session.step_2_completed_at) {
      return redirectTo(
        SITE_URL + "/key-complete?error=linkvertise_step_order_invalid",
      );
    }

    const finalHash = await sha256(
      "clear-bypass-linkvertise-redsquare-v1:" +
        signingSecret +
        ":" +
        state,
    );

    let licenseKey = "";
    const { data: existing, error: lookupError } = await supabase
      .from("licenses")
      .select("license_key,active")
      .eq("source_hash", finalHash)
      .maybeSingle();

    if (lookupError) {
      console.error("clear_bypass_linkvertise_lookup_failed", {
        code: lookupError.code,
      });
      return redirectTo(SITE_URL + "/key-complete?error=server_error");
    }

    if (existing?.license_key && existing.active === true) {
      licenseKey = String(existing.license_key);
    } else {
      for (let i = 0; i < 5 && !licenseKey; i++) {
        const candidate = makeKey();
        const { error } = await supabase.from("licenses").insert({
          license_key: candidate,
          active: true,
          source_hash: finalHash,
          discord_user_id: null,
          redeemed_at: null,
        });

        if (!error) {
          licenseKey = candidate;
          break;
        }

        if (error.code === "23505") {
          const { data: raced } = await supabase
            .from("licenses")
            .select("license_key,active")
            .eq("source_hash", finalHash)
            .maybeSingle();

          if (raced?.license_key && raced.active === true) {
            licenseKey = String(raced.license_key);
            break;
          }

          continue;
        }

        console.error("clear_bypass_linkvertise_license_insert_failed", {
          code: error.code,
        });
        return redirectTo(
          SITE_URL + "/key-complete?error=license_save_failed",
        );
      }
    }

    if (!licenseKey) {
      return redirectTo(
        SITE_URL + "/key-complete?error=license_save_failed",
      );
    }

    const claimToken = await makeClaim(supabase, licenseKey);
    if (!claimToken) {
      return redirectTo(
        SITE_URL + "/key-complete?error=claim_save_failed",
      );
    }

    const { data: finalized, error: finalizeError } = await supabase
      .from("clear_bypass_sessions")
      .update({ step_2_completed_at: now })
      .eq("session_hash", sessionHash)
      .eq("provider", "lvdynamic")
      .is("step_2_completed_at", null)
      .select("session_hash")
      .maybeSingle();

    if (finalizeError || !finalized) {
      console.warn("clear_bypass_linkvertise_step2_finalize_race", {
        code: finalizeError?.code || "no_row",
      });
      return redirectTo(
        SITE_URL + "/key-complete?error=linkvertise_session_update_failed",
      );
    }

    return redirectTo(
      SITE_URL + "/key-complete?claim=" + encodeURIComponent(claimToken),
    );
  } catch (error) {
    console.error("clear_bypass_linkvertise_complete_fatal", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return redirectTo(SITE_URL + "/key-complete?error=server_error");
  }
});
