import { createClient } from "npm:@supabase/supabase-js@2.95.0";

const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") || "").trim().replace(/\/$/, "");
const ALLOWED_ORIGINS = new Set([
  "https://kys.linkvertise.lol",
  "https://red-square.space",
  "https://rs.linkvertise.lol",
]);

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
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function verifyState(state: string): Promise<{sid:string; stage:1|2}|null> {
  const secret = (Deno.env.get("LICENSE_SIGNING_SECRET") || "").trim();
  if (secret.length < 32) return null;

  const parts = state.split(".");
  if (parts.length !== 2) return null;
  const [body, signature] = parts;
  if (signature !== await hmacSha256(secret, body)) return null;

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(body)),
    );
    if (
      (payload?.v !== 4 && payload?.v !== 5) ||
      payload?.p !== "lvdynamic" ||
      (payload?.stage !== 1 && payload?.stage !== 2) ||
      typeof payload?.exp !== "number" ||
      payload.exp <= Math.floor(Date.now() / 1000) ||
      typeof payload?.n !== "string" ||
      payload.n.length < 16 ||
      typeof payload?.sid !== "string" ||
      !/^[a-f0-9]{64}$/.test(payload.sid)
    ) return null;

    return { sid: payload.sid, stage: payload.stage };
  } catch {
    return null;
  }
}

function corsHeaders(req: Request): Headers {
  const origin = req.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.has(origin) || origin === "https://clearb.space" || origin === "https://clearb.vercel.app";
  const h = new Headers({
    "Access-Control-Allow-Origin": allowed ? origin : "https://clearb.space",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Vary": "Origin",
  });
  return h;
}

function json(req: Request, body: unknown, status=200): Response {
  const headers = corsHeaders(req);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), {status, headers});
}

function guardScript(endpoint: string, sid: string, stage: number): string {
  return `(()=> {
    "use strict";
    const ENDPOINT = ${JSON.stringify(endpoint)};
    const SESSION = ${JSON.stringify(sid)};
    const STAGE = ${JSON.stringify(stage)};
    const PREFIX = "rs-clear-canary-" + Math.random().toString(36).slice(2);
    let reported = false;
    let strikes = 0;
    const canaries = new Map();

    const report = (reason) => {
      if (reported) return;
      reported = true;
      const payload = JSON.stringify({
        state_sid: SESSION,
        stage: STAGE,
        reason: String(reason || "iframe_integrity"),
        href: String(location.href).slice(0, 500),
        ts: Date.now()
      });
      try {
        navigator.sendBeacon(ENDPOINT, new Blob([payload], {type:"text/plain"}));
      } catch (_) {
        try {
          fetch(ENDPOINT, {
            method:"POST",
            mode:"no-cors",
            keepalive:true,
            headers:{"Content-Type":"text/plain;charset=UTF-8"},
            body:payload
          }).catch(()=>{});
        } catch (_) {}
      }
    };

    const suspiciousIframe = (frame) => {
      if (!frame || reported) return;
      const original = canaries.get(frame);
      if (!original) return;

      const src = frame.getAttribute("src") || "";
      const srcdoc = frame.getAttribute("srcdoc") || "";

      // Evade's snipe engine rewrites ordinary iframes to about:blank and
      // strips srcdoc unless a frame appears to be its selected VM frame.
      if (src === "about:blank" || (!src && !srcdoc)) {
        strikes++;
        if (strikes >= 2) report("iframe_canary_blank");
      }
    };

    const createCanary = (index) => {
      const frame = document.createElement("iframe");
      frame.id = PREFIX + "-" + index;
      frame.setAttribute(
        "src",
        "https://kys.linkvertise.lol/robots.txt?rs_canary=" +
          encodeURIComponent(PREFIX + "-" + index)
      );
      frame.setAttribute("aria-hidden", "true");
      frame.setAttribute("tabindex", "-1");
      frame.style.cssText =
        "position:fixed!important;left:-10000px!important;top:-10000px!important;" +
        "width:2px!important;height:2px!important;border:0!important;" +
        "opacity:0!important;pointer-events:none!important;";
      canaries.set(frame, frame.getAttribute("src") || "");
      (document.body || document.documentElement).appendChild(frame);

      const started = Date.now();
      const timer = setInterval(() => {
        if (reported) {
          clearInterval(timer);
          return;
        }
        suspiciousIframe(frame);
        if (!frame.isConnected || Date.now() - started > 9000) {
          clearInterval(timer);
          canaries.delete(frame);
        }
      }, 35);
    };

    const boot = () => {
      if (reported) return;
      createCanary(1);
      createCanary(2);
      createCanary(3);

      const observer = new MutationObserver((records) => {
        for (const record of records) {
          if (record.type === "attributes" && record.target instanceof HTMLIFrameElement) {
            suspiciousIframe(record.target);
          } else if (record.type === "childList") {
            for (const node of record.removedNodes) {
              if (node instanceof HTMLIFrameElement && canaries.has(node)) {
                strikes++;
                if (strikes >= 2) report("iframe_canary_removed");
              }
            }
          }
        }
      });

      try {
        observer.observe(document.documentElement, {
          subtree: true,
          childList: true,
          attributes: true,
          attributeFilter: ["src", "srcdoc", "style"]
        });
      } catch (_) {}
    };

    if (document.documentElement) boot();
    else document.addEventListener("DOMContentLoaded", boot, {once:true});
  })();`;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, {status:204, headers:corsHeaders(req)});

  const url = new URL(req.url);
  const state = (url.searchParams.get("state") || "").trim();

  if (req.method === "GET") {
    const verified = await verifyState(state);
    if (!verified || !SUPABASE_URL) {
      return new Response("/* invalid guard state */", {
        status: 403,
        headers: new Headers({
          ...Object.fromEntries(corsHeaders(req)),
          "Content-Type": "application/javascript; charset=utf-8"
        })
      });
    }

    const endpoint = SUPABASE_URL + "/functions/v1/clear-linkvertise-guard";
    return new Response(guardScript(endpoint, verified.sid, verified.stage), {
      status: 200,
      headers: new Headers({
        ...Object.fromEntries(corsHeaders(req)),
        "Content-Type": "application/javascript; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      })
    });
  }

  if (req.method !== "POST") return json(req, {ok:false,error:"method_not_allowed"},405);

  let body: any = null;
  try {
    body = JSON.parse(await req.text());
  } catch {
    body = null;
  }

  const sid = typeof body?.state_sid === "string" ? body.state_sid.trim() : "";
  const stage = body?.stage === 2 ? 2 : body?.stage === 1 ? 1 : 0;
  const reason = typeof body?.reason === "string" ? body.reason.slice(0,120) : "iframe_integrity";
  if (!/^[a-f0-9]{64}$/.test(sid) || !stage) {
    return json(req,{ok:false,error:"invalid_report"},400);
  }

  const key = serverKey();
  if (!SUPABASE_URL || !key) return json(req,{ok:false,error:"server_configuration_error"},500);

  // Only accept reports for a currently valid Clear session by looking up the
  // signed session hash. We do not trust arbitrary client-supplied state.
  const db = createClient(SUPABASE_URL, key, {
    auth: {persistSession:false, autoRefreshToken:false},
  });

  const {data:session,error:sessionError} = await db
    .from("clear_bypass_sessions")
    .select("id,session_hash,provider,expires_at")
    .eq("session_hash",sid)
    .eq("provider","lvdynamic")
    .maybeSingle();

  if (sessionError || !session || new Date(session.expires_at).getTime() <= Date.now()) {
    return json(req,{ok:false,error:"invalid_session"},403);
  }

  const {error} = await db.from("clear_security_events").insert({
    event_type:"linkvertise_guard_detected",
    severity:"critical",
    metadata:{
      session_hash:sid,
      provider:"lvdynamic",
      stage,
      detector:"red_square_iframe_canary",
      reason,
      user_agent:(req.headers.get("user-agent") || "").slice(0,300),
      detected_at:new Date().toISOString(),
    },
  });

  if (error && error.code !== "23505") {
    console.error("clear_linkvertise_guard_event_insert_failed",{code:error.code});
    return json(req,{ok:false,error:"event_save_failed"},500);
  }

  return json(req,{ok:true});
});
