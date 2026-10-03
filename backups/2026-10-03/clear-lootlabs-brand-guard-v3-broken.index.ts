import { } from "https://deno.land/std@0.224.0/http/server.ts";

const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") || "").trim().replace(/\/$/, "");

function getSecret(name: string): string {
  return (Deno.env.get(name) || "").trim();
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") +
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
  return base64Url(new Uint8Array(signature));
}

async function verifyState(state: string): Promise<boolean> {
  const secret = getSecret("LICENSE_SIGNING_SECRET");
  if (secret.length < 32) return false;

  const parts = state.split(".");
  if (parts.length !== 2) return false;
  const [body, signature] = parts;
  if (signature !== await hmacSha256(secret, body)) return false;

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(body)),
    );
    return (
      (payload?.v === 4 || payload?.v === 5) &&
      payload?.p === "lootlabs" &&
      (payload?.stage === 1 || payload?.stage === 2) &&
      typeof payload?.exp === "number" &&
      payload.exp > Math.floor(Date.now() / 1000) &&
      typeof payload?.n === "string" &&
      payload.n.length >= 16
    );
  } catch {
    return false;
  }
}

function corsHeaders(req: Request): Headers {
  const origin = req.headers.get("Origin") || "";
  const allowed = origin === "https://clearb.space" ||
    origin === "https://clearb.vercel.app" ||
    origin === "https://loot-link.com" ||
    origin === "https://lootdest.org";
  return new Headers({
    "Access-Control-Allow-Origin": allowed ? origin : "*",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Vary": "Origin",
  });
}

function brandingScript(): string {
  return `(()=> {
    "use strict";

    const CLEAR_LOGO_URL = "https://res.cloudinary.com/wmmf7i3g/image/upload/v1787241416/Adobe_Express_-_file-1.png";
    const CLEAR_LOGO_ID = "clear-lootlabs-top-left-logo";

    const GRAY = "#8b8b8b";

    const toRgb = (value) => {
      const m = String(value || "").match(
        /rgba?\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*([\\d.]+))?\\s*\\)/
      );
      if (m) {
        return {
          r: Number(m[1]),
          g: Number(m[2]),
          b: Number(m[3]),
          a: m[4] == null ? 1 : Number(m[4])
        };
      }

      const h = String(value || "").trim().replace(/^#/, "");
      if (/^[0-9a-f]{6}$/i.test(h)) {
        return {r:parseInt(h.slice(0,2),16),g:parseInt(h.slice(2,4),16),b:parseInt(h.slice(4,6),16),a:1};
      }
      if (/^[0-9a-f]{3}$/i.test(h)) {
        return {r:parseInt(h[0]+h[0],16),g:parseInt(h[1]+h[1],16),b:parseInt(h[2]+h[2],16),a:1};
      }
      return null;
    };

    const isRed = (value) => {
      const c = toRgb(value);
      if (!c || c.a === 0) return false;
      return c.r >= 110 && c.r >= c.g * 1.45 && c.r >= c.b * 1.45 && (c.r - Math.max(c.g, c.b)) >= 35;
    };

    const grayifyRed = () => {
      try {
        const root = document.body || document.documentElement;
        if (!root) return;

        const all = Array.from(root.querySelectorAll("*"));
        const properties = [
          ["color", "color"],
          ["backgroundColor", "background-color"],
          ["borderTopColor", "border-top-color"],
          ["borderRightColor", "border-right-color"],
          ["borderBottomColor", "border-bottom-color"],
          ["borderLeftColor", "border-left-color"],
          ["outlineColor", "outline-color"],
          ["textDecorationColor", "text-decoration-color"],
          ["fill", "fill"],
          ["stroke", "stroke"]
        ];

        for (const el of all) {
          if (!(el instanceof HTMLElement || el instanceof SVGElement)) continue;
          if (el.id === CLEAR_LOGO_ID) continue;

          const cs = getComputedStyle(el);
          for (const [prop, cssProp] of properties) {
            const value = cs[prop];
            if (isRed(value)) el.style.setProperty(cssProp, GRAY, "important");
          }
        }
      } catch (_) {}
    };


    const normalize = (value) =>
      String(value || "").replace(/\s+/g, " ").trim();

    const hide = (el) => {
      if (el instanceof HTMLElement) {
        el.style.setProperty("display", "none", "important");
        el.setAttribute("aria-hidden", "true");
      }
    };

    const isRedSquareBrandText = (text) => {
      const t = normalize(text);
      if (!t || t.length > 260) return false;
      return /red[-\s]?square/i.test(t) ||
        /protected\s+by\s+b\.?y\.?p\.?a\.?s\.?s/i.test(t) ||
        /red[-\s]?square\s+security/i.test(t) ||
        /b\.?y\.?p\.?a\.?s\.?s/i.test(t);
    };

    const isRedSquareBrandAsset = (el) => {
      if (!(el instanceof Element)) return false;
      const meta = [
        el.getAttribute("src") || "",
        el.getAttribute("alt") || "",
        el.getAttribute("title") || "",
        el.getAttribute("aria-label") || "",
        el.getAttribute("id") || "",
        el.getAttribute("class") || ""
      ].join(" ");
      return /red[-\s]?square|b\.?y\.?p\.?a\.?s\.?s/i.test(meta);
    };

    const removeOldClearPlacement = () => {
      for (const el of Array.from(document.querySelectorAll("[data-clear-brand-logo], #clear-lootlabs-top-left-logo"))) {
        if (el.id !== CLEAR_LOGO_ID) el.remove();
      }
    };

    const ensureTopLeftLogo = () => {
      if (!document.body) return;

      let logo = document.getElementById(CLEAR_LOGO_ID);
      if (!(logo instanceof HTMLImageElement)) {
        logo = document.createElement("img");
        logo.id = CLEAR_LOGO_ID;
        logo.src = CLEAR_LOGO_URL;
        logo.alt = "Clear";
        logo.title = "Clear";
        logo.referrerPolicy = "no-referrer";
        logo.decoding = "async";
        logo.setAttribute("aria-hidden", "true");
        document.body.appendChild(logo);
      }

      // Exactly one Clear logo, fixed in the top-left corner.
      logo.style.cssText =
        "position:fixed!important;left:16px!important;top:16px!important;" +
        "width:42px!important;height:42px!important;object-fit:cover!important;" +
        "border-radius:8px!important;display:block!important;z-index:2147483647!important;" +
        "pointer-events:none!important;user-select:none!important;";
    };

    const clean = () => {
      try {
        const root = document.body || document.documentElement;
        if (!root) return;

        const all = Array.from(root.querySelectorAll("*"));

        // Remove every visible Red Square / B.Y.P.A.S.S branding node.
        for (const el of all) {
          if (!(el instanceof HTMLElement)) continue;
          if (el.id === CLEAR_LOGO_ID) continue;

          if (isRedSquareBrandAsset(el)) {
            hide(el);
            continue;
          }

          const text = normalize(el.innerText || "");
          if (text && isRedSquareBrandText(text)) hide(el);
        }

        removeOldClearPlacement();
        ensureTopLeftLogo();
        grayifyRed();
      } catch (_) {}
    };

    const boot = () => {
      clean();
      const observer = new MutationObserver(() => clean());
      try {
        observer.observe(document.documentElement, {
          subtree: true,
          childList: true,
          attributes: true,
          attributeFilter: ["src", "alt", "title", "aria-label", "class", "id", "style"]
        });
      } catch (_) {}
    };

    if (document.documentElement) boot();
    else document.addEventListener("DOMContentLoaded", boot, {once:true});
  })();`;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(req) });
  }

  const url = new URL(req.url);
  const state = (url.searchParams.get("state") || "").trim();

  if (req.method !== "GET") {
    return new Response("/* method not allowed */", {
      status: 405,
      headers: new Headers({
        ...Object.fromEntries(corsHeaders(req)),
        "Content-Type": "application/javascript; charset=utf-8"
      })
    });
  }

  if (!state || !(await verifyState(state)) || !SUPABASE_URL) {
    return new Response("/* invalid branding state */", {
      status: 403,
      headers: new Headers({
        ...Object.fromEntries(corsHeaders(req)),
        "Content-Type": "application/javascript; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      })
    });
  }

  return new Response(brandingScript(), {
    status: 200,
    headers: new Headers({
      ...Object.fromEntries(corsHeaders(req)),
      "Content-Type": "application/javascript; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    })
  });
});
