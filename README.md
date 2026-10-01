# Clear Anti-Bypass Gateway

Independent server-side gateway for Clear's Linkvertise and LootLabs checkpoint verification.

## Core security rule

A browser saying "completed" is never accepted as proof. A clearance ticket is created only after provider-side evidence is verified by this service.

### Linkvertise

Linkvertise Target-Links can append a short-lived hash after a visitor completes the ad flow. The gateway sends that hash to Linkvertise's official anti-bypass API and requires the documented successful response before releasing a one-time clearance. The hash is treated as single-use/replay-sensitive.

### LootLabs

Each gateway session receives a random puid. LootLabs returns that value as click_id in its postback together with the visitor IP and a unique_id. The gateway requires the exact session click ID, matching provider-reported IP, and a never-before-claimed unique ID before release.

## Defense layers

- Short-lived, 256-bit random sessions.
- __Host- Secure/HttpOnly/SameSite cookie.
- Session binding to IP and User-Agent, configurable by environment.
- One-time provider evidence and one-time clearance claims.
- Rate limiting for session creation, client telemetry, callbacks, and LootLabs postbacks.
- Browser automation and userscript integrity signals: webdriver, common automation globals, native API tampering, DOM marker tampering, visibility anomalies, and suspicious timing.
- Optional Cloudflare Turnstile with server-side Siteverify validation.
- CSP, HSTS, clickjacking protection, no-store caching, and HTTPS-only integration URLs.
- Audit logs store hashes of IP/User-Agent instead of raw identifiers.

## Provider integration

For Linkvertise, configure the Target-Link to redirect to:

https://YOUR-GATEWAY/v1/provider/linkvertise/complete

For LootLabs, configure the postback URL:

https://YOUR-GATEWAY/v1/webhooks/lootlabs?secret=YOUR_POSTBACK_SECRET

and ensure the final provider flow returns the user to:

https://YOUR-GATEWAY/v1/provider/lootlabs/complete

The gateway appends a random puid to LootLabs links automatically when a session is started.

## Clear integration

1. Clear's backend calls POST /v1/session/start with X-Antibypass-Key.
2. The user is sent to the returned sessionUrl.
3. The provider returns to the appropriate completion endpoint.
4. The gateway redirects to the Clear destination with a short-lived one-time ab_ticket.
5. Clear's backend calls POST /v1/verify with the ticket and step.
6. Only a successful /v1/verify response should unlock the next checkpoint or final content.

Use a new gateway session for every checkpoint. Never grant step 2 or the final result based only on frontend state.

## Optional Turnstile

Set TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY, TURNSTILE_HOSTNAME, and TURNSTILE_ACTION to enable interaction-only Turnstile before provider completion. The service validates the token server-side.

## Operational notes

The service is designed to keep normal provider redirects low-friction. Detection signals are a secondary defense; provider proof, binding, freshness, and one-time claims are the real authorization gate.

No web anti-bypass system can honestly guarantee detection of every future userscript or bot. The important security property is that bypassing or forging the browser flow does not create a valid server-side clearance.

## Deployment

render.yaml defines one Singapore web service plus one Redis-compatible Render Key Value instance. Do not commit provider secrets; use Render environment variables.
