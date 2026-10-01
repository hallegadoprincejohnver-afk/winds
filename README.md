# Clear Anti-Bypass Gateway

Independent server-side verification gateway for Clear Linkvertise and LootLabs checkpoints.

The gateway never treats client-side completion as proof. Provider-side evidence is required before a one-time HMAC clearance ticket can be issued.

Providers:
- Linkvertise: verifies the official Target-Link anti-bypass hash server-side.
- LootLabs: verifies the official postback click_id, IP, and unique_id server-side.

Defense in depth:
- short-lived random sessions
- Secure/HttpOnly/SameSite __Host- cookie
- IP + User-Agent binding
- replay protection
- rate limiting
- automated-client and client-integrity telemetry
- optional Cloudflare Turnstile server-side validation

See render.yaml and .env.example for deployment configuration. No existing Clear/Supabase functions are modified by this repo.
