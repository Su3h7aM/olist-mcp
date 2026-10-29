# olistd — v2.1 (Bill + Prometeu reconciled). Base: ARCHITECTURE-v2.md; this file overrides where it differs.

## Spec inventory (from openapi.json, 221 ops)
- 133 writes (POST/PUT/DELETE) — never mirrored; only write-through refetch.
- 37 paginated list endpoints (limit/offset) = the sync surface; 51 other GETs = detail/child fetches (by id), plus a few non-enumerable (xml, comprovante, link, etiquetas = fetched on demand, NOT mirrored in bulk; xml/PDF stay out of the replica or are lazily cached as blobs).
- Not every list is top-level enumerable: children (contatos/{id}/pessoas, crm/assuntos/{id}/acoes|anotacoes, produtos/{id}/custos|logs-*, estoque/{id}/logs-movimentacao) need a per-parent N+1 fan-out — budgeted last, incremental only for changed parents. Lookup/reference lists (depositos, formas-*, marcas, tags, categorias, vendedores, usuarios, /info) are small: full refresh each cycle.
- Each resource gets an explicit sync class in code: `incremental(filter)`, `window(date)`, `full-refresh`, `child-fanout`, `on-demand-only`. Coverage is reported per resource (last_ok, class, complete|partial|n/a), never a global "complete".

## Reconciliation with Prometeu's review
- D1 agree: pin Go + modernc versions; CI proves CGO_ENABLED=0 build, FTS5, WAL, migrations, clean shutdown. One writer goroutine per DB.
- D2 agree: official go-sdk (Streamable HTTP + bearer/metadata middleware); pin SDK+spec version. URL-only config = discovery start; consent still happens in the client.
- D3 ACCEPTED CHANGE: do NOT hand-roll an authorization server. Plan: (1) v1 ships static scoped bearer tokens (hashed, expiry, revocation, per-account allowlist) — works for headless agents immediately; (2) MCP-client OAuth is delivered by embedding a maintained OAuth2/OIDC provider library (candidates: ory/fosite, zitadel/oidc OP) behind the single-owner login, with PKCE, audience/resource binding, and DCR/CIMD only if target clients need it. Gate step 2 on a compatibility prototype against the real target clients. Olist tokens never reach clients.
- D4 agree: refresh serialized per account, response persisted before use; if rotation + crash loses the token, or refresh is rejected, state=needs_reauth (transient network/5xx errors retry with backoff, only invalid_grant flips state). Do not assume periodic refresh extends the 1-day refresh lifetime; confirm sliding vs fixed on first real account.
- D5 agree: authorize every op and every attached DB server-side from the token, including `all`; slug from client is untrusted. Sessions isolated.
- D6 agree: `sql_query` runs on a dedicated read-only connection that the server attaches itself (allowlisted files, `PRAGMA query_only`, authorizer callback denying ATTACH/PRAGMA/load_extension/writes, row/time caps, cancellation). Results carry per-account `as_of`; no cross-DB snapshot consistency promised. Token/secrets encrypted with AEAD (XChaCha20-Poly1305), key from env/file, versioned for rotation; config secrets via env/file refs; backups must include the key separately.
- D7 ACCEPTED CHANGES: no preemption/availability guarantee. Separate read and write budgets per documented plan. Per-account limiter = local bucket sized from plan config, corrected by X-RateLimit-* headers; ~20% read capacity reserved for on-demand as best effort; on-demand waits up to a timeout then returns a retryable error (`rate_limited`, retry_after) rather than hanging. Other apps on the same account share the limit — a 429 is handled, not treated as a bug. Deletion detection only when a full listing completed cleanly in one pass; 404/5xx never imply deletion (needs two consecutive clean full passes or explicit 404 on direct fetch twice).
- D8/D9 agree: validate config + slugs + file perms at startup, never log secrets, require/validate public_url + trusted proxy/TLS.

## Plan before/within implementation (no rate-limit measuring)
1. Prototype: pure-Go build + minimal go-sdk Streamable HTTP server + bearer middleware, test with the real target MCP clients (what the user will connect).
2. Prototype OAuth path with the chosen library against those clients (decides step 2 of D3).
3. Confirm on first real account: redirect URI acceptance, refresh rotation/lifetime, plan limits via headers (validation only).
4. Then build in order: store+migrations -> api client/limiter -> auth/token manager -> sync (lookups, produtos, contatos, pedidos, notas, contas, estoque) -> MCP tools -> admin page -> remaining resources.

## Key decisions for the user (final list)
1. Always-on daemon, pure Go (no CGO), MCP Streamable HTTP at a single URL.
2. Client auth: static scoped tokens first; real OAuth via an embedded maintained OAuth library (not hand-written), after a compatibility prototype. Olist secrets/tokens stay server-side.
3. Olist account connection: one admin-page consent per account, one redirect URI for all five; automatic refresh; `needs_reauth` is the only manual step.
4. One SQLite DB per account + control DB; `account` is a tool argument; token scopes restrict accounts; read-only cross-account SQL via server-controlled ATTACH.
5. Replica semantics: per-resource sync classes with explicit coverage; lists/reports local-only; get-by-id read-through; best-effort on-demand priority, no availability promise; writes off unless `write` scope.

## v2.2 update (user answers)
- Clients: OpenBot (Nightly Labs) driving Codex, Claude Code and OpenCode. All are MCP remote (Streamable HTTP) clients; OAuth is required in v1 (not "later"). Static tokens remain only as a break-glass/headless fallback.
- AS requirements to satisfy all of them (verify each with a real login in the prototype, do not assume): RFC 9728 protected-resource metadata, RFC 8414 AS metadata, authorization-code + PKCE S256, refresh tokens, RFC 7591 dynamic client registration (and CIMD if a client needs it), RFC 8707 `resource` binding, redirect URIs of loopback and server-side callbacks (OpenBot signs in from a server, so authorize/callback must work over the public URL).
- Authorize step = owner login + consent screen where the owner picks which Olist accounts (and read/write) the client gets. The grant is stored on the issued token => every call is authorized against that account set. DCR alone grants nothing.
- Embed a maintained OAuth library (fosite / zitadel-oidc candidates); no hand-rolled crypto/flows. Prototype picks one.
- Deploy: container (static binary, CGO off, distroless/scratch, non-root, data volume for /data, secrets via env/file), run via Portainer by Fesco; public through Cloudflare Tunnel (HTTPS terminated at Cloudflare; olistd trusts X-Forwarded-* only from the tunnel). Streamable-HTTP SSE needs keepalive pings < 100 s (Cloudflare idle timeout). Admin/consent endpoints: owner login, optionally also behind Cloudflare Access. Needs a stable hostname -> public_url, and the Olist redirect URI `https://<host>/oauth/olist/callback` registered in all 5 Olist apps.
