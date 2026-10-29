# MCP-client OAuth design (Bill) — olistd as OAuth AS + resource server

## Library decision
**github.com/zitadel/oidc/v3 `pkg/op`** (Apache-2.0, v3.51.16 released 2026-10-15, pushed daily, OpenID-certified OP). Pure Go, `op.NewProvider(config, storage, issuerFn, opts...)`, `op.CreateRouter`/`Provider.Handler`, we implement `op.Storage`.
Rejected: ory/fosite (last release v0.49.0 Dec 2024, last push Nov 2025; no registration endpoint either); dex/authelia (products, not embeddable libs); hand-written AS (Prometeu veto, agreed).
Resource side: go-sdk v1.8.0 already in go.mod: `auth.RequireBearerToken(verifier, &RequireBearerTokenOptions{ResourceMetadataURL, Scopes})` and `auth.ProtectedResourceMetadataHandler(*oauthex.ProtectedResourceMetadata)`.

## Verified gaps in the library (we must build these; small)
Checked in source (zitadel/oidc master, fosite master):
1. **No RFC 7591 dynamic client registration** in either lib (zitadel only lists the field in discovery JSON, `pkg/oidc/discovery.go`). Build `POST /oauth/register`.
2. **No RFC 8707 `resource` on /authorize**: `pkg/oidc/token_request.go:260` only parses it for token exchange. AuthRequest.GetAudience() comes from our storage, so: wrap router with an `op.HttpInterceptor` that validates `resource` (if present must equal canonical MCP URL, else `invalid_target`) on /authorize and /token; our storage sets audience = canonical MCP URL always (one resource server).
3. **No RFC 8414 document**: zitadel serves `/.well-known/openid-configuration`; MCP spec (2025-11-25) says clients MUST try `/.well-known/oauth-authorization-server` then OIDC discovery for issuers without path. Serve the same JSON at the 8414 path (small handler) plus `code_challenge_methods_supported:["S256"]`, `registration_endpoint`, `client_id_metadata_document_supported`.
4. **No Client ID Metadata Documents** (spec 2025-11-25 lists CIMD first, DCR as fallback). Phase 1 = DCR only; CIMD optional later (fetch HTTPS client_id URL with SSRF guard, validate redirect_uris).
5. **Account-scoped grants** are ours: see below.

## Endpoints (all under public_url, behind Cloudflare Tunnel)
- `/.well-known/oauth-protected-resource` (+ `/mcp` path variant) via `auth.ProtectedResourceMetadataHandler`: `resource=<public>/mcp`, `authorization_servers=[<public>]`, `scopes_supported=[olist:read, olist:write]`.
- `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke` (RFC 7009) — zitadel router + our wrappers.
- `/mcp` — `RequireBearerToken` middleware in front of `mcpserver.Handler()`; 401 carries `WWW-Authenticate: Bearer resource_metadata="…"`. Issuer = public_url, no path (simplest discovery).
- `/admin/*` — owner login, consent, Olist connect (existing `internal/admin`).

## Flow
1. Client hits /mcp → 401 + resource_metadata → fetches PRM → AS metadata.
2. Client `POST /oauth/register` (public client, `token_endpoint_auth_method=none`, redirect_uris, grant_types authorization_code+refresh_token). Registration stores a client row with status `unapproved`; **it grants nothing** (D2 text). Rate-limit, cap clients (e.g. 200), TTL-delete clients never approved, redirect URI rules: https or loopback http only, exact match.
3. /authorize (PKCE S256 mandatory; plain rejected; `op.Config.CodeMethodS256=true`, set `RequireAuthTime` off). Storage `CreateAuthRequest` persists request; zitadel redirects to our login URL (`op.AuthorizeCallbackURL`) with request id.
4. Our `/admin/login` + `/admin/consent?id=`: owner authenticates, sees client name/redirect host, ticks accounts + read/write, submit (CSRF token + SameSite=Strict + POST). On approve: `storage.SaveGrant(authReqID, owner, accounts[], scopes[])`, then redirect to `op.AuthCallbackURL(provider)(id)`. Deny → access_denied.
5. /token: code → storage mints **opaque** access token (32 random bytes; store SHA-256 only; 15–60 min TTL) and rotating refresh token (hash; reuse detection ⇒ revoke whole grant family, required for public clients by spec). `aud` = canonical MCP URL, grant row carries accounts+scopes.
6. /mcp: `TokenVerifier` func looks up hash → returns `auth.TokenInfo{Scopes, Expiration, UserID, Extra{"grant_id","accounts","aud"}}` (check aud == canonical URL, not revoked, owner still valid). Tool handlers read `auth.TokenInfoFromContext(ctx)` and **intersect any `accounts` argument with the grant** server-side; write tools additionally need `olist:write` and the account in the grant. Olist tokens never touch this path.

## Why opaque, not JWT
Instant revocation, per-grant account list changes without reissue, no signing-key rotation surface, verifier is one indexed lookup. zitadel supports it: implement `Storage.CreateAccessToken` returning our opaque ID; skip JWT/ID-token unless a client requires `openid` (advertise scopes `olist:read olist:write offline_access` only; MCP does not need OIDC id_token; confirm zitadel does not force `openid` — **blocker check #1**).

## Storage (control.db, same encrypted-key regime as tokenstore)
Tables (migration 002 in control DB, NOT olist.db so SQL tools can’t reach them): `oauth_client(id, name, redirect_uris, created_at, approved_at, last_used)`, `oauth_auth_request(id, client_id, redirect_uri, code_challenge, scopes, state, resource, expires_at)`, `oauth_grant(id, client_id, owner, accounts_json, scopes, created_at, revoked_at)`, `oauth_code(hash, grant_id, expires 60s, used)`, `oauth_access(hash, grant_id, expires)`, `oauth_refresh(hash, grant_id, family, parent, used_at, expires)`. Hash everything at rest; codes single use in a transaction (reuse admin/oauthstate patterns but durable: current `internal/oauthstate` is memory-only, fine for Olist connect, NOT for this). Signing key is only needed if we use JWT/request objects: zitadel needs a `Crypto` key (32 bytes, `op.NewProvider` arg) for encrypting auth-request ids/codes — load from env/file, same rules as token key.
Expired-row janitor goroutine; admin page to list/revoke grants (revoke = set `revoked_at`, verifier rejects).

## Owner authentication (single owner, no user DB)
Phase 1: `admin_secret_file` (argon2id hash in config, not plaintext) → login form → session cookie (random 32B, stored hashed in control.db, `Secure; HttpOnly; SameSite=Strict`, 8h, rotated on login) → this is the `admin.Owner` func (`internal/admin/connect.go:17`) returning owner id "owner". Login throttling (per IP + global backoff). CSRF: Origin/Sec-Fetch-Site check + per-session token on every POST (Icarus finding #1 in msg 203 — wiring must enforce). Optional second layer: Cloudflare Access in front of `/admin/*` only; never in front of `/oauth/*` or `/mcp` or `/.well-known/*` (clients can’t do Access login). Passkeys/OIDC owner login = later.

## Codebase touchpoints
- new `internal/mcpauth` (storage implementing `op.Storage`, DCR, consent, verifier, metadata); keep `internal/admin` for Olist connect.
- `cmd/olist-mcp`: build mux: PRM, AS metadata, op router, admin, `/mcp` wrapped; drop loopback-only restriction behind explicit `public_url` + trusted-proxy config (go-sdk Streamable handler DNS-rebinding/Origin settings: configure `CrossOriginProtection`/allowed hosts for the public host rather than disabling).
- `mcpserver.Handler()` must become per-request tool authorization aware (TokenInfo from context).
- Stateful sessions: bind session to `grant_id` at initialize; reject requests whose token’s grant differs from the session’s.

## Remaining compatibility checks (cannot be settled from specs; need a real login each)
1. zitadel/oidc accepts a non-`openid` scope set and works without ID tokens / `openid` scope (else we advertise `openid` and ignore id_token).
2. **Claude Code**: supports DCR + loopback redirect; verify it sends `resource`, accepts `WWW-Authenticate` PRM discovery, and refresh rotation.
3. **Codex** (`codex mcp login`): DCR support, redirect (loopback port), scope handling when `scopes_supported` is present, token refresh.
4. **OpenCode**: DCR + callback server (localhost:19876-style fixed port?) — fixed redirect ports must be accepted by exact-match rule; check whether it needs pre-registered `clientId` config instead of DCR.
5. **OpenBot (Nightly Labs)**: it authenticates from a server, not a desktop: confirm its redirect URI (https callback on its own host), whether it uses DCR or CIMD, whether it persists/refreshes tokens across restarts, and how it surfaces the consent step to the user. Unknown to us — **needs its docs/maintainer or a test instance**.
6. Behind Cloudflare Tunnel: SSE keepalive < 100 s; `X-Forwarded-*` trusted only from tunnel; issuer/redirect scheme stays https.
7. Clients that skip `resource`: we default audience to canonical URL (accept absent), reject mismatched.
8. Clock skew + token TTL vs long backfill-driven tool calls (not an issue; tool calls read local DB).
Test plan (project policy: no mocks): real zitadel provider + real SQLite control DB in-process; drive full flow with go-sdk `auth.AuthorizationCodeHandler`/`oauthex.RegisterClient` (it is a real client implementation, v1.8.0 `auth/authorization_code.go`, `oauthex/dcr.go`) including PKCE failure, replay, refresh-reuse revocation, account-intersection, audience mismatch; then the 4 real-client logins above.

## Blockers / decisions needed
- Hostname + TLS public URL (still unknown) — issuer cannot be finalized without it.
- OpenBot’s OAuth client behavior (check 5) — only unknown that could change DCR vs CIMD priority.
- Owner secret provisioning (who sets `admin_secret_file`).
Effort estimate: mcpauth storage+DCR+consent+verifier ≈ the bulk; ~1.5–2k LOC Go incl. tests, delegable to Icarus in slices (storage+migration, DCR endpoint, consent/login, verifier+tool-scoping, interceptor for `resource`).
