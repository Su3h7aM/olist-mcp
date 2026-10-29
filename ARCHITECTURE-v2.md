# olistd — architecture v2 (DRAFT by Bill, for Prometeu review)
Supersedes the CLI shape in ARCHITECTURE.md. Data-model/sync/report ideas there still apply; process model, auth and transport change.

## Validated facts
- Rate limit is per ACCOUNT per minute, by plan (ajuda.olist.com, updated 15/10/2026): Construa/Crescer 30R/30W · Evoluir/Impulsione 60/60 · Domine 120/100 · Protagonize 140/100. Shared by all apps on the account. Headers X-RateLimit-Limit/Remaining/Reset confirm at runtime. => 5 accounts = 5 independent budgets.
- API v3 apps are "private mode": each account creates its own app (client_id/secret) in its ERP. OAuth2 auth-code via Keycloak (accounts.tiny.com.br). Access token 4h, refresh token 1 day.
- At 30 reads/min a 10k-entity detail backfill is ~5.5h; at 120/min ~1.4h. Backfill runs per account in parallel; fine for a daemon.

## D1. Process: one long-running daemon `olistd`
Pure Go, no CGO (modernc.org/sqlite). Single binary, config file, systemd/container. Components: HTTP server (MCP + admin + OAuth endpoints), per-account sync supervisor, per-account API client with its own rate limiter. No CLI-style "run and exit" paths; `olistd` is the product (small `olistctl`-style subcommands only for config check/migrate).

## D2. MCP transport: Streamable HTTP (MCP remote server spec), single endpoint `/mcp`
Client config = URL only. Validate Origin, bind behind TLS reverse proxy. stdio not needed (optional dev flag). Use official modelcontextprotocol/go-sdk if its streamable-HTTP + auth support covers it; else thin own implementation (spec is small).

## D3. Two separate OAuth relationships — never mixed
(a) **Olist upstream** (server <-> Olist): server-only. client_id/secret per account live in server config; Olist access/refresh tokens live in server storage; they are NEVER sent to MCP clients (MCP spec forbids token passthrough; and the secret can't leave the server anyway).
(b) **MCP client auth** (agent <-> olistd): olistd is an OAuth 2.1 resource server per the MCP authorization spec: serves Protected Resource Metadata (RFC 9728), 401 + WWW-Authenticate. 
   Recommendation: olistd also acts as its OWN minimal authorization server (RFC 8414 metadata, PKCE auth-code, Dynamic Client Registration or Client ID Metadata Docs), because that is the only way a generic MCP client can onboard with just a URL. Authorize step = owner login (admin secret from config, or later OIDC). Issued tokens are olistd tokens, scoped to accounts (`account:<slug>`, `read`, `write`).
   Also accept static long-lived bearer tokens (config-defined, scoped the same way) for headless agents that can't do browser OAuth.
   Rejected: redirecting the client straight to Tiny's authorize endpoint. It needs the client_secret at token exchange, issues tokens for one account only, and breaks the audience/passthrough rule.

## D4. Connecting Olist accounts (the Tiny consent), once per account
Admin page `/admin/accounts/<slug>/connect` -> redirect to Tiny authorize -> `/oauth/olist/callback` -> exchange code (server holds secret) -> store tokens. Redirect URI to register in each Olist app: `https://<host>/oauth/olist/callback` (one URI for all 5; account carried in `state`, signed, single-use).
Refresh-token lifetime is only 1 day: daemon refreshes proactively (e.g. every 1-2h, serialized per account, single-flight, persist rotated tokens atomically BEFORE use). If refresh fails (revoked/expired after long downtime) account goes `needs_reauth`: sync pauses, tools return a clear error with the connect URL, admin page shows status. Re-auth is the only manual step.

## D5. Account selection for clients
One endpoint, accounts are an argument: every tool takes `account` (slug); omitted => the token's only allowed account, else error listing allowed ones. `list_accounts` tool (slug, name, plan, sync status, coverage). Read/report tools also accept `account: "all"` (cross-account aggregates) restricted to the token's allowed set. Optional later: per-account URLs `/mcp/<slug>` that pin the account. Token scope enforces which accounts a client may touch; writes need `write` scope AND account scope.

## D6. Storage: SQLite per account (+ small control DB)
- `data/<slug>.db`: mirror tables (JSON `raw` + normalized columns + child tables + FKs, see v1 addendum), `sync_state`, `local_*`.
- `control.db`: accounts runtime state, Olist tokens (encrypted at rest with a key from env/file; secrets in config referenced via `${ENV}`/`file:` not inline in git), issued MCP tokens/clients (hashed), audit log.
- WAL; one writer goroutine per account DB; many readers. Cross-account SQL via ATTACH on a read-only connection (5 attached < SQLite default limit 10).
Rationale: isolation (a bug can't leak across stores), trivial per-account rebuild/delete, no account_id on every row/join.

## D7. Sync + read-through (replica AND cache)
- Per-account scheduler goroutine. Three priority classes on ONE shared token-bucket per account (sized from plan, auto-corrected by X-RateLimit-* headers; reserve ~20% of read budget for on-demand): (1) on-demand read-through, (2) incremental sync, (3) backfill.
- Incremental: resources with `dataAtualizacao`/`dataAlteracao` filters use cursor+overlap; notas/contas-pagar use date windows + resync of open items; deletions via periodic id-set reconciliation (low priority).
- Read-through semantics: `get_*(id)`: local hit -> serve with `synced_at`; miss -> API fetch (priority 1) -> upsert -> serve. List/search/report: ALWAYS local only (a miss can't be detected for a query), response carries `coverage` ({backfill: complete|in_progress, as_of}) so agents know completeness. `refresh:true` forces a live refetch of one entity.
- 429 / exhausted budget: honor Reset, backoff; never fail a user request just because background work is running (priority 1 preempts).
- Webhooks (vendas, enviados, estoque, NF autorizada) become viable now that there is a public server: optional `/webhooks/olist/<slug>/<secret>` that enqueues ids for priority-1.5 refetch. Plan-dependent, so phase 2.
- Writes: pass to API, then write-through refetch. Disabled unless token has `write`; destructive tools need `confirm:true`; all writes audited.

## D8. Differences from wacli we deliberately do NOT copy
No per-store process lock/delegation, no QR/pairing, no one-shot `sync` command, no JSON-lines CLI output. We keep from it only the idea: separate session/auth state from the searchable mirror.

## D9. Config (YAML, example)
```
server: {listen: ":8080", public_url: "https://olist.example.com", data_dir: "/var/lib/olistd", admin_secret_file: "/run/secrets/admin"}
accounts:
  - {slug: loja-a, name: "Loja A", client_id: "...", client_secret: "${OLIST_A_SECRET}", plan: crescer}  # plan -> initial rate budget
  # x5
mcp_tokens: [ {name: "agent-x", token_hash: "...", accounts: [loja-a], scopes: [read]} ]
```

## Key decisions for the user to approve (the only ones needing review)
1. Daemon + Streamable HTTP at one `/mcp` URL (client needs only the URL).
2. olistd is its own OAuth authorization server for MCP clients (+ static scoped tokens for headless agents); Olist tokens/secrets never leave the server.
3. One-time per-account Olist consent via admin page, single redirect URI; proactive refresh; `needs_reauth` state is the only manual step (refresh token lives 1 day).
4. SQLite per account (+control DB), cross-account queries via ATTACH; `account` is a tool argument, token scopes limit accounts.
5. Replica semantics: lists/reports local-only with explicit coverage flags; get-by-id is read-through; 3-priority shared rate bucket per account.
