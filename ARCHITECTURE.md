# olistcli / olist-mcp — architecture

Go, wacli-style: one binary, CLI + MCP server, local SQLite mirror of the Olist ERP (Tiny) API v3.
Spec: `openapi.json` (copy of https://erp.tiny.com.br/public-api/v3/swagger/swagger.json, v3.1, 221 operations, base `https://api.tiny.com.br/public-api/v3`, Bearer auth).

## Purpose / constraints
- Read-fast: queries (CLI/MCP) hit local SQLite; API only on `sync` and on explicit writes.
- Rate limit is per account (headers X-RateLimit-Limit/Remaining/Reset), reads > writes. Access token 4h, refresh token 1 day (OAuth2 auth code, Keycloak: accounts.tiny.com.br/realms/tiny/protocol/openid-connect/{auth,token}).
- Writes (POST/PUT/DELETE: emitir NF, baixar conta, ajustar estoque...) are dangerous: off by default.

## Layout
```
cmd/olist/main.go          # flag parsing, dispatch only
internal/api/              # HTTP client: auth header, rate limiter (honors X-RateLimit-*), retry on 429/5xx, pagination iterator (limit/offset)
internal/auth/             # OAuth login (local loopback redirect), token store (0600 file), refresh; single-flight refresh
internal/store/            # SQLite (modernc.org/sqlite, no CGO; FTS5 built in), migrations, per-resource upsert/query
internal/sync/             # per-resource sync procedures (list -> get detail -> upsert), cursor table
internal/mcp/              # MCP stdio server (official go-sdk), tools = thin wrappers over store/sync/api
internal/cli/              # commands: auth, sync, doctor, <resource> list/get/search, mcp serve
```
Plain procedures, no interfaces until a second implementation exists. Errors returned, never swallowed. Store dir `~/.olist` (`--store`, `OLIST_STORE`), DB `olist.db`, tokens `auth.json` (separate from DB, like wacli).

## Data model (SQLite)
Authority: Olist. Local = cache. Per resource table: `id INTEGER PK, <indexed cols>, raw JSON, synced_at`. Keep full JSON in `raw`; extract only columns we filter/sort/FTS on (numero, situacao, data, cliente, cpfCnpj, valor...). Avoids schema churn when the API adds fields.
- `sync_state(resource, cursor_kind, cursor_value, last_full_at, last_ok_at)`
- FTS5 tables: produtos(nome, codigo, gtin), contatos(nome, fantasia, cpfCnpj, email), pedidos(numero, cliente, numeroEcommerce)
- Tables, phase 1 (read-heavy core): produtos (+variações, estoque, depositos), contatos, pedidos (+itens), notas, contas_receber, contas_pagar, categorias, formas_pagamento/envio, vendedores, marcas, tags, info.
- Phase 2: crm, orcamentos, ordem-compra, ordem-servico, expedição, separação, extrato, caixa, listas-preços, serviços.

## Sync
- List endpoints give summaries; detail needs GET by id. Strategy: list with incremental filter, then fetch details for new/changed ids, upsert (single tx per batch).
- Incremental filters in spec: produtos `dataAlteracao`, contatos `dataAtualizacao`, pedidos `dataAtualizacao`, estoque `dataAlteracao`, contas-receber `dataAtualizacao`. notas / contas-pagar have no update filter -> window by date (dataInicial/dataFinal, emissão) + periodic full resync of open ones (situacao != final).
- Cursor = max server date seen minus overlap margin (idempotent upsert makes overlap safe). Deletions are invisible to list endpoints -> `sync --full` reconciles by id set diff.
- Rate budget: sync reads `X-RateLimit-Remaining`, sleeps until Reset when low; concurrency capped (default 2 workers). Detail-fetch is the cost driver; make it resumable (cursor advances per batch).
- Webhooks (vendas, enviados, estoque, NF autorizada) optional phase 3: `olist serve-webhook` writes ids into a queue table, sync drains it. Needs Webhooks app/plan, so not required.
- `sync --follow` = poll loop (interval, default 5 min). Single writer lock per store, like wacli.

## CLI (wacli-style)
`olist auth` · `olist sync [--resource X] [--full] [--follow]` · `olist doctor` · `olist produtos|pedidos|contatos|notas|contas-receber|contas-pagar ... list|get|search` · `olist sql "<SELECT...>"` (read-only conn) · `olist mcp` (stdio). Global: `--json`, `--read-only` / `OLIST_READONLY=1`, `--store`.
Write commands live under `olist api <operationId> --data @file` generated from the spec; require `--allow-writes`.

## MCP
- stdio transport. Tools (phase 1), all reading local DB unless noted:
  `search_produtos`, `get_produto`, `search_contatos`, `get_contato`, `list_pedidos`, `get_pedido`, `list_notas`, `get_nota`, `list_contas_receber`, `list_contas_pagar`, `get_estoque`, `sql_query` (read-only, row cap), `sync_status`, `sync_run` (triggers incremental sync).
- `refresh_live` flag on get_* to bypass cache for one entity (uses API, updates cache).
- Write tools (`atualizar_estoque`, `baixar_conta`, `emitir_nota`, `atualizar_situacao_pedido`...) registered only with `--allow-writes`; each returns what it will do first (`confirm:true` param required). Annotate tools with readOnlyHint/destructiveHint.
- Every response includes `synced_at` so the model knows staleness. Output size capped, paginated with offset.

## Codegen
`openapi.json` -> small generator (`tools/gen`) producing typed request/response structs + operation table for the `api` passthrough. Hand-write only store mapping and sync procedures. Keep generated code committed.

## Testing (per user policy)
No mocks. API tests run against a local httptest server replaying recorded real-shaped fixtures from the spec; store tests use real SQLite (temp file); bug repro tests first; assert on public CLI/MCP output; property tests for sync cursor/upsert idempotency.

## Open decisions for the user
1. Credentials: needs an app created in the ERP (client_id/secret) + OAuth redirect; confirm loopback `http://localhost:PORT/callback` is registrable.
2. Writes in MCP: default off (recommended). OK?
3. Phase-1 resource set above OK? (CRM/OS/expedição deferred.)
4. Go version/toolchain: Go is not installed on this host; implementer must install.

## Addendum: purpose confirmed (full local mirror for rate-limit avoidance + reporting)
The user's goal: a replica of the API data so bulk reads and cross-entity reports don't depend on the rate limit. Consequences for the design:
1. **Mirror, not cache.** Goal is complete coverage of every GET resource (phase 2 resources included, just later). Queries/reports never call the API.
2. **Relational, not just JSON.** Keep `raw` JSON, but also normalize what reports join on: `pedido_itens`, `nota_itens`, `conta_*` parcelas, `produto_variacoes`, `estoque_saldos(produto, deposito)`, `contato_pessoas`, marcadores/tags link tables. Real FKs on ids (pedido.contato_id, pedido_itens.produto_id, nota.pedido_id, conta.nota_id/venda_id). Columns typed (dates ISO-8601, money as integer cents or decimal text, never float).
3. **Report layer.** SQL views shipped in migrations (vendas_por_dia, margem_por_produto, inadimplencia, estoque_critico...). `olist sql` and MCP `sql_query` (read-only connection, `PRAGMA query_only`, row/time caps) are first-class; MCP also exposes `describe_schema` so the model can write correct SQL.
4. **Backfill is the expensive part.** Lists return summaries; each detail is 1 request. Cost = (#entities) / (reads per minute). Backfill must be: resumable (cursor per resource and per page), prioritized (produtos/contatos/pedidos first), progress-reporting (`sync status` with ETA from X-RateLimit-Limit), and run in background. After backfill, incremental sync is cheap (only changed ids).
5. **Freshness contract.** Each table has `synced_at`; `sync_state` has last_ok per resource; MCP/CLI report staleness. Writes through the API are followed by a re-fetch of that entity into the mirror (write-through), so the mirror never lags our own changes.
6. **Local-only data.** Mirror tables are API-owned and may be rebuilt at any time; any user-added data (notes, report snapshots) goes in separate `local_*` tables that sync never touches.
7. **Open risk to verify early (spike before building everything):** the real rate limit of the account and whether list payloads already contain enough fields to skip detail fetches for some resources. Prometeu should measure this with a real token on day one and tell us the actual backfill ETA.
