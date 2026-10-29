# olistd v2.3 — multi-account data model (Bill; supersedes D6 "SQLite per account" and v1 per-resource table sketches)

## Facts from the user
6 Olist accounts = 6 companies (6 CNPJs), multi-company setup. Customers, suppliers, product catalog are the same logical records in all 6, but each account holds its own copy with its OWN numeric ids. Cross-account identity: product = SKU; contact = CPF/CNPJ (my proposal, to confirm). Transactions (pedidos, notas, contas) belong to one company.

## Decision: ONE SQLite file for data, ONE control DB for secrets
- `olist.db` (all 6 accounts) + `control.db` (Olist tokens, client secrets refs, issued MCP grants, audit). Separate files so SQL tools can never reach tokens, and so backup/permissions differ.
- Single data DB removes ATTACH, makes cross-account JOIN/report plain SQL, no duplicated shared data to keep consistent.
- Writes: one writer goroutine for olist.db fed by 6 account workers via a channel; batches of one API page per transaction; WAL; readers concurrent. Throughput is API-bound (<=140 req/min/account), so a single writer is not a bottleneck.

## Two layers, strictly separated
**Layer 1 — source mirror (faithful, per account).** Every mirrored row is keyed `(account_id, id)` where `id` is that account's own Olist id. `WITHOUT ROWID`, composite PKs. Never merged, never rewritten. This is what sync owns.
**Layer 2 — identity (derived, never copied).** Canonical product/contact is NOT a duplicated table; it is a *key* computed at ingest and indexed, and views group by it:
- `produto.sku_key` = trim(sku) (exact, case-preserving; collisions flagged, see below)
- `contato.doc_key` = digits-only CPF/CNPJ (empty => no canonical identity, row stays account-local)
- denormalized into children at ingest so reports survive deleted/unsynced parents: `pedido.contato_doc_key`, `pedido_item.sku_key`, `nota.contato_doc_key`, `nota_item.sku_key`, `conta_*.contato_doc_key`, `estoque.sku_key`.
Manual fixes (SKU renamed in one account, contact without doc): `local_identity_override(kind, account_id, remote_id, canonical_key)`; ingest and views apply it. `local_*` tables are never touched by sync.

## Schema sketch
```
account(id INTEGER PK, slug UNIQUE, name, cnpj_key, plano, status, is_canonical_source INTEGER)   -- cnpj from GET /info
produto(account_id, id, sku, sku_key, nome, tipo, situacao, gtin, preco_cents, custo_cents, dt_alteracao, raw JSON, synced_at,
        PRIMARY KEY(account_id,id)) WITHOUT ROWID;  INDEX(sku_key); INDEX(account_id, sku_key)
produto_variacao(account_id, produto_id, id, sku, sku_key, ...)         -- variations carry their own SKU
contato(account_id, id, doc_key, nome, fantasia, tipo_pessoa, is_cliente, is_fornecedor, situacao, raw, synced_at, PK(account_id,id)); INDEX(doc_key)
pedido(account_id, id, numero, contato_id, contato_doc_key, situacao, data, total_cents, vendedor_id, raw, synced_at, PK(account_id,id))
pedido_item(account_id, pedido_id, seq, produto_id, sku_key, qtd, unit_cents, total_cents, PK(account_id,pedido_id,seq))
nota / nota_item / conta_receber / conta_pagar / estoque(account_id, produto_id, deposito_id, sku_key, saldo, reservado) / deposito / marca / tag / categoria / forma_* / vendedor ...  (all (account_id,id))
sync_state(account_id, resource, class, cursor, last_ok_at, last_full_at, coverage)   -- per account AND resource
local_identity_override(...), local_note(...)
```
Rules: ids are INTEGER from the API; money = integer cents; dates ISO-8601 text; `raw` JSON kept; lookup tables (marcas, tags, formas, categorias, vendedores) are also per account (their ids differ too) with a `name_key` for cross-account grouping.
**No enforced FKs between mirror entities**: partial backfill and out-of-order sync would make them fail. Relations are declared in comments/docs and verified by `v_orphans` views; a get-by-id miss triggers read-through fetch of the missing parent.

## Derived views (the reason for the single DB)
- `v_produto_canonico(sku_key, n_accounts, account_ids, nome_canon, ...)` — attributes from the account marked `is_canonical_source`, else most recently changed.
- `v_produto_drift` — same SKU, different nome/gtin/ncm/preço across accounts.
- `v_produto_sku_problems` — empty SKU, duplicate SKU inside one account, SKU present in <6 accounts.
- `v_contato_canonico(doc_key, ...)`, `v_contato_dup` (same doc twice in one account).
- `v_intercompany_contato` — contacts whose doc_key equals another account's `account.cnpj_key`: sales between the group's own companies; reports can exclude them to avoid double counting.
- `v_vendas_por_sku_dia(sku_key, account_id, dia, qtd, total)` and other report views join by keys, not by ids.
- `v_estoque_por_sku(sku_key, total, por_conta...)`. Stock/price/cost are ALWAYS per account; cross-account totals are explicit sums, never "the" value.

## MCP surface consequences
- Every entity returned carries `{account: slug, id}`; tools accept `accounts: [slugs] | "all"` (intersected with the login's grant, server-side).
- Cross-account lookups: `get_produto_by_sku(sku)` -> per-account ids + drift flags; `get_contato_by_doc(doc)`. Write tools take `account` + resolve the id from SKU/doc locally; fan-out writes to all 6 are an explicit separate action with a preview, never implicit.
- `sql_query` isolation: with one DB, scope must be enforced on rows. Plan: read-only connection per request with TEMP VIEWs named like the tables, filtered by `account_id IN (granted)`, base tables in a schema the statement cannot name; authorizer/statement checks deny writes, ATTACH, PRAGMA, extensions. PROTOTYPE RISK: confirm modernc exposes an authorizer; fallback = typed report tools always filter by grant, and free-form `sql_query` only for logins granted all accounts.
- Secrets/tokens live only in control.db => unreachable from any SQL tool.

## Sync consequences
- Rate limiter, token refresh, cursors, coverage: per account. Backfill order per account independent; 6 run in parallel.
- Because each account has its own copy, a catalog change in account A is NOT assumed to appear in B; each is synced from its own API. Drift views surface divergence.
- Identity keys are recomputed on every upsert; override changes trigger a key rebuild job.

## Questions for the user (defaults in brackets)
1. Is one account the master of the catalog/contacts? [No master; canonical = most recently changed; config can pin one]
2. Is stock physically separate per company? [Yes, per account; totals are sums]
3. Is SKU unique per account and the same string in all 6 (incl. variations)? Do all customers/suppliers have CPF/CNPJ? [Assume yes; problems surface in v_*_problems views]

## v2.3.1 — reconciled with Prometeu (overrides conflicting text above)
1. Single DB + single writer: agreed. Bounded queue, short per-page batches, queue-depth/latency metrics; benchmark on real backfill before tuning. Backup = SQLite online backup / `VACUUM INTO` (consistent with WAL), never a raw file copy. NOTE: single DB removes cross-DB ATTACH, not the per-account copies: mirrored rows stay per account by design (faithful replica); "no duplication" applies to the identity layer and reports, not the mirror.
2. FKs: enforced only inside one write unit (pedido_item -> pedido, nota_item -> nota, produto_variacao -> produto, account_id -> account). Not enforced across remote entities (pedido.contato_id etc.); `v_orphans` distinguishes "parent not yet synced" (coverage partial) from "parent deleted" (confirmed by clean pass).
3. Identity: children store the OBSERVED values (`sku_obs`, `doc_obs`, normalized, immutable snapshot of what the transaction carried). Current identity is resolved through a rebuildable projection `identity_map(kind, account_id, remote_id, canonical_key, source auto|override, status ok|ambiguous)` built from produto/contato + `local_identity_override`. Empty/duplicate SKU or missing/non-unique CPF/CNPJ => `status=ambiguous`, NEVER auto-merged, listed in problem views. Parent/override changes enqueue a projection rebuild. Reports declare their mode: `historical` (join on *_obs) or `current` (join via identity_map); default `current`, and the tool echoes which one.
4. sql_query isolation: `modernc.org/sqlite` exposes `AuthorizerRegisterer` (per physical connection). Plan: per-grant read-only connection, authorizer allows reads of base tables only when reached through the grant-filtered views, denies direct schema access, other views, dangerous functions, ATTACH/PRAGMA/writes; no connection or policy reuse across grants; pinned version; test suite for bypasses (aliases, nested views, sqlite_master/metadata, reprepare). Until that suite passes: typed tools always filter by grant; free-form SQL only for a login granted ALL accounts (read-only conn, limits, control.db unreachable).
5. Intercompany: `v_intercompany_candidate` is an indicator only (contact doc_key == another account's cnpj_key). Not proof of a mirrored transaction; no automatic exclusion. Tools expose the classification and an explicit `exclude_intercompany` filter; real elimination requires reconciling counterpart documents (e.g. NF emitted vs received), ambiguous cases flagged.

## v2.3.2 — generic multi-company model (user: primary account, distributor/retail; keep MCP generic)
Finding: the public API v3 spec (221 ops) and docs expose NO multi-company concept: no empresa/filial/matriz fields or endpoints. Each credential = one company account; `GET /info` gives only that company's razaoSocial, cpfCnpj, fantasia, regimeTributario. So Olist's multi-company linkage is invisible to the API and cannot be "integrated with" through it; the MCP must treat accounts as independent API tenants and derive relationships itself. (Unverified: whether shared catalog/contacts propagate server-side in the ERP; the mirror simply records what each account returns.)

Generic design (no business assumptions in code):
- `account.role` is config, not logic: optional `tags` (e.g. `primary`, `distributor`) and a config `group` that lists member accounts. Everything is optional; a single-account install works with no group.
- `group.primary` (optional): account that is the source of truth for given entity kinds, configured as `authority: {produto: <slug>, contato: any}`. Used for (a) canonical attribute selection in views (replaces "most recently changed" when set), (b) write routing hints, (c) health checks.
- Identity keys are configurable per kind: `identity: {produto: sku, contato: cpf_cnpj}` defaults; products without key in a non-authority account are `unkeyed` (visible, flagged, never merged). The user's case (non-primary accounts create SKU-less products) shows up as `v_produto_sku_problems`, and a product in a secondary account with no SKU can be matched to primary by gtin/name only as a *suggestion*, never auto.
- Write guard: tools declare `entity_kind`; if a group has `authority` for that kind and the target account differs, the tool refuses with an explanation naming the authority account (policy `authority_writes: enforce|warn|off`, default warn). Customers: `any` => no restriction.
- Cross-account reads stay "accounts: [..]|all" within the grant; group members are just the default set for `all`.
- Roles (distributor vs retail) are NOT modeled; reports like "stock in the distributor vs stores" use account lists passed by the caller or saved as named `account_set` in config. Intercompany candidates (doc_key == another member's cnpj) already cover distributor->store flows.
Config example:
```
groups:
  - name: acme
    accounts: [dist, loja1, loja2]
    authority: {produto: dist}
    identity: {produto: sku, contato: cpf_cnpj}
    authority_writes: warn
```
