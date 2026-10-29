PRAGMA foreign_keys = ON;

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    cnpj TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Raw records remain separate for each account even when they describe the same entity.
CREATE TABLE records (
    account_id TEXT NOT NULL REFERENCES accounts(id),
    resource TEXT NOT NULL,
    remote_id TEXT NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    observed_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (account_id, resource, remote_id)
);
CREATE INDEX records_by_resource ON records(resource, account_id, remote_id);

CREATE TABLE sync_coverage (
    account_id TEXT NOT NULL REFERENCES accounts(id),
    resource TEXT NOT NULL,
    sync_class TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'partial', 'complete', 'error', 'not_applicable')),
    last_success_at TEXT,
    cursor TEXT,
    PRIMARY KEY (account_id, resource)
);

-- Identity is a projection; ambiguous keys are not automatically merged.
CREATE TABLE identity_candidates (
    account_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    remote_id TEXT NOT NULL,
    identity_kind TEXT NOT NULL,
    identity_value TEXT NOT NULL CHECK (length(identity_value) > 0),
    PRIMARY KEY (account_id, resource, remote_id, identity_kind),
    FOREIGN KEY (account_id, resource, remote_id) REFERENCES records(account_id, resource, remote_id) ON DELETE CASCADE
);
CREATE INDEX identity_lookup ON identity_candidates(resource, identity_kind, identity_value);
