CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS contract_capabilities (
    chain_id INTEGER,
    address VARCHAR,
    contract_name VARCHAR,
    selector VARCHAR,
    operation VARCHAR,
    guard_type VARCHAR,
    guard_detail VARCHAR,
    effects_json VARCHAR,
    confidence VARCHAR,
    pc_range VARCHAR,
    merkle_leaf_hash VARCHAR,
    indexed_at_utc VARCHAR,
    PRIMARY KEY (chain_id, address, selector, operation)
);

CREATE TABLE IF NOT EXISTS proxy_lineage (
    chain_id INTEGER,
    address VARCHAR,
    proxy_standard VARCHAR,
    implementation_address VARCHAR,
    admin_address VARCHAR,
    content_hash VARCHAR,
    last_checked_utc VARCHAR,
    PRIMARY KEY (chain_id, address)
);

CREATE TABLE IF NOT EXISTS capability_roots (
    commit_id BIGINT PRIMARY KEY,
    chain_id INTEGER,
    address VARCHAR,
    merkle_root VARCHAR,
    capabilities_count INTEGER,
    timestamp_utc VARCHAR
);

CREATE TABLE IF NOT EXISTS ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    chain_id INTEGER,
    address VARCHAR,
    detail VARCHAR
);
