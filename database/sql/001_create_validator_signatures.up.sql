CREATE TABLE IF NOT EXISTS validator_signatures (
    pub_key TEXT NOT NULL,
    signing_root TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (pub_key, signing_root)
);

CREATE INDEX IF NOT EXISTS idx_validators_pub_key
    ON validator_signatures (pub_key);

CREATE INDEX IF NOT EXISTS idx_validators_signing_root
    ON validator_signatures (signing_root);
