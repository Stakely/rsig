CREATE TABLE signed_attestations (
    id BIGSERIAL PRIMARY KEY,
    validator_pubkey BYTEA NOT NULL,
    signing_root     BYTEA NOT NULL,
    CONSTRAINT signed_attestations_validator_pubkey_len
        CHECK (octet_length(validator_pubkey) = 48),

    CONSTRAINT signed_attestations_signing_root_len
        CHECK (octet_length(signing_root) = 32),

    CONSTRAINT signed_attestations_validator_signing_root_uniq
        UNIQUE (validator_pubkey, signing_root)
);

CREATE INDEX signed_attestations_signing_root_idx
    ON signed_attestations (signing_root);

CREATE INDEX signed_attestations_validator_pubkey_idx
    ON signed_attestations (validator_pubkey);

CREATE TABLE signed_blocks (
    id BIGSERIAL PRIMARY KEY,
    validator_pubkey BYTEA NOT NULL,
    signing_root     BYTEA NOT NULL,
    CONSTRAINT signed_blocks_validator_pubkey_len
        CHECK (octet_length(validator_pubkey) = 48),
    CONSTRAINT signed_blocks_signing_root_len
        CHECK (octet_length(signing_root) = 32),
    CONSTRAINT signed_blocks_validator_signing_root_uniq
        UNIQUE (validator_pubkey, signing_root)
);

CREATE INDEX signed_blocks_signing_root_idx
    ON signed_blocks (signing_root);

CREATE INDEX signed_blocks_validator_pubkey_idx
    ON signed_blocks (validator_pubkey);
