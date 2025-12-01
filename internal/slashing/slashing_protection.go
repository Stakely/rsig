package slashing

import (
	"context"
	"database/sql"
	"fmt"
)

const (
	validatorPubkeyLen = 48
	signingRootLen     = 32
)

type SlashingProtection struct {
	db *sql.DB
}

func NewSlashingProtection(db *sql.DB) *SlashingProtection {
	return &SlashingProtection{
		db: db,
	}
}

func (s *SlashingProtection) CanSignAttestation(validatorPubkey, signingRoot []byte) (bool, error) {
	if len(validatorPubkey) != validatorPubkeyLen {
		return false, fmt.Errorf("invalid validator pubkey length: got %d, want %d", len(validatorPubkey), validatorPubkeyLen)
	}
	if len(signingRoot) != signingRootLen {
		return false, fmt.Errorf("invalid signing root length: got %d, want %d", len(signingRoot), signingRootLen)
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM signed_attestations
			WHERE validator_pubkey = $1 AND signing_root = $2
		)
	`

	var exists bool
	if err := s.db.QueryRowContext(context.Background(), query, validatorPubkey, signingRoot).Scan(&exists); err != nil {
		return false, fmt.Errorf("query slashing protection attestations: %w", err)
	}

	return !exists, nil
}

func (s *SlashingProtection) CanSignBlock(validatorPubkey, signingRoot []byte) (bool, error) {
	if len(validatorPubkey) != validatorPubkeyLen {
		return false, fmt.Errorf("invalid validator pubkey length: got %d, want %d", len(validatorPubkey), validatorPubkeyLen)
	}
	if len(signingRoot) != signingRootLen {
		return false, fmt.Errorf("invalid signing root length: got %d, want %d", len(signingRoot), signingRootLen)
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM signed_blocks
			WHERE validator_pubkey = $1 AND signing_root = $2
		)
	`

	var exists bool
	if err := s.db.QueryRowContext(context.Background(), query, validatorPubkey, signingRoot).Scan(&exists); err != nil {
		return false, fmt.Errorf("query slashing protection blocks: %w", err)
	}

	return !exists, nil
}

func (s *SlashingProtection) InsertAttestationSignature(validatorPubkey, signingRoot []byte) (bool, error) {
	if len(validatorPubkey) != validatorPubkeyLen {
		return false, fmt.Errorf("invalid validator pubkey length: got %d, want %d", len(validatorPubkey), validatorPubkeyLen)
	}
	if len(signingRoot) != signingRootLen {
		return false, fmt.Errorf("invalid signing root length: got %d, want %d", len(signingRoot), signingRootLen)
	}

	const stmt = `
		INSERT INTO signed_attestations (validator_pubkey, signing_root)
		VALUES ($1, $2)
		ON CONFLICT (validator_pubkey, signing_root) DO NOTHING
	`

	res, err := s.db.ExecContext(context.Background(), stmt, validatorPubkey, signingRoot)
	if err != nil {
		return false, fmt.Errorf("insert signed_attestations: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected (attestations): %w", err)
	}

	return rows == 1, nil
}

func (s *SlashingProtection) InsertBlockSignature(validatorPubkey, signingRoot []byte) (bool, error) {
	if len(validatorPubkey) != validatorPubkeyLen {
		return false, fmt.Errorf("invalid validator pubkey length: got %d, want %d", len(validatorPubkey), validatorPubkeyLen)
	}
	if len(signingRoot) != signingRootLen {
		return false, fmt.Errorf("invalid signing root length: got %d, want %d", len(signingRoot), signingRootLen)
	}

	const stmt = `
		INSERT INTO signed_blocks (validator_pubkey, signing_root)
		VALUES ($1, $2)
		ON CONFLICT (validator_pubkey, signing_root) DO NOTHING
	`

	res, err := s.db.ExecContext(context.Background(), stmt, validatorPubkey, signingRoot)
	if err != nil {
		return false, fmt.Errorf("insert signed_blocks: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected (blocks): %w", err)
	}

	return rows == 1, nil
}
