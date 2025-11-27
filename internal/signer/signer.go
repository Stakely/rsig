package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"rsig/internal/validator"
)

func SignAttestation(req Eth2SigningRequestBody, v validator.ValidatorKey) (string, error) {
	if req.Attestation == nil {
		return "", errors.New("attestation must be specified")
	}
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}

	attRoot, err := hashTreeRootAttestation(req.Attestation)
	if err != nil {
		return "", fmt.Errorf("hash attestation SSZ: %w", err)
	}

	epoch := uint64(req.Attestation.Target.Epoch)
	domain, err := computeDomainAttester(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute attester domain: %w", err)
	}

	signingRoot, err := computeSigningRoot(attRoot, domain)
	if err != nil {
		return "", fmt.Errorf("compute signing root: %w", err)
	}

	if req.SigningRoot != nil {
		if !bytes.Equal(req.SigningRoot[:], signingRoot[:]) {
			return "", fmt.Errorf(
				"provided signing_root != computed signing_root (provided=%s computed=%s)",
				"0x"+hex.EncodeToString(req.SigningRoot[:]),
				"0x"+hex.EncodeToString(signingRoot[:]),
			)
		}
	}

	sigHex, err := v.Sign(signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("bls sign: %w", err)
	}

	return sigHex, nil
}

func SignBlock(req Eth2SigningRequestBody, v validator.ValidatorKey) (string, error) {
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}

	objRoot, err := hashBlockObject(req)
	if err != nil {
		return "", fmt.Errorf("hash block SSZ: %w", err)
	}

	slot, err := getBlockSlot(req)
	if err != nil {
		return "", fmt.Errorf("get block slot: %w", err)
	}
	epoch := slot / slotsPerEpoch

	domain, err := computeDomainProposer(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute proposer domain: %w", err)
	}

	signingRoot, err := computeSigningRoot(objRoot, domain)
	if err != nil {
		return "", fmt.Errorf("compute signing root: %w", err)
	}

	if req.SigningRoot != nil {
		if !bytes.Equal(req.SigningRoot[:], signingRoot[:]) {
			return "", fmt.Errorf(
				"provided signing_root != computed signing_root (provided=%s computed=%s)",
				"0x"+hex.EncodeToString(req.SigningRoot[:]),
				"0x"+hex.EncodeToString(signingRoot[:]),
			)
		}
	}

	sigHex, err := v.Sign(signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("bls sign: %w", err)
	}

	return sigHex, nil
}
