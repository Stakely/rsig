package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"rsig/internal/slashing"
	"rsig/internal/validator"
	"strconv"
)

func SignAttestation(req Eth2SigningRequestBody, v validator.ValidatorKey, sp *slashing.SlashingProtection) (string, error) {
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

	pubKey, err := v.PubkeyBytes()
	if err != nil {
		return "", fmt.Errorf("invalid validator pub key: %w", err)
	}

	canSign, err := sp.CanSignAttestation(pubKey, signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("slashing protection attestation: %w", err)
	}
	if !canSign {
		return "", fmt.Errorf("slashing protection: attestation already signed for this (validator_pubkey, signing_root)")
	}

	sigHex, err := v.Sign(signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("bls sign: %w", err)
	}

	inserted, err := sp.InsertAttestationSignature(pubKey, signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("slashing protection insert attestation: %w", err)
	}
	if !inserted {
		return "", fmt.Errorf("slashing protection: attestation already signed for this (validator_pubkey, signing_root)")
	}

	return sigHex, nil
}

func SignBlock(req Eth2SigningRequestBody, v validator.ValidatorKey, sp *slashing.SlashingProtection) (string, error) {
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

	pubKey, err := v.PubkeyBytes()
	if err != nil {
		return "", fmt.Errorf("invalid validator pub key: %w", err)
	}

	canSign, err := sp.CanSignBlock(pubKey, signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("slashing protection block: %w", err)
	}
	if !canSign {
		return "", fmt.Errorf("slashing protection: block already signed for this (validator_pubkey, signing_root)")
	}

	sigHex, err := v.Sign(signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("bls sign: %w", err)
	}

	inserted, err := sp.InsertBlockSignature(pubKey, signingRoot[:])
	if err != nil {
		return "", fmt.Errorf("slashing protection insert block: %w", err)
	}
	if !inserted {
		return "", fmt.Errorf("slashing protection: block already signed for this (validator_pubkey, signing_root)")
	}

	return sigHex, nil
}

func SignAggregationSlot(req Eth2SigningRequestBody, v validator.ValidatorKey) (string, error) {
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}
	if req.AggregationSlot == nil {
		return "", errors.New("aggregation_slot must be specified")
	}

	slot := uint64(req.AggregationSlot.Slot)
	epoch := slot / slotsPerEpoch

	objectRoot := hashTreeRootUint64(slot)

	domain, err := computeDomainAggregationSlot(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute aggregation slot domain: %w", err)
	}

	signingRoot, err := computeSigningRoot(objectRoot, domain)
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

func SignAggregateAndProof(req Eth2SigningRequestBody, v validator.ValidatorKey) (string, error) {
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}
	if req.AggregateAndProof == nil {
		return "", errors.New("aggregate_and_proof must be specified")
	}

	ap := req.AggregateAndProof
	epoch := uint64(ap.Aggregate.Data.Target.Epoch)

	objRoot, err := hashTreeRootAggregateAndProof(ap)
	if err != nil {
		return "", fmt.Errorf("hash aggregate_and_proof SSZ: %w", err)
	}

	domain, err := computeDomainAggregateAndProof(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute aggregate_and_proof domain: %w", err)
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

func SignVoluntaryExit(req Eth2SigningRequestBody, v validator.ValidatorKey) (string, error) {
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}
	if req.VoluntaryExit == nil {
		return "", errors.New("voluntary_exit must be specified")
	}

	epoch := uint64(req.VoluntaryExit.Epoch)

	objRoot, err := hashTreeRootVoluntaryExit(req.VoluntaryExit)
	if err != nil {
		return "", fmt.Errorf("hash voluntary_exit SSZ: %w", err)
	}

	domain, err := computeDomainVoluntaryExit(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute voluntary_exit domain: %w", err)
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

func SignRandaoReveal(req Eth2SigningRequestBody, v validator.ValidatorKey) (string, error) {
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}
	if req.RandaoReveal == nil {
		return "", errors.New("randao_reveal must be specified")
	}

	epoch := uint64(req.RandaoReveal.Epoch)
	objectRoot := hashTreeRootUint64(epoch)

	domain, err := computeDomainRandao(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute randao domain: %w", err)
	}

	signingRoot, err := computeSigningRoot(objectRoot, domain)
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

func SignSyncCommitteeMessage(
	req Eth2SigningRequestBody,
	v validator.ValidatorKey,
) (string, error) {
	if req.SyncCommitteeMessage == nil {
		return "", errors.New("sync_committee_message must be specified")
	}
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}

	objRoot := req.SyncCommitteeMessage.BeaconBlockRoot
	slot := uint64(req.SyncCommitteeMessage.Slot)
	epoch := slot / slotsPerEpoch

	domain, err := computeDomainSyncCommittee(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute sync committee domain: %w", err)
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

func SignSyncCommitteeSelectionProof(
	req Eth2SigningRequestBody,
	v validator.ValidatorKey,
) (string, error) {
	if req.SyncAggregatorSelectionData == nil {
		return "", errors.New("sync_aggregator_selection_data must be specified")
	}
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}

	sel := req.SyncAggregatorSelectionData

	if sel.Slot == "" {
		return "", errors.New("sync_aggregator_selection_data.slot must be specified")
	}
	if sel.SubcommitteeIndex == "" {
		return "", errors.New("sync_aggregator_selection_data.subcommittee_index must be specified")
	}

	slot, err := strconv.ParseUint(sel.Slot, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid slot %q: %w", sel.Slot, err)
	}

	subIndex, err := strconv.ParseUint(sel.SubcommitteeIndex, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid subcommittee_index %q: %w", sel.SubcommitteeIndex, err)
	}

	objRoot, err := hashTreeRootSyncAggregatorSelectionData(slot, subIndex)
	if err != nil {
		return "", fmt.Errorf("hash sync_aggregator_selection_data: %w", err)
	}

	epoch := slot / slotsPerEpoch

	domain, err := computeDomainSyncCommitteeSelectionProof(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute sync committee selection proof domain: %w", err)
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

func SignSyncCommitteeContributionAndProof(
	req Eth2SigningRequestBody,
	v validator.ValidatorKey,
) (string, error) {
	if req.ForkInfo == nil {
		return "", errors.New("fork_info must be specified")
	}
	if req.ContributionAndProof == nil {
		return "", errors.New("contribution_and_proof must be specified")
	}
	if req.ContributionAndProof.Contribution == nil {
		return "", errors.New("contribution_and_proof.contribution must be specified")
	}

	cp := req.ContributionAndProof
	contrib := cp.Contribution

	slot := uint64(contrib.Slot)
	epoch := slot / slotsPerEpoch

	objRoot, err := hashTreeRootContributionAndProof(cp)
	if err != nil {
		return "", fmt.Errorf("hash contribution_and_proof SSZ: %w", err)
	}

	domain, err := computeDomainContributionAndProof(*req.ForkInfo, epoch)
	if err != nil {
		return "", fmt.Errorf("compute contribution_and_proof domain: %w", err)
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

func SignDeposit(
	req Eth2SigningRequestBody,
	v validator.ValidatorKey,
) (string, error) {
	if req.Deposit == nil {
		return "", errors.New("deposit must be specified")
	}

	d := req.Deposit

	objRoot, err := hashTreeRootDepositMessage(d)
	if err != nil {
		return "", fmt.Errorf("hash deposit message SSZ: %w", err)
	}

	domain, err := computeDomainDeposit(d.GenesisForkVersion)
	if err != nil {
		return "", fmt.Errorf("compute deposit domain: %w", err)
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

func SignValidatorRegistration(
	req Eth2SigningRequestBody,
	v validator.ValidatorKey,
) (string, error) {
	if req.ValidatorRegistration == nil {
		return "", errors.New("validator_registration must be specified")
	}

	objRoot, err := hashTreeRootValidatorRegistration(req.ValidatorRegistration)
	if err != nil {
		return "", fmt.Errorf("hash validator_registration SSZ: %w", err)
	}

	domain, err := computeDomainApplicationBuilder()
	if err != nil {
		return "", fmt.Errorf("compute validator_registration domain: %w", err)
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
