package signer

import (
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func hashTreeRootAttestation(a *AttestationData) (Bytes32, error) {
	if a == nil {
		return Bytes32{}, errors.New("nil attestation")
	}
	pa := phase0.AttestationData{
		Slot:            phase0.Slot(uint64(a.Slot)),
		Index:           phase0.CommitteeIndex(uint64(a.Index)),
		BeaconBlockRoot: phase0.Root(a.BeaconBlockRoot),
		Source: &phase0.Checkpoint{
			Epoch: phase0.Epoch(uint64(a.Source.Epoch)),
			Root:  phase0.Root(a.Source.Root),
		},
		Target: &phase0.Checkpoint{
			Epoch: phase0.Epoch(uint64(a.Target.Epoch)),
			Root:  phase0.Root(a.Target.Root),
		},
	}
	root, err := pa.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(AttestationData): %w", err)
	}
	return Bytes32(root), nil
}

func hashTreeRootSigningData(sd *SigningData) (Bytes32, error) {
	psd := phase0.SigningData{
		ObjectRoot: phase0.Root(sd.ObjectRoot),
		Domain:     phase0.Domain(sd.Domain),
	}
	root, err := psd.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(SigningData): %w", err)
	}
	return Bytes32(root), nil
}

func computeDomainAttester(fi ForkInfo, targetEpoch uint64) (phase0.Domain, error) {
	forkVersion := fi.Fork.CurrentVersion
	if targetEpoch < uint64(fi.Fork.Epoch) {
		forkVersion = fi.Fork.PreviousVersion
	}

	var fd phase0.ForkData
	copy(fd.CurrentVersion[:], forkVersion[:])
	copy(fd.GenesisValidatorsRoot[:], fi.GenesisValidatorsRoot[:])

	fdr, err := fd.HashTreeRoot()
	if err != nil {
		return phase0.Domain{}, fmt.Errorf("hash_tree_root(ForkData): %w", err)
	}
	var domain phase0.Domain
	copy(domain[:4], domainBeaconAttester[:])
	copy(domain[4:], fdr[0:28])
	return domain, nil
}
