package signer

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

func hashTreeRootUint64(u uint64) Bytes32 {
	var out Bytes32
	binary.LittleEndian.PutUint64(out[0:8], u)
	return out
}

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

func hashTreeRootFullAttestation(a *Attestation) (Bytes32, error) {
	if a == nil {
		return Bytes32{}, errors.New("nil aggregate attestation")
	}

	pa := phase0.Attestation{
		AggregationBits: bitfield.Bitlist([]byte(a.AggregationBits)),
		Data: &phase0.AttestationData{
			Slot:            phase0.Slot(uint64(a.Data.Slot)),
			Index:           phase0.CommitteeIndex(uint64(a.Data.Index)),
			BeaconBlockRoot: phase0.Root(a.Data.BeaconBlockRoot),
			Source: &phase0.Checkpoint{
				Epoch: phase0.Epoch(uint64(a.Data.Source.Epoch)),
				Root:  phase0.Root(a.Data.Source.Root),
			},
			Target: &phase0.Checkpoint{
				Epoch: phase0.Epoch(uint64(a.Data.Target.Epoch)),
				Root:  phase0.Root(a.Data.Target.Root),
			},
		},
	}
	copy(pa.Signature[:], a.Signature[:])

	root, err := pa.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(Attestation): %w", err)
	}
	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}

func hashTreeRootAggregateAndProof(ap *AggregateAndProofData) (Bytes32, error) {
	if ap == nil {
		return Bytes32{}, errors.New("nil aggregate_and_proof")
	}

	pap := phase0.AggregateAndProof{
		AggregatorIndex: phase0.ValidatorIndex(uint64(ap.AggregatorIndex)),
	}

	agg := ap.Aggregate
	pAgg := phase0.Attestation{
		AggregationBits: bitfield.Bitlist([]byte(agg.AggregationBits)),
		Data: &phase0.AttestationData{
			Slot:            phase0.Slot(uint64(agg.Data.Slot)),
			Index:           phase0.CommitteeIndex(uint64(agg.Data.Index)),
			BeaconBlockRoot: phase0.Root(agg.Data.BeaconBlockRoot),
			Source: &phase0.Checkpoint{
				Epoch: phase0.Epoch(uint64(agg.Data.Source.Epoch)),
				Root:  phase0.Root(agg.Data.Source.Root),
			},
			Target: &phase0.Checkpoint{
				Epoch: phase0.Epoch(uint64(agg.Data.Target.Epoch)),
				Root:  phase0.Root(agg.Data.Target.Root),
			},
		},
	}
	copy(pAgg.Signature[:], agg.Signature[:])
	pap.Aggregate = &pAgg

	copy(pap.SelectionProof[:], ap.SelectionProof[:])

	root, err := pap.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(AggregateAndProof): %w", err)
	}
	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}

func hashTreeRootVoluntaryExit(ve *VoluntaryExitData) (Bytes32, error) {
	if ve == nil {
		return Bytes32{}, errors.New("nil voluntary_exit")
	}

	pve := phase0.VoluntaryExit{
		Epoch:          phase0.Epoch(uint64(ve.Epoch)),
		ValidatorIndex: phase0.ValidatorIndex(uint64(ve.ValidatorIndex)),
	}

	root, err := pve.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(VoluntaryExit): %w", err)
	}

	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}

func computeDomainAttester(fi ForkInfo, targetEpoch uint64) (phase0.Domain, error) {
	return computeDomain(domainBeaconAttester, fi, targetEpoch)
}

func computeDomainProposer(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainBeaconProposer, fi, epoch)
}

func computeDomainAggregationSlot(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainSelectionProof, fi, epoch)
}

func computeDomainAggregateAndProof(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainAggregateAndProof, fi, epoch)
}
func computeDomainVoluntaryExit(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainVoluntaryExit, fi, epoch)
}

func computeDomain(domainType [4]byte, fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	var forkVersion Bytes4
	if epoch < uint64(fi.Fork.Epoch) {
		forkVersion = fi.Fork.PreviousVersion
	} else {
		forkVersion = fi.Fork.CurrentVersion
	}

	var fd phase0.ForkData
	copy(fd.CurrentVersion[:], forkVersion[:])
	copy(fd.GenesisValidatorsRoot[:], fi.GenesisValidatorsRoot[:])

	fdr, err := fd.HashTreeRoot()
	if err != nil {
		return phase0.Domain{}, fmt.Errorf("hash_tree_root(ForkData): %w", err)
	}

	var d phase0.Domain
	copy(d[:4], domainType[:])
	copy(d[4:], fdr[0:28])
	return d, nil
}

func computeSigningRoot(objectRoot Bytes32, domain phase0.Domain) (Bytes32, error) {
	sd := phase0.SigningData{
		ObjectRoot: phase0.Root(objectRoot),
		Domain:     domain,
	}
	root, err := sd.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(SigningData): %w", err)
	}
	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}

func hashTreeRootBlockHeader(h *BeaconBlockHeader) (Bytes32, error) {
	if h == nil {
		return Bytes32{}, errors.New("nil block_header")
	}
	ph := phase0.BeaconBlockHeader{
		Slot:          phase0.Slot(uint64(h.Slot)),
		ProposerIndex: phase0.ValidatorIndex(uint64(h.ProposerIndex)),
	}

	copy(ph.ParentRoot[:], h.ParentRoot[:])
	copy(ph.StateRoot[:], h.StateRoot[:])
	copy(ph.BodyRoot[:], h.BodyRoot[:])

	root, err := ph.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(BeaconBlockHeader): %w", err)
	}

	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}
