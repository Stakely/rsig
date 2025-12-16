package signer

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prysmaticlabs/go-bitfield"
)

func hashTreeRootUint64(u uint64) Bytes32 {
	var out Bytes32
	binary.LittleEndian.PutUint64(out[0:8], u)
	return out
}

func hashTreeRootAttestationForAggregate(a *Attestation, version *string) (Bytes32, error) {
	if a == nil {
		return Bytes32{}, errors.New("nil attestation")
	}

	ver := ""
	if version != nil {
		ver = strings.ToUpper(strings.TrimSpace(*version))
	}
	if ver == "" || (ver != "ELECTRA" && ver != "FULU") {
		return hashTreeRootFullAttestation(a)
	}

	if len(a.CommitteeBits) == 0 {
		return Bytes32{}, errors.New("attestation.committee_bits must be specified for ELECTRA/FULU")
	}

	aggRoot, _, err := hashTreeRootBitlistSSZ([]byte(a.AggregationBits))
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(aggregation_bits): %w", err)
	}

	dataRoot, err := hashTreeRootAttestation(&a.Data)
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(attestation.data): %w", err)
	}

	sigRoot := hashTreeRootBLSSignature(a.Signature)
	committeeBitsRoot := hashTreeRootBytesVector([]byte(a.CommitteeBits))

	return merkleize32([]Bytes32{aggRoot, dataRoot, sigRoot, committeeBitsRoot}), nil
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

func hashTreeRootSyncCommitteeMessage(m *SyncCommitteeMessageData) (Bytes32, error) {
	if m == nil {
		return Bytes32{}, errors.New("nil sync_committee_message")
	}

	slotChunk := hashTreeRootUint64(uint64(m.Slot))
	blockChunk := m.BeaconBlockRoot

	sum := sha256.Sum256(append(slotChunk[:], blockChunk[:]...))

	var out Bytes32
	copy(out[:], sum[:])
	return out, nil
}

func hashTreeRootAggregateAndProofV2(ap *AggregateAndProofData) (Bytes32, error) {
	if ap == nil {
		return Bytes32{}, errors.New("nil aggregate_and_proof")
	}

	aggIndexRoot := hashTreeRootUint64(uint64(ap.AggregatorIndex))

	att := ap.Aggregate
	attRoot, err := hashTreeRootAttestationForAggregateElectra(&att)
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(aggregate): %w", err)
	}

	selRoot := hashTreeRootBLSSignature(ap.SelectionProof)

	return merkleize32([]Bytes32{aggIndexRoot, attRoot, selRoot}), nil
}

func hashTreeRootAttestationForAggregateElectra(a *Attestation) (Bytes32, error) {
	if a == nil {
		return Bytes32{}, errors.New("nil attestation")
	}
	if len(a.CommitteeBits) == 0 {
		return Bytes32{}, errors.New("attestation.committee_bits must be specified for ELECTRA+")
	}

	aggRoot, _, err := hashTreeRootBitlistSSZ([]byte(a.AggregationBits))
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(aggregation_bits): %w", err)
	}

	dataRoot, err := hashTreeRootAttestation(&a.Data)
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(attestation.data): %w", err)
	}

	sigRoot := hashTreeRootBLSSignature(a.Signature)
	committeeBitsRoot := hashTreeRootBytesVector([]byte(a.CommitteeBits))

	return merkleize32([]Bytes32{aggRoot, dataRoot, sigRoot, committeeBitsRoot}), nil
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

func hashTreeRootSyncAggregatorSelectionData(slot, subcommitteeIndex uint64) (Bytes32, error) {
	slotChunk := hashTreeRootUint64(slot)
	indexChunk := hashTreeRootUint64(subcommitteeIndex)

	sum := sha256.Sum256(append(slotChunk[:], indexChunk[:]...))

	var out Bytes32
	copy(out[:], sum[:])
	return out, nil
}

func hashTreeRootContributionAndProof(cp *ContributionAndProofData) (Bytes32, error) {
	if cp == nil {
		return Bytes32{}, errors.New("nil contribution_and_proof")
	}
	if cp.Contribution == nil {
		return Bytes32{}, errors.New("nil contribution in contribution_and_proof")
	}

	contrib := cp.Contribution

	var pContrib altair.SyncCommitteeContribution
	pContrib.Slot = phase0.Slot(uint64(contrib.Slot))

	copy(pContrib.BeaconBlockRoot[:], contrib.BeaconBlockRoot[:])

	pContrib.SubcommitteeIndex = uint64(contrib.SubcommitteeIndex)
	pContrib.AggregationBits = bitfield.Bitvector128([]byte(contrib.AggregationBits))
	copy(pContrib.Signature[:], contrib.Signature[:])

	var pCP altair.ContributionAndProof
	pCP.AggregatorIndex = phase0.ValidatorIndex(uint64(cp.AggregatorIndex))
	pCP.Contribution = &pContrib
	copy(pCP.SelectionProof[:], cp.SelectionProof[:])

	root, err := pCP.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(ContributionAndProof): %w", err)
	}

	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}

func hashTreeRootDepositMessage(d *DepositData) (Bytes32, error) {
	if d == nil {
		return Bytes32{}, errors.New("nil deposit data")
	}

	var pk phase0.BLSPubKey
	if len(d.Pubkey) != len(pk) {
		return Bytes32{}, fmt.Errorf("deposit pubkey length invalid: expected %d, got %d", len(pk), len(d.Pubkey))
	}
	copy(pk[:], d.Pubkey)

	dm := phase0.DepositMessage{
		PublicKey:             pk,
		WithdrawalCredentials: d.WithdrawalCredentials[:],
		Amount:                phase0.Gwei(uint64(d.Amount)),
	}

	root, err := dm.HashTreeRoot()
	if err != nil {
		return Bytes32{}, fmt.Errorf("hash_tree_root(DepositMessage): %w", err)
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

func computeDomainRandao(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainRandao, fi, epoch)
}

func computeDomainSyncCommittee(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainSyncCommittee, fi, epoch)
}

func computeDomainSyncCommitteeSelectionProof(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainSyncCommitteeSelectionProof, fi, epoch)
}

func computeDomainContributionAndProof(fi ForkInfo, epoch uint64) (phase0.Domain, error) {
	return computeDomain(domainContributionAndProof, fi, epoch)
}

func computeDomainApplicationBuilder() (phase0.Domain, error) {
	var fd phase0.ForkData
	copy(fd.CurrentVersion[:], genesisForkVersionApplicationBuilder[:])
	fd.GenesisValidatorsRoot = phase0.Root{}

	fdr, err := fd.HashTreeRoot()
	if err != nil {
		return phase0.Domain{}, fmt.Errorf("hash_tree_root(ForkData): %w", err)
	}

	var d phase0.Domain
	copy(d[:4], domainApplicationBuilder[:])
	copy(d[4:], fdr[0:28])
	return d, nil
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

func computeDomainDeposit(genesisForkVersion Bytes4) (phase0.Domain, error) {
	var fd phase0.ForkData
	copy(fd.CurrentVersion[:], genesisForkVersion[:])
	fd.GenesisValidatorsRoot = phase0.Root{}

	fdr, err := fd.HashTreeRoot()
	if err != nil {
		return phase0.Domain{}, fmt.Errorf("hash_tree_root(ForkData): %w", err)
	}

	var d phase0.Domain
	copy(d[:4], domainDeposit[:])
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

func hashTreeRootBytes20(b Bytes20) Bytes32 {
	var out Bytes32
	copy(out[:], b[:])
	return out
}

func hashTreeRootBytes48(b Bytes48) Bytes32 {
	var chunk1 [32]byte
	var chunk2 [32]byte
	copy(chunk1[:], b[0:32])
	copy(chunk2[:], b[32:48])

	sum := sha256.Sum256(append(chunk1[:], chunk2[:]...))

	var out Bytes32
	copy(out[:], sum[:])
	return out
}

func hashTreeRootValidatorRegistration(vr *ValidatorRegistrationData) (Bytes32, error) {
	if vr == nil {
		return Bytes32{}, errors.New("nil validator_registration")
	}

	feeChunk := hashTreeRootBytes20(vr.FeeRecipient)
	gasChunk := hashTreeRootUint64(uint64(vr.GasLimit))
	timeChunk := hashTreeRootUint64(uint64(vr.Timestamp))
	pkChunk := hashTreeRootBytes48(vr.Pubkey)

	left := sha256.Sum256(append(feeChunk[:], gasChunk[:]...))
	right := sha256.Sum256(append(timeChunk[:], pkChunk[:]...))
	root := sha256.Sum256(append(left[:], right[:]...))

	var out Bytes32
	copy(out[:], root[:])
	return out, nil
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func merkleize32(leaves []Bytes32) Bytes32 {
	if len(leaves) == 0 {
		return Bytes32{}
	}

	n := nextPow2(len(leaves))
	level := make([][32]byte, 0, n)
	for i := 0; i < len(leaves); i++ {
		level = append(level, leaves[i])
	}
	for len(level) < n {
		level = append(level, [32]byte{})
	}

	for len(level) > 1 {
		next := make([][32]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			sum := sha256.Sum256(append(level[i][:], level[i+1][:]...))
			next = append(next, sum)
		}
		level = next
	}

	var out Bytes32
	copy(out[:], level[0][:])
	return out
}

func hashTreeRootBytesVector(b []byte) Bytes32 {
	if len(b) == 0 {
		return Bytes32{}
	}
	chunkCount := (len(b) + 31) / 32
	leaves := make([]Bytes32, 0, chunkCount)

	for i := 0; i < chunkCount; i++ {
		var c Bytes32
		start := i * 32
		end := start + 32
		if end > len(b) {
			end = len(b)
		}
		copy(c[:], b[start:end])
		leaves = append(leaves, c)
	}

	return merkleize32(leaves)
}

func hashTreeRootBitlistSSZ(serialized []byte) (Bytes32, uint64, error) {
	if len(serialized) == 0 {
		serialized = []byte{0x01}
	}

	last := serialized[len(serialized)-1]
	if last == 0 {
		return Bytes32{}, 0, fmt.Errorf("bitlist: invalid SSZ (terminator missing)")
	}

	termPos := -1
	for i := 7; i >= 0; i-- {
		if (last & (1 << uint(i))) != 0 {
			termPos = i
			break
		}
	}
	if termPos < 0 {
		return Bytes32{}, 0, fmt.Errorf("bitlist: invalid terminator")
	}

	bitLen := uint64(len(serialized)-1)*8 + uint64(termPos)
	dataLen := int((bitLen + 7) / 8)

	data := make([]byte, dataLen)
	if dataLen > 0 {
		copy(data, serialized[:dataLen])

		if bitLen%8 != 0 {
			mask := byte(^(1 << uint(termPos)))
			data[dataLen-1] &= mask
		}
	}

	merkle := hashTreeRootBytesVector(data)

	lenChunk := hashTreeRootUint64(bitLen)
	sum := sha256.Sum256(append(merkle[:], lenChunk[:]...))

	var out Bytes32
	copy(out[:], sum[:])
	return out, bitLen, nil
}

func hashTreeRootBLSSignature(sig Bytes96) Bytes32 {
	return hashTreeRootBytesVector(sig[:])
}
