package signer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Bytes96 [96]byte
type Bytes32 [32]byte
type Bytes4 [4]byte
type Uint64 uint64
type HexBytes []byte

func (b *Bytes96) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("Bytes96: expected string: %w", err)
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != 192 {
		return fmt.Errorf("Bytes96: expected 192 hex chars, got %d", len(s))
	}
	dst, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("Bytes96: invalid hex: %w", err)
	}
	copy(b[:], dst)
	return nil
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("HexBytes: expected string: %w", err)
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if s == "" {
		*h = []byte{}
		return nil
	}
	if len(s)%2 != 0 {
		return fmt.Errorf("HexBytes: expected even-length hex")
	}
	dst, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("HexBytes: invalid hex: %w", err)
	}
	*h = dst
	return nil
}

func (b *Bytes32) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("Bytes32 must be hex string: %w", err)
	}

	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != 64 {
		return fmt.Errorf("Bytes32: expected 64 hex chars, got %d", len(s))
	}
	dst, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("Bytes32: invalid hex: %w", err)
	}
	copy(b[:], dst)
	return nil
}

func (b *Bytes4) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("Bytes4 must be hex string: %w", err)
	}

	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != 8 {
		return fmt.Errorf("Bytes4: expected 8 hex chars, got %d", len(s))
	}

	dst, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("Bytes4: invalid hex: %w", err)
	}

	copy(b[:], dst)
	return nil
}

func (u *Uint64) UnmarshalJSON(data []byte) error {
	var n float64
	if err := json.Unmarshal(data, &n); err == nil {
		*u = Uint64(uint64(n))
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("Uint64: empty string")
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return fmt.Errorf("Uint64: invalid decimal string: %w", err)
		}
		*u = Uint64(v)
		return nil
	}
	return fmt.Errorf("Uint64: expected number or decimal string")
}

type ArtifactType string

const (
	ArtifactAttestation ArtifactType = "ATTESTATION"
	ArtifactBlockV2     ArtifactType = "BLOCK_V2"
	AggregationSlot     ArtifactType = "AGGREGATION_SLOT"
	AggregateAndProof   ArtifactType = "AGGREGATE_AND_PROOF"
	VoluntaryExit       ArtifactType = "VOLUNTARY_EXIT"
	RandaoReveal        ArtifactType = "RANDAO_REVEAL"
)

type Fork struct {
	PreviousVersion Bytes4 `json:"previous_version"`
	CurrentVersion  Bytes4 `json:"current_version"`
	Epoch           Uint64 `json:"epoch"`
}
type ForkInfo struct {
	Fork                  Fork    `json:"fork"`
	GenesisValidatorsRoot Bytes32 `json:"genesis_validators_root"`
}
type Checkpoint struct {
	Epoch Uint64  `json:"epoch"`
	Root  Bytes32 `json:"root"`
}
type AttestationData struct {
	Slot            Uint64     `json:"slot"`
	Index           Uint64     `json:"index"`
	BeaconBlockRoot Bytes32    `json:"beacon_block_root"`
	Source          Checkpoint `json:"source"`
	Target          Checkpoint `json:"target"`
}

type Attestation struct {
	AggregationBits HexBytes        `json:"aggregation_bits"`
	Data            AttestationData `json:"data"`
	Signature       Bytes96         `json:"signature"`
}
type AggregateAndProofData struct {
	AggregatorIndex Uint64      `json:"aggregator_index"`
	Aggregate       Attestation `json:"aggregate"`
	SelectionProof  Bytes96     `json:"selection_proof"`
}

type BeaconBlockHeader struct {
	Slot          Uint64  `json:"slot"`
	ProposerIndex Uint64  `json:"proposer_index"`
	ParentRoot    Bytes32 `json:"parent_root"`
	StateRoot     Bytes32 `json:"state_root"`
	BodyRoot      Bytes32 `json:"body_root"`
}

type BeaconBlock struct {
	Slot          Uint64  `json:"slot"`
	ProposerIndex Uint64  `json:"proposer_index"`
	ParentRoot    Bytes32 `json:"parent_root"`
	StateRoot     Bytes32 `json:"state_root"`
	BodyRoot      Bytes32 `json:"body_root"`
}

type BlockRequest struct {
	Version     string             `json:"version"`
	Block       *BeaconBlock       `json:"block,omitempty"`
	BlockHeader *BeaconBlockHeader `json:"block_header,omitempty"`
}

type AggregationSlotData struct {
	Slot Uint64 `json:"slot"`
}

type VoluntaryExitData struct {
	Epoch          Uint64 `json:"epoch"`
	ValidatorIndex Uint64 `json:"validator_index"`
}

type RandaoRevealData struct {
	Epoch Uint64 `json:"epoch"`
}

type Eth2SigningRequestBody struct {
	Type              ArtifactType           `json:"type"`
	SigningRoot       *Bytes32               `json:"signingRoot,omitempty"`
	ForkInfo          *ForkInfo              `json:"fork_info"`
	Attestation       *AttestationData       `json:"attestation,omitempty"`
	BlockRequest      *BlockRequest          `json:"beacon_block,omitempty"`
	AggregationSlot   *AggregationSlotData   `json:"aggregation_slot,omitempty"`
	AggregateAndProof *AggregateAndProofData `json:"aggregate_and_proof,omitempty"`
	VoluntaryExit     *VoluntaryExitData     `json:"voluntary_exit,omitempty"`
	RandaoReveal      *RandaoRevealData      `json:"randao_reveal,omitempty"`
}

func (r *Eth2SigningRequestBody) UnmarshalJSON(data []byte) error {
	type Alias Eth2SigningRequestBody

	aux := &struct {
		ForkInfoSnake *ForkInfo `json:"fork_info"`
		ForkInfoCamel *ForkInfo `json:"forkInfo"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.ForkInfoSnake != nil {
		r.ForkInfo = aux.ForkInfoSnake
	} else if aux.ForkInfoCamel != nil {
		r.ForkInfo = aux.ForkInfoCamel
	}

	return nil
}

type SigningData struct {
	ObjectRoot Bytes32
	Domain     [32]byte
}

var domainBeaconAttester = [4]byte{0x01, 0x00, 0x00, 0x00}
var domainBeaconProposer = [4]byte{0x00, 0x00, 0x00, 0x00}
var domainSelectionProof = [4]byte{0x05, 0x00, 0x00, 0x00}
var domainAggregateAndProof = [4]byte{0x06, 0x00, 0x00, 0x00}
var domainVoluntaryExit = [4]byte{0x04, 0x00, 0x00, 0x00}
var domainRandao = [4]byte{0x02, 0x00, 0x00, 0x00}

const slotsPerEpoch = 32
