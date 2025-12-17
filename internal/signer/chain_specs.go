package signer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ChainSpecs struct {
	DomainApplicationMask             Bytes4
	DomainBeaconAttester              Bytes4
	DomainBeaconProposer              Bytes4
	DomainSelectionProof              Bytes4
	DomainAggregateAndProof           Bytes4
	DomainVoluntaryExit               Bytes4
	DomainRandao                      Bytes4
	DomainSyncCommittee               Bytes4
	DomainSyncCommitteeSelectionProof Bytes4
	DomainContributionAndProof        Bytes4
	DomainDeposit                     Bytes4
	SlotsPerEpoch                     uint64
	GenesisForkVersion                Bytes4
	ElectraForkEpoch                  uint64
}

type specFile struct {
	Data map[string]json.RawMessage `json:"data"`
}

func LoadChainSpecs(chain string, customSpecPath string) (ChainSpecs, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	switch chain {
	case "mainnet", "hoodi", "custom":
	case "":
		chain = "mainnet"
	default:
		return ChainSpecs{}, fmt.Errorf("invalid chain %q (allowed: mainnet|hoodi|custom)", chain)
	}

	specPath := strings.TrimSpace(customSpecPath)
	if chain == "custom" {
		if specPath == "" {
			return ChainSpecs{}, fmt.Errorf("custom network requires a spec path")
		}
	} else {
		if specPath == "" {
			root, err := findProjectRoot()
			if err != nil {
				return ChainSpecs{}, err
			}
			name := "spec_config_mainnet.json"
			if chain == "hoodi" {
				name = "spec_config_hoodi.json"
			}
			specPath = filepath.Join(root, name)
		}
	}

	b, err := os.ReadFile(specPath)
	if err != nil {
		return ChainSpecs{}, fmt.Errorf("read spec file %q: %w", specPath, err)
	}

	var sf specFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return ChainSpecs{}, fmt.Errorf("parse spec json %q: %w", specPath, err)
	}

	getString := func(key string) (string, error) {
		raw, ok := sf.Data[key]
		if !ok {
			return "", fmt.Errorf("missing key %q in %s", key, specPath)
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s, nil
		}
		var anyV any
		if err := json.Unmarshal(raw, &anyV); err != nil {
			return "", fmt.Errorf("invalid key %q in %s: %w", key, specPath, err)
		}
		return fmt.Sprint(anyV), nil
	}

	getUint := func(key string) (uint64, error) {
		s, err := getString(key)
		if err != nil {
			return 0, err
		}
		s = strings.TrimSpace(s)
		u, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("key %q: parse uint from %q: %w", key, s, err)
		}
		return u, nil
	}

	getBytes4Hex := func(key string) (Bytes4, error) {
		s, err := getString(key)
		if err != nil {
			return Bytes4{}, err
		}
		return parseHexBytes4(s, key)
	}

	var out ChainSpecs

	if out.DomainApplicationMask, err = getBytes4Hex("DOMAIN_APPLICATION_MASK"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainBeaconAttester, err = getBytes4Hex("DOMAIN_BEACON_ATTESTER"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainBeaconProposer, err = getBytes4Hex("DOMAIN_BEACON_PROPOSER"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainSelectionProof, err = getBytes4Hex("DOMAIN_SELECTION_PROOF"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainAggregateAndProof, err = getBytes4Hex("DOMAIN_AGGREGATE_AND_PROOF"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainVoluntaryExit, err = getBytes4Hex("DOMAIN_VOLUNTARY_EXIT"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainRandao, err = getBytes4Hex("DOMAIN_RANDAO"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainSyncCommittee, err = getBytes4Hex("DOMAIN_SYNC_COMMITTEE"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainSyncCommitteeSelectionProof, err = getBytes4Hex("DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainContributionAndProof, err = getBytes4Hex("DOMAIN_CONTRIBUTION_AND_PROOF"); err != nil {
		return ChainSpecs{}, err
	}
	if out.DomainDeposit, err = getBytes4Hex("DOMAIN_DEPOSIT"); err != nil {
		return ChainSpecs{}, err
	}

	if out.SlotsPerEpoch, err = getUint("SLOTS_PER_EPOCH"); err != nil {
		return ChainSpecs{}, err
	}
	if out.GenesisForkVersion, err = getBytes4Hex("GENESIS_FORK_VERSION"); err != nil {
		return ChainSpecs{}, err
	}
	if out.ElectraForkEpoch, err = getUint("ELECTRA_FORK_EPOCH"); err != nil {
		return ChainSpecs{}, err
	}

	return out, nil
}

func parseHexBytes4(s string, field string) (Bytes4, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "0x")

	if len(s) > 8 {
		return Bytes4{}, fmt.Errorf("%s: expected 4 bytes hex, got %q", field, "0x"+s)
	}
	s = strings.Repeat("0", 8-len(s)) + s

	b, err := hex.DecodeString(s)
	if err != nil {
		return Bytes4{}, fmt.Errorf("%s: decode hex %q: %w", field, "0x"+s, err)
	}
	if len(b) != 4 {
		return Bytes4{}, fmt.Errorf("%s: expected 4 bytes, got %d", field, len(b))
	}
	var out Bytes4
	copy(out[:], b)
	return out, nil
}

func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("project root not found (go.mod not found from cwd upwards)")
		}
		dir = parent
	}
}
