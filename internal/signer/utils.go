package signer

import (
	"errors"
	"fmt"
	"strings"
)

func getBlockSlot(req Eth2SigningRequestBody) (uint64, error) {
	switch req.Type {
	case ArtifactBlockV2:
		if req.BlockRequest == nil {
			return 0, errors.New("beacon_block must be specified for type BLOCK_V2")
		}
		br := req.BlockRequest
		version := strings.ToLower(br.Version)

		switch version {
		case "phase0", "altair":
			if br.Block == nil {
				return 0, errors.New("block must be specified for BLOCK_V2 PHASE0/ALTAIR")
			}
			return uint64(br.Block.Slot), nil
		default: // bellatrix, capella, deneb, ...
			if br.BlockHeader == nil {
				return 0, errors.New("block_header must be specified for BLOCK_V2 BELLATRIX+")
			}
			return uint64(br.BlockHeader.Slot), nil
		}
	default:
		return 0, fmt.Errorf("unsupported type for getBlockSlot: %s", req.Type)
	}
}

func hashBlockObject(req Eth2SigningRequestBody) (Bytes32, error) {
	switch req.Type {
	case ArtifactBlockV2:
		if req.BlockRequest == nil {
			return Bytes32{}, errors.New("beacon_block must be specified for BLOCK_V2")
		}
		br := req.BlockRequest
		version := strings.ToLower(br.Version)

		switch version {
		case "phase0", "altair":
		default:
			return hashTreeRootBlockHeader(br.BlockHeader)
		}
	default:
		return Bytes32{}, fmt.Errorf("unsupported type for hashBlockObject: %s", req.Type)
	}

	return Bytes32{}, fmt.Errorf("unsupported type for hashBlockObject: %s", req.Type)
}
