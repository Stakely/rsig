package signer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"rsig/internal/validator"
)

func SignAttestation(req Eth2SigningRequestBody, validator validator.ValidatorKey) (string, error) {
	attRoot, err := hashTreeRootAttestation(req.Attestation)
	if err != nil {
		return "", fmt.Errorf("hash attestation SSZ: %v", err)
	}

	domain, err := computeDomainAttester(*req.ForkInfo, uint64(req.Attestation.Target.Epoch))
	if err != nil {
		return "", fmt.Errorf("compute domain: %v", err)
	}

	var dom32 [32]byte
	copy(dom32[:], domain[:])
	signingRoot, err := hashTreeRootSigningData(&SigningData{
		ObjectRoot: attRoot,
		Domain:     dom32,
	})
	if err != nil {
		return "", fmt.Errorf("hash signing data: %v", err)
	}
	
	if req.SigningRoot != nil {
		fmt.Println("esta aquiiiiiiii")
		if !bytes.Equal(req.SigningRoot[:], signingRoot[:]) {
			return "", fmt.Errorf("provided signing_root != computed signing_root (provided=%s computed=%s)",
				"0x"+hex.EncodeToString(req.SigningRoot[:]),
				"0x"+hex.EncodeToString(signingRoot[:]))
		}
	}

	sigHex, err := validator.Sign(signingRoot[:])
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("bls sign: %v", err))
	}

	return sigHex, nil
}
