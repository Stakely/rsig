package validator

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"
)

type ValidatorKey struct {
	PubKeyHex  string
	PrivKey    []byte
	PrivKeyHex string
}

func (v *ValidatorKey) Sign(msg []byte) (string, error) {
	if err := ensureBLSInit(); err != nil {
		return "", err
	}
	if len(v.PrivKey) != 32 {
		return "", fmt.Errorf("invalid private key length: got %d, want 32", len(v.PrivKey))
	}

	le, err := beToLE32(v.PrivKey)
	if err != nil {
		return "", err
	}

	var sk bls.SecretKey
	if err := sk.SetLittleEndian(le); err != nil {
		return "", fmt.Errorf("set little endian: %w", err)
	}

	sig := sk.SignByte(msg)
	if sig == nil {
		return "", errors.New("bls sign failed")
	}
	return "0x" + hex.EncodeToString(sig.Serialize()), nil
}
