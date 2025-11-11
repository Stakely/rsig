package validator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/herumi/bls-eth-go-binary/bls"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var (
	blsInitOnce sync.Once
	blsInitErr  error
)

func ensureBLSInit() error {
	blsInitOnce.Do(func() {
		if err := bls.Init(bls.BLS12_381); err != nil {
			blsInitErr = fmt.Errorf("bls.Init: %w", err)
			return
		}

		bls.SetETHmode(bls.EthModeDraft07)
	})
	return blsInitErr
}

func decryptKeystoreBytes(ksBytes []byte, password string, origin string) (*ValidatorKey, error) {
	var ks KeystoreJSON
	if err := json.Unmarshal(ksBytes, &ks); err != nil {
		return nil, fmt.Errorf("error parsing keystore file %s: %w", origin, err)
	}

	derivedKey, err := deriveKey(ks, password)
	if err != nil {
		return nil, fmt.Errorf("key derivation of %s: %w", origin, err)
	}

	if err := verifyPassword(ks, derivedKey); err != nil {
		return nil, fmt.Errorf("incorrect password for %s: %w", origin, err)
	}

	privKeyBytes, err := decryptSecret(ks, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("private key error %s: %w", origin, err)
	}

	pubBytes, err := blsPubkeyFromPriv(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("bls pubkey derivation failed for %s: %w", origin, err)
	}

	pubKeyHex := strings.ToLower(hex.EncodeToString(pubBytes))

	v := &ValidatorKey{
		PubKeyHex:  pubKeyHex,
		PrivKey:    privKeyBytes,
		PrivKeyHex: strings.ToLower(hex.EncodeToString(privKeyBytes)),
	}

	return v, nil
}

func blsPubkeyFromPriv(privBytes []byte) ([]byte, error) {
	if err := ensureBLSInit(); err != nil {
		return nil, err
	}

	var sk bls.SecretKey
	hexPriv := hex.EncodeToString(privBytes)
	if err := sk.SetHexString(hexPriv); err != nil {
		return nil, fmt.Errorf("SetHexString: %w", err)
	}

	pk := sk.GetPublicKey()
	return pk.Serialize(), nil
}

func deriveKey(ks KeystoreJSON, password string) ([]byte, error) {
	kdf := ks.Crypto.KDF
	switch kdf.Function {
	case "scrypt":
		N := int(getFloatParam(kdf.Params, "n"))
		r := int(getFloatParam(kdf.Params, "r"))
		p := int(getFloatParam(kdf.Params, "p"))
		dklen := int(getFloatParam(kdf.Params, "dklen"))

		saltHex := getStringParam(kdf.Params, "salt")
		salt, err := hex.DecodeString(saltHex)
		if err != nil {
			return nil, fmt.Errorf("invalid salt: %w", err)
		}

		return scrypt.Key([]byte(password), salt, N, r, p, dklen)

	case "pbkdf2":
		c := int(getFloatParam(kdf.Params, "c"))
		dklen := int(getFloatParam(kdf.Params, "dklen"))
		prf := getStringParam(kdf.Params, "prf")
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("unsupported prf: %s", prf)
		}
		saltHex := getStringParam(kdf.Params, "salt")
		salt, err := hex.DecodeString(saltHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hex salt: %w", err)
		}

		return pbkdf2.Key([]byte(password), salt, c, dklen, sha256.New), nil

	default:
		return nil, fmt.Errorf("kdf.function %q unsupported", kdf.Function)
	}
}

func verifyPassword(ks KeystoreJSON, derivedKey []byte) error {
	if len(derivedKey) < 32 {
		return errors.New("invalid derived key")
	}
	cipherHex := ks.Crypto.Cipher.Message
	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return fmt.Errorf("cipher.message invalid hex: %w", err)
	}

	preImage := append(derivedKey[16:32], cipherBytes...)
	sum := sha256.Sum256(preImage)
	expectedHex := ks.Crypto.Checksum.Message
	expectedBytes, err := hex.DecodeString(expectedHex)
	if err != nil {
		return fmt.Errorf("checksum.message invalid hex: %w", err)
	}

	if !bytesEqual(sum[:], expectedBytes) {
		return errors.New("checksum mismatch: incorrect password")
	}
	return nil
}

func decryptSecret(ks KeystoreJSON, derivedKey []byte) ([]byte, error) {
	cipherHex := ks.Crypto.Cipher.Message
	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return nil, fmt.Errorf("cipher.message invalid hex: %w", err)
	}

	ivHex := getStringParam(ks.Crypto.Cipher.Params, "iv")
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("invalid iv hex: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv size: %d, expected: %d", len(iv), aes.BlockSize)
	}

	if len(derivedKey) < 16 {
		return nil, errors.New("derivedKey too short for AES-128")
	}
	block, err := aes.NewCipher(derivedKey[:16])
	if err != nil {
		return nil, fmt.Errorf("creating cipher AES: %w", err)
	}

	stream := cipher.NewCTR(block, iv)
	plain := make([]byte, len(cipherBytes))
	stream.XORKeyStream(plain, cipherBytes)

	if len(plain) != 32 {
		return nil, fmt.Errorf("unexpected key size: %d", len(plain))
	}

	return plain, nil
}

func getFloatParam(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	f, _ := v.(float64)
	return f
}

func getStringParam(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func beToLE32(in []byte) ([]byte, error) {
	if len(in) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(in))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = in[31-i]
	}
	return out, nil
}
