package validator_test

import (
	"path/filepath"
	"strings"
	"testing"

	"rsig/internal/validator"
)

func TestLoadValidatorKeys_WithPassphrase(t *testing.T) {
	keystoreDir := filepath.Join("keystore")
	passwordDir := filepath.Join("password")

	keys, err := validator.LoadValidatorKeys(keystoreDir, passwordDir)
	if err != nil {
		t.Fatalf("LoadValidatorKeys returned error: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected exactly 1 validator key, got %d", len(keys))
	}

	var pub string
	var vk *validator.ValidatorKey
	for p, v := range keys {
		pub = p
		vk = v
		break
	}

	if vk == nil {
		t.Fatalf("validator key for pubkey %s is nil", pub)
	}

	if vk.PubKeyHex == "" {
		t.Errorf("validator key %s has empty PubKeyHex", pub)
	}

	// Expected pubkey
	if vk.PubKeyHex != "85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37" {
		t.Errorf("validator key %s has invalid PubKeyHex", pub)
	}

	if len(vk.PrivKey) == 0 {
		t.Errorf("validator key %s has empty PrivKey", pub)
	}

	if got := len(vk.PrivKey); got != 32 {
		t.Errorf("validator key %s has unexpected PrivKey length: got %d, want 32", pub, got)
	}

	if vk.PrivKeyHex == "" {
		t.Errorf("validator key %s has empty PrivKeyHex", pub)
	}
}

func TestLoadValidatorKeys_WithRawFile(t *testing.T) {
	keystoreDir := filepath.Join("raw_keystore")

	keys, err := validator.LoadValidatorKeys(keystoreDir, "")
	if err != nil {
		t.Fatalf("LoadValidatorKeys returned error: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected exactly 1 validator key, got %d", len(keys))
	}

	var pub string
	var vk *validator.ValidatorKey
	for p, v := range keys {
		pub = p
		vk = v
		break
	}

	if vk.PubKeyHex != "9134b4417b86352ca842039485fc6444b3201f681abf0e9a582418dc82d3d20b3d76d2291c9953150053f153249cf6b1" {
		t.Errorf("validator key %s has invalid PubKeyHex", pub)
	}
}

func TestLoadValidatorKeys_WithWrongPassword(t *testing.T) {
	keystoreDir := filepath.Join("keystore")
	passwordDir := filepath.Join("password_wrong")

	_, err := validator.LoadValidatorKeys(keystoreDir, passwordDir)
	if err == nil {
		t.Fatalf("expected error due to wrong password, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "incorrect password") &&
		!strings.Contains(strings.ToLower(err.Error()), "checksum mismatch") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadValidatorKeys_WithInvalidPath(t *testing.T) {
	keystoreDir := filepath.Join("invalid")
	passwordDir := filepath.Join("invalid_password")

	_, err := validator.LoadValidatorKeys(keystoreDir, passwordDir)
	if err == nil {
		t.Fatalf("expected error due to wrong password, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "no such file or directory") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadValidatorKeys_WithEmptyFolder(t *testing.T) {
	keystoreDir := filepath.Join("empty_keystore")

	keys, err := validator.LoadValidatorKeys(keystoreDir, "")

	if err != nil {
		t.Fatalf("LoadValidatorKeys returned error: %v", err)
	}

	if len(keys) != 0 {
		t.Fatalf("expected empty validator keys, got %d", len(keys))
	}
}
