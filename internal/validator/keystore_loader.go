package validator

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type KeystoreJSON struct {
	Crypto struct {
		KDF struct {
			Function string                 `json:"function"`
			Params   map[string]interface{} `json:"params"`
			Message  string                 `json:"message"`
		} `json:"kdf"`
		Checksum struct {
			Function string                 `json:"function"`
			Params   map[string]interface{} `json:"params"`
			Message  string                 `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string                 `json:"function"`
			Params   map[string]interface{} `json:"params"`
			Message  string                 `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
}

type KeyConfig struct {
	Type                 string `yaml:"type" json:"type"`
	KeyType              string `yaml:"keyType" json:"keyType"`
	PrivateKey           string `yaml:"privateKey" json:"privateKey"`
	KeystoreFile         string `yaml:"keystoreFile" json:"keystoreFile"`
	KeystorePasswordFile string `yaml:"keystorePasswordFile" json:"keystorePasswordFile"`
}

func LoadValidatorKeys(keystoresDir, passwordsDir string) (map[string]*ValidatorKey, error) {
	results := make(map[string]*ValidatorKey)

	err := filepath.WalkDir(keystoresDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		name := d.Name()

		rawBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		var cfg KeyConfig
		if err := yaml.Unmarshal(rawBytes, &cfg); err != nil {
			return fmt.Errorf("parsing %s as yaml/json: %w", path, err)
		}

		if cfg.Type != "" {
			switch strings.ToLower(cfg.Type) {

			case "file-raw":
				if strings.ToUpper(cfg.KeyType) != "BLS" {
					return fmt.Errorf("unsupported keyType %q in %s (only BLS supported)", cfg.KeyType, path)
				}

				vKey, err := loadRawFileValidatorKey(cfg)
				if err != nil {
					return fmt.Errorf("loading file-raw key from %s: %w", path, err)
				}
				results[vKey.PubKeyHex] = vKey
				return nil

			case "file-keystore":
				if strings.ToUpper(cfg.KeyType) != "BLS" {
					return fmt.Errorf("unsupported keyType %q in %s (only BLS supported)", cfg.KeyType, path)
				}

				vKey, err := loadFileKeystoreValidatorKey(cfg)
				if err != nil {
					return fmt.Errorf("loading file-keystore key from %s: %w", path, err)
				}
				results[vKey.PubKeyHex] = vKey
				return nil

			default:
				return fmt.Errorf("unsupported keystore type %q in %s", cfg.Type, path)
			}
		}

		if !strings.HasSuffix(name, ".json") {
			return nil
		}

		vKey, err := loadEncryptedValidatorKey(path, rawBytes, passwordsDir)
		if err != nil {
			return err
		}
		results[vKey.PubKeyHex] = vKey
		return nil
	})

	if err != nil {
		return nil, err
	}
	return results, nil
}

func loadRawFileValidatorKey(cfg KeyConfig) (*ValidatorKey, error) {
	privHex := strings.TrimSpace(cfg.PrivateKey)
	privHex = strings.TrimPrefix(privHex, "0x")

	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("invalid privateKey hex: %w", err)
	}

	if len(privBytes) != 32 {
		return nil, fmt.Errorf("unexpected private key length %d (want 32 bytes)", len(privBytes))
	}

	pubBytes, err := blsPubkeyFromPriv(privBytes)
	if err != nil {
		return nil, fmt.Errorf("bls pubkey derivation failed: %w", err)
	}

	v := &ValidatorKey{
		PubKeyHex:  strings.ToLower(hex.EncodeToString(pubBytes)),
		PrivKey:    privBytes,
		PrivKeyHex: strings.ToLower(hex.EncodeToString(privBytes)),
	}

	return v, nil
}

func loadFileKeystoreValidatorKey(cfg KeyConfig) (*ValidatorKey, error) {
	if cfg.KeystoreFile == "" {
		return nil, fmt.Errorf("keystoreFile is empty in file-keystore config")
	}
	if cfg.KeystorePasswordFile == "" {
		return nil, fmt.Errorf("keystorePasswordFile is empty in file-keystore config")
	}

	ksBytes, err := os.ReadFile(cfg.KeystoreFile)
	if err != nil {
		return nil, fmt.Errorf("error reading keystoreFile %s: %w", cfg.KeystoreFile, err)
	}

	passBytes, err := os.ReadFile(cfg.KeystorePasswordFile)
	if err != nil {
		return nil, fmt.Errorf("error reading keystorePasswordFile %s: %w", cfg.KeystorePasswordFile, err)
	}
	password := strings.TrimSpace(string(passBytes))

	return decryptKeystoreBytes(ksBytes, password, cfg.KeystoreFile)
}

func loadEncryptedValidatorKey(path string, ksBytes []byte, passwordsDir string) (*ValidatorKey, error) {
	baseName := filepath.Base(path)
	passFile := strings.TrimSuffix(baseName, ".json") + ".txt"
	passPath := filepath.Join(passwordsDir, passFile)

	passBytes, err := os.ReadFile(passPath)
	if err != nil {
		return nil, fmt.Errorf("error reading keystore password %s: %w", passPath, err)
	}
	password := strings.TrimSpace(string(passBytes))

	return decryptKeystoreBytes(ksBytes, password, path)
}
