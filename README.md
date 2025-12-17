# KUIPER SIGNER
Monorepo for the RSIG application. This repository follows a **ports-and-adapters** (hexagonal) layout:

- `cmd/`: CLI entry points (adapters).
- `server/`: HTTP API adapter (routing, controllers).
- `internal/`: domain & use cases (business logic).
- `database/`: migrations and DB runner code.
- `config_example.*`: example configuration file with sane defaults.

## Configuration

By **default**, the app loads configuration from the example file in the repo root  
(see **`config_example.*`** — e.g., `config_example.yaml` or `config_example.json`).  
Any value can be **overridden via environment variables**.

### Load order & precedence

1. **Built-in defaults** (if any)
2. **`config_example.*`** (file-based config)
3. **Environment variables** (highest precedence)

If a key is present in multiple sources, the **last one wins** (env vars override file values).

### File format

Use YAML format:

```yaml
# config_example.yaml
validators:
  keystore_path: #VALIDATORS_KEYSTORE_PATH
  keystore_password_path: #VALIDATORS_KEYSTORE_PASSWORD_PATH
http:
  port: #HTTP_PORT
  api_prefix: #HTTP_API_PREFIX
database:
  dsn: #DATABASE_DSN
```

### Configuration precedence
This project can be configured using CLI flags, environment variables, and a config file. When the same setting is provided in multiple places, the value is chosen using the following precedence order (from highest to lowest):

`FLAGS > ENV > CONFIG FILE > DEFAULTS`

That means:
- Flags always win (useful for one-off runs and overrides).
- If no flag is provided, the app falls back to environment variables (recommended for Docker/CI/Kubernetes and secrets).
- If no env var is provided, it uses the value from the config file (useful for local and persistent configuration).
- If none of the above are provided, defaults are used.

**Example**: if `database.dsn` is set in `config.yaml` but `DATABASE_DSN` is also set in the environment, the app will use `DATABASE_DSN` unless you override it with a `--dsn` flag.
## Keystore support

All keys are loaded by scanning every file found under a given `keystore_path`.
Each file is inspected to determine what type of key definition it contains, and the key is imported accordingly.

There are three supported formats:

- Encrypted keystore JSONs (EIP-2335) + matching password files
- Raw private key YAML (`file-raw`)
- Encrypted keystore reference YAML (`file-keystore`)

### 1. Encrypted validator keystores + password directory

#### Overview

In this mode you provide:
- `keystore_path`: directory that contains validator keystores in JSON format.
- `keystore_password_path`: directory that contains the passwords for those keystores.

The loader will:
1. Walk `keystore_path`.
2. For every file that looks like a validator keystore (e.g. `validator01.json`, `keystore-m_12381_3600_0_0_0-123456789.json`, etc.), it will try to decrypt it.
3. To decrypt it, it expects a password file in `keystore_password_path` with the same base name but a `.txt` extension.

#### File naming requirements

- Keystore file:
    - `validator01.json`
    - `keystore-m_12381_3600_0_0_0-123456789.json`

- Password file:
    - `validator01.txt`
    - `keystore-m_12381_3600_0_0_0-123456789.txt`

**Important:**
- The extension for the password file MUST be `.txt`.
- The base name (before `.json` / `.txt`) must match exactly.

For example:

```text
keystore_path/
  validator01.json
  validator02.json

keystore_password_path/
  validator01.txt
  validator02.txt
```

#### Keystore format

Each `*.json` file must follow [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

#### How it's loaded

- The loader reads the keystore JSON.
- It looks up the corresponding password file.
- It derives the symmetric key using the KDF parameters in the keystore.

Only BLS validator keys are currently supported.

---

### 2. Raw private key YAML (`file-raw`)

#### Overview

In this mode, you only provide `keystore_path`.
Inside that directory, instead of a JSON keystore, you can drop a YAML file that directly embeds the validator's private key in plaintext.

This is intended mainly for development or testing, because the private key is stored unencrypted.

#### YAML format

```yaml
type: "file-raw"
keyType: "BLS"
privateKey: "0x<32-byte-private-key-hex>"
```

Where:
- `type` must be `"file-raw"`.
- `keyType` must be `"BLS"`. At the moment only BLS validator keys are supported.
- `privateKey` is the raw validator private key, 32 bytes, hex-encoded.
  The loader accepts the key with or without the `0x` prefix.

#### How it's loaded

- The loader scans `keystore_path`.
- For any file that parses as YAML/JSON and has `type: "file-raw"`, it:
    - Reads the `privateKey`.
    - Interprets it as a 32-byte BLS private key.
    - Derives the matching BLS public key.

Because the key is not encrypted, this is the simplest mode operationally, but also the most sensitive from a security perspective.

---

### 3. Encrypted keystore reference YAML (`file-keystore`)

#### Overview

This mode is a hybrid. Instead of placing:
- a raw private key (like `file-raw`), or
- a plain JSON keystore + password in fixed directories (like mode 1),

you can give the loader a YAML file that *points to* an encrypted keystore file and its password file.

This allows you to group configuration in one directory even if the actual keystore and password live somewhere else.

### YAML format

```yaml
type: "file-keystore"
keyType: "BLS"
keystoreFile: "/path/to/validator.json"
keystorePasswordFile: "/path/to/password.txt"
```

Where:
- `type` must be `"file-keystore"`.
- `keyType` must be `"BLS"`. Only BLS is supported.
- `keystoreFile` points to an encrypted validator keystore that MUST follow [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).
- `keystorePasswordFile` points to a text file containing the passphrase for that keystore.

Both `keystoreFile` and `keystorePasswordFile` can be either:
- absolute paths, or
- relative paths.

If they are relative, they are resolved relative to the directory where this YAML file lives.

#### How it's loaded

- The loader reads the YAML, sees `type: "file-keystore"`.
- It resolves `keystoreFile` and `keystorePasswordFile`.
- It reads the EIP-2335 keystore JSON.
- It reads the password.
- It decrypts the private key exactly the same way as in mode 1.
- It derives the BLS public key from that private key.

This gives you similar security properties to encrypted keystores (the private key on disk is still encrypted), but it's more flexible about file layout because the YAML can live next to your application instead of next to the keystore.


### Key type restrictions

At this stage, **only `keyType: "BLS"` is supported**.
That means we currently assume these are Ethereum consensus validator signing keys (BLS12-381).

No `SECP256K1` execution-layer keys are supported yet in this loader.

---

## Summary

- **Mode 1: Encrypted keystore JSON + password directory**
    - You provide `keystore_path` and `keystore_password_path`.
    - Filenames must match (`.json` ↔ `.txt`).
    - Each keystore JSON must comply with EIP-2335.
    - The loader decrypts the private key and derives the public key.

- **Mode 2: Raw YAML (`file-raw`)**
    - You provide `keystore_path`.
    - YAML contains the BLS private key in plaintext (`privateKey`).
    - The loader derives the public key directly.

- **Mode 3: YAML (`file-keystore`)**
    - You provide `keystore_path`.
    - YAML points to an external encrypted keystore JSON and its password file.
    - The keystore JSON must comply with EIP-2335.
    - Paths may be relative to the YAML file.
    - The loader decrypts and derives the key.

In all cases, the loader walks `keystore_path` and imports every key definition it finds.
**Only BLS validator keys are supported.**
