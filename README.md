# RSIG
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
http:
  port: 8080
