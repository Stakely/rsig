## Command-line entry points for the application.

Treat everything in `cmd` as **adapters** that orchestrate use cases from the `internal/` domain layer.
While CLI is the primary entry point here, the same use cases can be adapted by other interfaces (e.g. HTTP).

## Responsibilities
- Parse flags, environment variables, and config.
- Wire dependencies (e.g. repositories, services).
- Invoke **use cases** (from `internal/`) and format user-facing output.
- Handle process lifecycle (exit codes, cancellation, signals).

## Non-responsibilities
- **No business logic**.
- **No database logic**.
- **No HTTP handlers**.

## Guidelines
- Keep commands thin; move logic to `internal/` use cases.
- Prefer functional options or small wiring constructors over global state.
- Validate inputs early and return actionable errors.

## Example
```go
// Serve command adapts config + server as an entry point
cfg := loadConfig()
return server.InitServer(cfg.Server)