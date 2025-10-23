### Internal business logic

The **domain layer**: business logic, entities, repositories, and **use cases** consumed by `cmd/` and `server/`.

Use **vertical slicing**: each folder is a context/bounded domain that owns its models, repositories and rules.

## Responsibilities
- Domain models (entities, invariants).
- Use cases (application services) that orchestrate domain operations.
- Repository interfaces and domain-oriented ports.
- Pure business rules (no framework dependencies).

## Non-responsibilities
- **No HTTP** (controllers live in `server/`).
- **No CLI parsing** (lives in `cmd/`).
- **No SQL or database coupling** (implemented in adapters, e.g., `database/` or `infrastructure/`).

## Structure (example)
