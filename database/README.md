## Everything related to the database and migrations.

This includes `.sql` files for schema changes and the code that **executes** and **manages** migrations.

## Responsibilities
- Schema definition and evolution via migrations.
- Migration runner (apply/rollback/status).
- Seeders and fixtures for local/dev environments.

## Non-responsibilities
- **No business logic**.
- **No HTTP or CLI orchestration** (only the runner API).
- **No direct coupling** to application use cases.

## Guidelines
- Keep migrations **idempotent** when possible and always **reversible** (add a down step or compensating change).
- Name migrations with an increasing, sortable prefix.
- Provide a simple programmatic API: `Apply(ctx)`, `Rollback(ctx, toVersion)`, `Status(ctx)`.