### HTTP API

HTTP API adapter: bootstraps the HTTP server and hosts controllers/handlers that **invoke use cases**.

Treat this layer purely as an **adapter**: translate HTTP <-> domain inputs/outputs.

## Responsibilities
- Server initialization and lifecycle (listen, shutdown).
- Routing and controller wiring.
- Request validation, authentication/authorization middleware.
- Mapping domain errors to HTTP responses.
- JSON encoding/decoding and content negotiation.

## Non-responsibilities
- **No business logic** (delegate to `internal/` use cases).
- **No SQL or migrations** (lives in `database/`).
- **No CLI logic**.

## Guidelines
- Keep handlers thin: validate -> call use case -> map result -> respond.
- Don’t pass HTTP types into the domain; convert to domain inputs first.
- Centralize error handling and logging; avoid leaking internals in responses.
- Prefer context-aware timeouts and request-scoped dependencies.
