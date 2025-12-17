# =========================
# Stage 1: builder
# =========================
FROM golang:1.25-alpine AS builder

# CGO is required for herumi/bls-eth-go-binary
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

# Install build dependencies for CGO
RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/bin/app ./cmd/...


# =========================
# Stage 2: runtime
# =========================
FROM alpine:3.20

# Install runtime dependencies for CGO binary
RUN apk add --no-cache libc6-compat && \
    adduser -D -u 10001 appuser

WORKDIR /home/appuser

COPY --from=builder /app/bin/app ./app

RUN chmod +x ./app && chown appuser:appuser ./app
USER appuser

EXPOSE 8080

ENTRYPOINT ["./app"]
