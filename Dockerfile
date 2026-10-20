# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Build stage: compile fully static binaries. Dependency download is kept in
# its own layer so source edits do not invalidate the module cache.
# ---------------------------------------------------------------------------
FROM golang:1.24-alpine AS build

ARG VERSION=1.0.0

WORKDIR /src

RUN apk add --no-cache ca-certificates

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS=-mod=readonly

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN go build -trimpath -buildvcs=false \
        -ldflags="-s -w -X banner-fingerprint/internal/version.Version=${VERSION}" \
        -o /out/server ./cmd/server \
 && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/client ./cmd/client \
 && go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

# ---------------------------------------------------------------------------
# Server runtime: scratch (no shell, no package manager, minimal attack
# surface). Runs as UID/GID 65532 (the conventional "nonroot" id) and carries
# a static health probe because scratch has neither curl nor wget.
# ---------------------------------------------------------------------------
FROM scratch AS server

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /bin/server
COPY --from=build /out/healthcheck /bin/healthcheck
COPY --chown=65532:65532 rules/ /app/rules/

ENV RULES_DIR=/app/rules \
    LISTEN_ADDR=:8080

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
    CMD ["/bin/healthcheck"]

ENTRYPOINT ["/bin/server"]

# ---------------------------------------------------------------------------
# Client runtime: one-shot CLI. Input data is bind-mounted read-only.
# ---------------------------------------------------------------------------
FROM scratch AS client

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/client /bin/client

ENV SERVER_URL=http://server:8080 \
    INPUT_FILE=/data/input.json

USER 65532:65532

ENTRYPOINT ["/bin/client"]
