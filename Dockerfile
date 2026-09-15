# Multi-stage build for KyVault Server

# Stage 1: Build React Frontend
FROM node:26-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Go Backend Binary
FROM golang:1.27-alpine AS backend-builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kyvault-server ./cmd/server

# Stage 3: Minimal Production Image
FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -S kyvault && adduser -S kyvault -G kyvault \
    && mkdir -p /kyvault/data /kyvault/config /app/frontend/dist \
    && chown -R kyvault:kyvault /kyvault /app

WORKDIR /app
COPY --from=backend-builder /kyvault-server /usr/local/bin/kyvault-server
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

USER kyvault:kyvault
ENV PORT=5877 \
    DATA_DIR=/kyvault/data \
    CONFIG_DIR=/kyvault/config \
    WEB_DIR=/app/frontend/dist

VOLUME ["/kyvault/data", "/kyvault/config"]
EXPOSE 5877

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5877/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/kyvault-server"]
