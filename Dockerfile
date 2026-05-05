# mcp-android — Android development MCP server (ADB + emulator management)
# Runs on FRAME-DESK in Podman rootless container.
# Multi-stage build: install deps → production image with ADB.

# ── Build stage ──────────────────────────────────────
FROM oven/bun:1.3.10-alpine AS build

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --production

# ── Production stage ─────────────────────────────────
FROM oven/bun:1.3.10-alpine

WORKDIR /app

# Install Android SDK platform-tools (ADB)
RUN apk add --no-cache android-tools git openssh-client

# Copy only production artifacts
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/

# Build output directory for APKs
RUN mkdir -p /data/builds && chown bun:bun /data/builds

# Non-root user for defense-in-depth
USER bun

EXPOSE 8912

# Auto-link ghcr.io package to repo
LABEL org.opencontainers.image.source=https://github.com/nsoult-agentic/mcp-android

CMD ["bun", "run", "src/http.ts"]
