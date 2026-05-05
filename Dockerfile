# mcp-android — Android development MCP server (ADB + emulator management)
# Runs on FRAME-DESK in Podman rootless container.
# Multi-stage build: install deps → production image.
# Java/Android SDK mounted from host (not installed here) to stay in sync.
# Debian base required: Android SDK binaries need glibc (musl breaks aapt2).

# ── Build stage ──────────────────────────────────────
FROM oven/bun:1.3.10-debian AS build

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --production

# ── Production stage ─────────────────────────────────
FROM oven/bun:1.3.10-debian

WORKDIR /app

# ADB, git, SSH for repo-sync
RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy only production artifacts
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/

# Build output directory for APKs + Gradle cache
RUN mkdir -p /data/builds && chown bun:bun /data/builds \
    && mkdir -p /home/bun/.gradle && chown bun:bun /home/bun/.gradle

# Non-root user for defense-in-depth
USER bun

EXPOSE 8912

# Auto-link ghcr.io package to repo
LABEL org.opencontainers.image.source=https://github.com/nsoult-agentic/mcp-android

CMD ["bun", "run", "src/http.ts"]
