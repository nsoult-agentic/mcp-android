# mcp-android — Android development MCP server (ADB + build tooling)
# Runs on FRAME-DESK in Podman rootless container.
# JDK 21 installed here (self-contained, no host symlink issues).
# Android SDK mounted from host to stay in sync with Android Studio.
# Debian base required: Android SDK binaries need glibc (musl breaks aapt2).

# ── Build stage ──────────────────────────────────────
FROM oven/bun:1.3.10-debian AS build

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --production

# ── Production stage ─────────────────────────────────
FROM oven/bun:1.3.10-debian

WORKDIR /app

# JDK 21 (for AGP 9.x) + ADB, git, SSH for repo-sync
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    adb \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

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
