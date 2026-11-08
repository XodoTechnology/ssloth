# ---- build frontend ----
FROM node:20-bookworm-slim AS webbuild
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- server deps ----
FROM node:20-bookworm-slim AS serverdeps
WORKDIR /app/server
# build tools for better-sqlite3 fallback (prebuilds cover most platforms)
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY server/package.json server/package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund

# ---- runtime ----
# Build the bmc-node napi addon inside the same distro as the runtime — the
# checked-in server/native binaries may be built on a newer glibc and fail to
# load (libssl.so.3 / GLIBC_2.xx not found), silently disabling KVM/BMC.
FROM rust:1-bookworm AS bmcbuild
WORKDIR /build
# Whole vendor/ is needed: bmc-core include_str!/include_bytes! reach
# vendor/CHANGELOG.md and vendor/assets/icons/*.
COPY vendor vendor
RUN cargo build --release --manifest-path vendor/bmc/Cargo.toml -p bmc-node \
 && cp vendor/bmc/target/release/libbmc_node.so /bmc.node

FROM node:20-bookworm-slim
ENV NODE_ENV=production \
    SSLOTH_DATA_DIR=/data \
    PORT=8080
WORKDIR /app
COPY --from=serverdeps /app/server/node_modules server/node_modules
COPY server/package.json server/
COPY server/src server/src
# Prebuilt bmc-core napi addon (KVM + BMC host commands) — without it the
# image boots but every KVM/BMC route reports the backend as unavailable.
COPY server/native server/native
# …then overwrite the linux artifacts with the bookworm-built ones (the
# loader prefers bmc.linux-x64.node, so both names must be replaced).
COPY --from=bmcbuild /bmc.node server/native/bmc.linux-x64.node
COPY --from=bmcbuild /bmc.node server/native/bmc.node
COPY --from=webbuild /app/web/dist web/dist
# libssl3: bmc-node links the system OpenSSL on Linux (vendored builds are
# non-Linux only) and the node base image doesn't ship it.
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r ssloth && useradd -r -g ssloth ssloth \
  && mkdir -p /data && chown ssloth:ssloth /data
USER ssloth
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/auth/state').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/src/index.js"]
