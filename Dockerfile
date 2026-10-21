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
FROM node:20-bookworm-slim
ENV NODE_ENV=production \
    SSLOTH_DATA_DIR=/data \
    PORT=8080
WORKDIR /app
COPY --from=serverdeps /app/server/node_modules server/node_modules
COPY server/package.json server/
COPY server/src server/src
COPY --from=webbuild /app/web/dist web/dist
RUN groupadd -r ssloth && useradd -r -g ssloth ssloth \
  && mkdir -p /data && chown ssloth:ssloth /data
USER ssloth
VOLUME ["/data"]
EXPOSE 8080
CMD ["node", "server/src/index.js"]
