# Stage 1 — Build a custom Caddy binary with the DuckDNS DNS provider plugin.
# This enables Let's Encrypt DNS-01 challenge without requiring open port 80.
FROM caddy:builder AS builder
RUN xcaddy build --with github.com/caddy-dns/duckdns

# Stage 2 — Minimal runtime image
FROM caddy:latest

LABEL org.opencontainers.image.title="FortiCNAPP CTF — HTTPS Reverse Proxy"
LABEL org.opencontainers.image.description="Caddy reverse proxy with Let's Encrypt TLS via DuckDNS DNS-01"

# Drop in the custom Caddy binary that knows about DuckDNS
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Site configuration
COPY Caddyfile /etc/caddy/Caddyfile

# 80   — HTTP (redirected to HTTPS automatically by Caddy)
# 443  — HTTPS (CTFd)
# 5555 — HTTPS (Trigger service)
# 2019 — Caddy admin API (health checks, config reload — internal only)
EXPOSE 80 443 5555 2019
