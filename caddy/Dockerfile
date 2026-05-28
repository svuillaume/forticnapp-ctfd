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

# Site configurations
# Caddyfile       — production (Let's Encrypt via DuckDNS DNS-01)
# Caddyfile.local — local dev  (self-signed cert via Caddy internal CA)
COPY Caddyfile       /etc/caddy/Caddyfile
COPY Caddyfile.local /etc/caddy/Caddyfile.local

# 80   — HTTP (redirected to HTTPS automatically by Caddy — production only)
# 443  — HTTPS (CTFd)
# 5555 — HTTPS (Trigger service)
# 2019 — Caddy admin API (health checks, config reload — internal only)
EXPOSE 80 443 5555 2019

# Select Caddyfile at runtime:
#   DUCKDNS_TOKEN set   → production  (Let's Encrypt + DuckDNS)
#   DUCKDNS_TOKEN unset → local dev   (self-signed cert)
CMD ["sh", "-c", \
     "if [ -n \"${DUCKDNS_TOKEN}\" ]; then \
        exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile; \
      else \
        exec caddy run --config /etc/caddy/Caddyfile.local --adapter caddyfile; \
      fi"]
