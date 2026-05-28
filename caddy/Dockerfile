FROM caddy:latest

LABEL org.opencontainers.image.title="FortiCNAPP CTF — HTTPS Reverse Proxy"
LABEL org.opencontainers.image.description="Caddy with self-signed TLS (tls internal)"

COPY Caddyfile /etc/caddy/Caddyfile

# 80   — HTTP (redirected to HTTPS by Caddy)
# 443  — HTTPS (CTFd)
# 5555 — HTTPS (Trigger service)
# 2019 — Caddy admin API (internal only)
EXPOSE 80 443 5555 2019
