#!/usr/bin/env python3
"""
FortiCNAPP CTF — control script
Run:  python ctl.py
"""

import os
import secrets
import subprocess
import sys
from pathlib import Path

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

ROOT = Path(__file__).parent
ENV  = ROOT / ".env"

# ── TLS cert probe ─────────────────────────────────────────────────────────────
# Caddy stores certs inside the caddy_data Docker volume at:
#   /data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<fqdn>/
# We spin up a throwaway alpine container (fast, ~0.3 s) to check the path.
# Result is cached for the session so the menu stays snappy.

_cert_cache: dict[str, bool] = {}

def _find_caddy_volume() -> str | None:
    """Return the caddy_data volume name (docker-compose prefixes it with project name)."""
    try:
        r = subprocess.run(
            ["docker", "volume", "ls", "--filter", "name=caddy_data", "--format", "{{.Name}}"],
            capture_output=True, text=True,
        )
        names = [n.strip() for n in r.stdout.strip().splitlines() if n.strip()]
        return names[0] if names else None
    except Exception:
        return None

def has_cert(fqdn: str) -> bool:
    """Return True if Caddy already holds a valid cert for fqdn in its data volume."""
    if not fqdn:
        return False
    if fqdn in _cert_cache:
        return _cert_cache[fqdn]

    vol = _find_caddy_volume()
    if not vol:
        _cert_cache[fqdn] = False
        return False

    cert_path = f"/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/{fqdn}"
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{vol}:/data", "alpine",
             "test", "-d", cert_path],
            capture_output=True,
        )
        result = r.returncode == 0
    except Exception:
        result = False

    _cert_cache[fqdn] = result
    return result

def invalidate_cert_cache() -> None:
    _cert_cache.clear()

# ── .env helpers ───────────────────────────────────────────────────────────────

def read_env() -> dict:
    result = {}
    if not ENV.exists():
        return result
    for line in ENV.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def write_env(values: dict) -> None:
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    updated = set()
    new_lines = []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in values:
                new_lines.append(f"{k}={values[k]}")
                updated.add(k)
                continue
        new_lines.append(line)
    for k, v in values.items():
        if k not in updated:
            new_lines.append(f"{k}={v}")
    ENV.write_text("\n".join(new_lines) + "\n")


def prompt(label: str, default: str = "", secret: bool = False, required: bool = False) -> str:
    shown = "*****" if (secret and default) else (default or ("required" if required else "optional"))
    while True:
        val = input(f"  {label} [{DIM}{shown}{RESET}]: ").strip()
        if val:      return val
        if default:  return default
        if not required: return ""
        print(f"  {RED}Required.{RESET}")


# ── Setup wizard ───────────────────────────────────────────────────────────────

def setup_wizard(env: dict) -> dict:
    print(f"\n{BOLD}{CYAN}── Configure .env ───────────────────────────────────────────────{RESET}")
    print(f"{DIM}Press Enter to keep the current value.{RESET}\n")
    changes = {}

    sections = [
        ("── CTFd", [
            ("SECRET_KEY",          "Secret key",                          secrets.token_hex(32), False),
            ("MYSQL_ROOT_PASSWORD", "MariaDB root password",               "FortiCTF-root-2026!", True),
            ("MYSQL_PASSWORD",      "MariaDB CTFd password",               "FortiCTF-ctfd-2026!", True),
            ("CTFD_ADMIN_TOKEN",    "CTFd admin token (generate after setup wizard)", "", True),
        ]),
        ("── HTTPS / Caddy", [
            ("FQDN",                "Domain (e.g. samvblogs.duckdns.org)", "",     False),
            ("HTTPS_PORT",          "HTTPS port (443 or 4443)",            "4443", False),
            ("DUCKDNS_TOKEN",       "DuckDNS token",                       "",     True),
        ]),
        ("── FortiCNAPP API  (Live CTF mode)", [
            ("FORTICNAPP_ACCOUNT",    "Account name (e.g. acme-prod)",     "", False),
            ("FORTICNAPP_SUBACCOUNT", "Sub-account  (leave blank if none)","", False),
            ("FORTICNAPP_API_KEY_ID", "API Key ID",                        "", True),
            ("FORTICNAPP_API_SECRET", "API Secret",                        "", True),
        ]),
    ]

    for section_title, fields in sections:
        print(f"\n  {BOLD}{CYAN}{section_title}{RESET}")
        for key, label, default, secret in fields:
            current = env.get(key, "")
            val = prompt(label, default=current or default, secret=secret)
            changes[key] = val

    write_env(changes)
    print(f"\n{GREEN}✅  .env saved.{RESET}")
    return {**env, **changes}


# ── Status ─────────────────────────────────────────────────────────────────────

def get_status() -> str:
    containers = {
        "forticnapp-ctfd":        "CTFd",
        "forticnapp-ctfd-db":     "DB",
        "forticnapp-ctfd-cache":  "Cache",
        "forticnapp-ctf-trigger": "Trigger",
        "forticnapp-ctf-caddy":   "Caddy",
    }
    try:
        r = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}\t{{.State}}"],
            capture_output=True, text=True, cwd=ROOT,
        )
        running = {}
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                running[parts[0].strip()] = parts[1].strip()
    except Exception:
        return f"  {DIM}(unavailable){RESET}"

    bits = []
    for cname, label in containers.items():
        state = running.get(cname, "")
        if state == "running":
            bits.append(f"{GREEN}●{RESET} {label}")
        elif state:
            bits.append(f"{YELLOW}◐{RESET} {label}")
        else:
            bits.append(f"{DIM}○ {label}{RESET}")
    return "  " + "   ".join(bits)


# ── Menu ───────────────────────────────────────────────────────────────────────

def build_menu(env: dict) -> str:
    fqdn       = env.get("FQDN", "")
    https_port = env.get("HTTPS_PORT") or "4443"
    token_ok   = bool(env.get("CTFD_ADMIN_TOKEN"))
    cert_found = has_cert(fqdn) if fqdn else False
    can_https  = bool(fqdn and token_ok and (cert_found or env.get("DUCKDNS_TOKEN")))

    url = (f"https://{fqdn}:{https_port}" if https_port != "443" else f"https://{fqdn}") if fqdn else ""

    if can_https and cert_found:
        start_info = f"{DIM}→ {url}{RESET}  {GREEN}🔒 cert found{RESET}"
    elif can_https:
        start_info = f"{DIM}→ {url}{RESET}  {YELLOW}(cert will be obtained on first start){RESET}"
    elif token_ok:
        start_info = f"{DIM}→ http://localhost:8000{RESET}  {YELLOW}(HTTPS not configured){RESET}"
    else:
        start_info = f"{YELLOW}⚠  configure .env first  (press s){RESET}"

    return f"""
{BOLD}{RED}╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝{RESET}

  {BOLD}STATUS{RESET}
{get_status()}

  {GREEN}s{RESET}  Setup / edit .env

  {GREEN}1{RESET}  START    {start_info}
  {YELLOW}2{RESET}  STOP     {DIM}(containers paused, data kept){RESET}
  {GREEN}3{RESET}  RESTART
  {RED}4{RESET}  RESET    {DIM}⚠️  wipes database + all scores{RESET}

  {DIM}5   Logs (CTFd)
  6   Logs (Trigger)
  q   Quit{RESET}
"""


# ── Actions ────────────────────────────────────────────────────────────────────

def check_docker() -> bool:
    """Return True if Docker is reachable. Print fix instructions if not."""
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        if r.returncode == 0:
            return True
        err = r.stderr.decode()
    except FileNotFoundError:
        err = "docker not found"
    except Exception as e:
        err = str(e)

    if "permission denied" in err.lower():
        print(f"""
{RED}{BOLD}Docker permission denied.{RESET}
Your user is not in the docker group. Fix with:

  {BOLD}sudo usermod -aG docker $USER{RESET}
  {BOLD}newgrp docker{RESET}          {DIM}# apply without logging out{RESET}

Then re-run this script.
""")
    elif "not found" in err.lower():
        print(f"\n{RED}Docker not found.{RESET} Install Docker Desktop or Docker Engine first.\n")
    else:
        print(f"\n{RED}Docker not reachable:{RESET} {err[:120]}\n")
    return False


def run(cmd: list[str]) -> None:
    if not check_docker():
        return
    print(f"\n{DIM}▶ {' '.join(cmd)}{RESET}\n")
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")


def start(env: dict) -> None:
    fqdn       = env.get("FQDN", "")
    https_port = env.get("HTTPS_PORT") or "4443"
    token_ok   = bool(env.get("CTFD_ADMIN_TOKEN"))

    # Use HTTPS if:
    #   a) cert already exists in caddy_data volume for this FQDN  (reuse, no token needed)
    #   b) DUCKDNS_TOKEN is set so Caddy can obtain a new cert
    cert_found = has_cert(fqdn) if fqdn else False
    use_https  = bool(fqdn and token_ok and (cert_found or env.get("DUCKDNS_TOKEN")))

    services = ["db", "cache", "ctfd", "trigger"] + (["caddy"] if use_https else [])
    run(["docker", "compose", "up", "-d"] + services)

    # Invalidate cache so next menu refresh re-probes after Caddy may have issued a cert
    invalidate_cert_cache()

    if use_https:
        url = f"https://{fqdn}:{https_port}" if https_port != "443" else f"https://{fqdn}"
        src = "existing cert" if cert_found else "new cert — Caddy is obtaining it (~30 s)"
        print(f"\n{CYAN}Open{RESET} {BOLD}{url}{RESET}  {DIM}({src}){RESET}")
    else:
        print(f"\n{CYAN}Open{RESET} {BOLD}http://localhost:8000{RESET}")


# ── Entry ──────────────────────────────────────────────────────────────────────

def main() -> None:
    os.chdir(ROOT)

    # Docker reachability check (warn but don't block — user may fix and retry)
    check_docker()

    env = read_env()

    # First run — no .env or placeholder key
    if not ENV.exists() or not env.get("SECRET_KEY") or env["SECRET_KEY"] == "change_me_secret_key":
        print(f"\n{YELLOW}First run — configure .env{RESET}")
        env = setup_wizard(env)

    while True:
        env = read_env()
        print(build_menu(env))
        choice = input(f"{BOLD}▶ {RESET}").strip().lower()

        if choice in ("q", "quit", "exit"):
            print(f"{DIM}Bye.{RESET}"); sys.exit(0)

        elif choice == "s":
            env = setup_wizard(env)

        elif choice == "1":
            start(env)

        elif choice == "2":
            run(["docker", "compose", "stop"])

        elif choice == "3":
            run(["docker", "compose", "stop"])
            start(env)

        elif choice == "4":
            c = input(f"{RED}{BOLD}⚠️  Wipe ALL data — type YES to confirm: {RESET}").strip()
            if c == "YES":
                run(["docker", "compose", "down", "-v"])
            else:
                print(f"{YELLOW}Cancelled.{RESET}")

        elif choice == "5":
            run(["docker", "compose", "logs", "-f", "ctfd"])

        elif choice == "6":
            run(["docker", "compose", "logs", "-f", "trigger"])

        else:
            print(f"{RED}Unknown option.{RESET}")
            continue

        input(f"\n{DIM}Press Enter to continue…{RESET}")


if __name__ == "__main__":
    main()
