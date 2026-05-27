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
    print(f"{DIM}Press Enter to keep the current value.  Fields marked (auto) are pre-filled.{RESET}")
    changes = {}

    # ── Section 1: CTFd internal settings ─────────────────────────────────────
    print(f"\n{BOLD}1 / 3  CTFd internal settings{RESET}")

    # SECRET_KEY — auto-generate, never shown to end users
    sk = env.get("SECRET_KEY", "")
    if not sk or sk == "change_me_secret_key":
        sk = secrets.token_hex(32)
        print(f"  {DIM}CTFd Flask session key — auto-generated random string, never share this{RESET}")
        changes["SECRET_KEY"] = sk
        print(f"  SECRET_KEY  {DIM}(auto-generated ✓){RESET}")
    else:
        print(f"  SECRET_KEY  {DIM}(already set ✓){RESET}")

    print(f"\n  {DIM}MariaDB passwords — used internally between containers, never exposed externally{RESET}")
    changes["MYSQL_ROOT_PASSWORD"] = prompt(
        "MariaDB ROOT password  (database admin, internal only)",
        default=env.get("MYSQL_ROOT_PASSWORD") or "root", secret=True)
    changes["MYSQL_PASSWORD"] = prompt(
        "MariaDB CTFd password  (app db user, internal only)",
        default=env.get("MYSQL_PASSWORD") or "root", secret=True)

    print(f"\n  {DIM}CTFd admin API token — generate this AFTER completing the CTFd setup wizard:{RESET}")
    print(f"  {DIM}  CTFd → Admin Panel → Settings → Tokens → Generate{RESET}")
    changes["CTFD_ADMIN_TOKEN"] = prompt(
        "CTFd admin API token   (starts with ctfd_...)",
        default=env.get("CTFD_ADMIN_TOKEN", ""), secret=True)

    # ── Section 2: HTTPS ───────────────────────────────────────────────────────
    print(f"\n{BOLD}2 / 3  HTTPS  (skip if running HTTP only){RESET}")

    print(f"  {DIM}Your DuckDNS subdomain — e.g. samvblogs.duckdns.org{RESET}")
    changes["FQDN"] = prompt(
        "FQDN  (your public domain name)",
        default=env.get("FQDN", ""))

    print(f"  {DIM}TCP port for CTFd HTTPS — 443 is standard, 4443 avoids needing root{RESET}")
    changes["HTTPS_PORT"] = prompt(
        "HTTPS port             (443 or 4443)",
        default=env.get("HTTPS_PORT") or "4443")

    print(f"  {DIM}DuckDNS token — log in at duckdns.org, your token is at the top of the page{RESET}")
    changes["DUCKDNS_TOKEN"] = prompt(
        "DuckDNS token          (for Let's Encrypt cert — leave blank to skip HTTPS)",
        default=env.get("DUCKDNS_TOKEN", ""), secret=True)

    # ── Section 3: FortiCNAPP API ──────────────────────────────────────────────
    print(f"\n{BOLD}3 / 3  FortiCNAPP API credentials  (Live CTF mode only — skip if using CTF Lab){RESET}")
    print(f"  {DIM}Get these from: FortiCNAPP console → Settings → API Keys → Create New{RESET}")

    changes["FORTICNAPP_ACCOUNT"] = prompt(
        "Account name           (subdomain only: acme-prod.lacework.net → acme-prod)",
        default=env.get("FORTICNAPP_ACCOUNT", ""))
    changes["FORTICNAPP_SUBACCOUNT"] = prompt(
        "Sub-account            (leave blank if not using sub-accounts)",
        default=env.get("FORTICNAPP_SUBACCOUNT", ""))
    changes["FORTICNAPP_API_KEY_ID"] = prompt(
        "API Key ID             (from downloaded JSON: field 'keyId')",
        default=env.get("FORTICNAPP_API_KEY_ID", ""), secret=True)
    changes["FORTICNAPP_API_SECRET"] = prompt(
        "API Secret             (from downloaded JSON: field 'secret')",
        default=env.get("FORTICNAPP_API_SECRET", ""), secret=True)

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
    """Return True if Docker is reachable. Offer to fix permission issues automatically."""
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        if r.returncode == 0:
            return True
        err = r.stderr.decode()
    except FileNotFoundError:
        print(f"\n{RED}Docker not found.{RESET} Install Docker Desktop or Docker Engine first.\n")
        return False
    except Exception as e:
        print(f"\n{RED}Docker not reachable:{RESET} {str(e)[:120]}\n")
        return False

    if "permission denied" in err.lower():
        print(f"\n{RED}{BOLD}Docker permission denied{RESET} — your user is not in the docker group.")
        ans = input(f"{BOLD}Fix it now? (requires sudo)  [Y/n]: {RESET}").strip().lower()
        if ans in ("", "y", "yes"):
            user = os.environ.get("USER") or os.environ.get("LOGNAME") or \
                   subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
            print(f"\n{DIM}▶ sudo usermod -aG docker {user}{RESET}")
            ret = subprocess.run(["sudo", "usermod", "-aG", "docker", user]).returncode
            if ret != 0:
                print(f"{RED}usermod failed — try manually:{RESET}  sudo usermod -aG docker {user}")
                return False
            print(f"\n{GREEN}✅ Added {user} to docker group.{RESET}")
            print(f"{YELLOW}Applying group change and restarting script…{RESET}\n")
            # Re-exec this script inside a new shell that has the docker group active
            os.execvp("sg", ["sg", "docker", "-c",
                             f"{sys.executable} {' '.join(sys.argv)}"])
            # os.execvp replaces the process — nothing below runs
        else:
            print(f"{DIM}Skipped. Run manually:  sudo usermod -aG docker $USER && newgrp docker{RESET}")
    else:
        print(f"\n{RED}Docker not reachable:{RESET} {err[:120]}\n")

    return False


def run(cmd: list[str]) -> bool:
    """Run a shell command. Returns True if it was executed, False if blocked (e.g. no Docker)."""
    if not check_docker():
        return False
    print(f"\n{DIM}▶ {' '.join(cmd)}{RESET}\n")
    try:
        subprocess.run(cmd, check=False)
        return True
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
        return False


def start(env: dict) -> None:
    fqdn       = env.get("FQDN", "")
    https_port = env.get("HTTPS_PORT") or "4443"
    token_ok   = bool(env.get("CTFD_ADMIN_TOKEN"))

    cert_found = has_cert(fqdn) if fqdn else False
    use_https  = bool(fqdn and token_ok and (cert_found or env.get("DUCKDNS_TOKEN")))

    services = ["db", "cache", "ctfd", "trigger"] + (["caddy"] if use_https else [])

    ok = run(["docker", "compose", "up", "-d"] + services)
    if not ok:
        return   # Docker unavailable — error already printed by run()

    # Invalidate cert cache so next menu re-probes after Caddy may have obtained a cert
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
