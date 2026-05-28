#!/usr/bin/env python3
"""
FortiCNAPP CTF — control script
Run:  python ctl.py
"""

import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
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


# ── CTFd auto-token ────────────────────────────────────────────────────────────
# After CTFd starts for the first time we:
#   1. Wait until the web UI is up
#   2. POST to /setup to complete the first-run wizard programmatically
#   3. Log in via /login to get a session cookie
#   4. POST to /api/v1/tokens to create an admin token
#   5. Write CTFD_ADMIN_TOKEN to .env
#
# The admin credentials (CTFD_ADMIN_NAME / EMAIL / PASSWORD) are collected in the
# setup wizard and stored in .env — they are never transmitted outside localhost.

CTFD_LOCAL = "http://localhost:8000"


def _extract_nonce(text: str) -> str:
    """Pull the CTFd CSRF nonce out of a page or JSON response."""
    for pat in (
        r"csrfNonce['\"]:\s*['\"]([a-f0-9]+)['\"]",
        r'name="nonce"\s+value="([^"]+)"',
        r"nonce['\"]:\s*['\"]([a-f0-9]+)['\"]",
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _auto_token(env: dict) -> str | None:
    """
    Programmatically complete the CTFd first-run wizard and return a fresh
    admin token string, or None if anything fails.
    """
    admin_name  = env.get("CTFD_ADMIN_NAME",  "admin")
    admin_email = env.get("CTFD_ADMIN_EMAIL", "admin@ctf.local")
    admin_pass  = env.get("CTFD_ADMIN_PASSWORD", "")
    ctf_name    = env.get("CTF_NAME", "FortiCNAPP CTF")

    if not admin_pass:
        return None

    jar    = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [("User-Agent", "forticnapp-ctl/1.0")]

    # ── 1. Wait for CTFd ──────────────────────────────────────────────────────
    print(f"  {DIM}Waiting for CTFd to be ready", end="", flush=True)
    deadline = time.time() + 120
    up = False
    while time.time() < deadline:
        try:
            r = opener.open(f"{CTFD_LOCAL}/", timeout=3)
            if r.status < 500:
                up = True
                break
        except urllib.error.HTTPError as e:
            if e.code < 500:
                up = True
                break
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print()

    if not up:
        print(f"  {RED}CTFd did not start in time.{RESET}")
        return None

    # ── 2. Complete setup wizard (only on first run) ───────────────────────────
    try:
        r     = opener.open(f"{CTFD_LOCAL}/setup", timeout=10)
        body  = r.read().decode(errors="replace")
        nonce = _extract_nonce(body)
        if nonce:
            print(f"  {DIM}Completing CTFd setup wizard…{RESET}")
            data = urllib.parse.urlencode({
                "nonce":     nonce,
                "ctf_name":  ctf_name,
                "name":      admin_name,
                "email":     admin_email,
                "password":  admin_pass,
                "user_mode": "users",
            }).encode()
            req = urllib.request.Request(
                f"{CTFD_LOCAL}/setup", data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                opener.open(req, timeout=15)
            except Exception:
                pass  # redirect after setup is normal
    except Exception:
        pass  # /setup redirects away if already set up — that's fine

    # ── 3. Log in ─────────────────────────────────────────────────────────────
    print(f"  {DIM}Logging in as {admin_name}…{RESET}")
    try:
        r     = opener.open(f"{CTFD_LOCAL}/login", timeout=10)
        body  = r.read().decode(errors="replace")
        nonce = _extract_nonce(body)
    except Exception as exc:
        print(f"  {RED}Login page unavailable:{RESET} {exc}")
        return None

    try:
        data = urllib.parse.urlencode({
            "nonce":    nonce,
            "name":     admin_name,
            "password": admin_pass,
        }).encode()
        req = urllib.request.Request(
            f"{CTFD_LOCAL}/login", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        opener.open(req, timeout=10)
    except Exception:
        pass  # redirect after login is normal

    # ── 4. Fetch CSRF nonce for the token endpoint ────────────────────────────
    csrf = ""
    try:
        r    = opener.open(f"{CTFD_LOCAL}/api/v1/tokens", timeout=10)
        body = r.read().decode(errors="replace")
        resp = json.loads(body)
        csrf = resp.get("data", {}).get("csrfNonce", "") or _extract_nonce(body)
    except Exception:
        pass

    if not csrf:
        try:
            r    = opener.open(f"{CTFD_LOCAL}/settings", timeout=10)
            body = r.read().decode(errors="replace")
            csrf = _extract_nonce(body)
        except Exception:
            pass

    # ── 5. Create token ───────────────────────────────────────────────────────
    print(f"  {DIM}Generating admin token…{RESET}")
    try:
        payload = json.dumps({"expiration": None}).encode()
        req = urllib.request.Request(
            f"{CTFD_LOCAL}/api/v1/tokens", data=payload,
            headers={"Content-Type": "application/json", "CSRF-Token": csrf},
        )
        r    = opener.open(req, timeout=10)
        resp = json.loads(r.read())
        return resp.get("data", {}).get("value")
    except Exception as exc:
        print(f"  {RED}Token generation failed:{RESET} {exc}")
        return None


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

    print(f"\n  {DIM}CTFd admin account — used to complete the first-run wizard automatically{RESET}")
    print(f"  {DIM}and to generate the admin API token (token is saved to .env on first start){RESET}")
    changes["CTFD_ADMIN_NAME"] = prompt(
        "CTFd admin username",
        default=env.get("CTFD_ADMIN_NAME") or "admin")
    changes["CTFD_ADMIN_EMAIL"] = prompt(
        "CTFd admin email",
        default=env.get("CTFD_ADMIN_EMAIL") or "admin@ctf.local")
    changes["CTFD_ADMIN_PASSWORD"] = prompt(
        "CTFd admin password",
        default=env.get("CTFD_ADMIN_PASSWORD") or "admin", secret=True, required=True)

    print(f"\n  {DIM}CTFd admin API token — leave blank; auto-filled on first start{RESET}")
    changes["CTFD_ADMIN_TOKEN"] = prompt(
        "CTFd admin API token   (leave blank to auto-generate)",
        default=env.get("CTFD_ADMIN_TOKEN", ""), secret=True)

    # ── Section 2: HTTPS ───────────────────────────────────────────────────────
    print(f"\n{BOLD}2 / 3  HTTPS{RESET}")
    print(f"  {DIM}Caddy uses a self-signed cert (tls internal). Leave FQDN blank to use localhost.{RESET}")
    print(f"  {DIM}Set FQDN to your hostname/IP if participants connect from other machines.{RESET}")

    changes["FQDN"] = prompt(
        "FQDN  (hostname or IP — blank = localhost)",
        default=env.get("FQDN", ""))

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
    fqdn     = env.get("FQDN") or "localhost"
    token_ok = bool(env.get("CTFD_ADMIN_TOKEN"))

    url = f"https://{fqdn}"
    if token_ok:
        start_info = f"{DIM}→ {url}{RESET}  {CYAN}self-signed cert{RESET}"
    else:
        start_info = f"{YELLOW}⚠  first start — token will be auto-generated{RESET}"

    return f"""
{BOLD}{RED}╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝{RESET}

  {BOLD}STATUS{RESET}
{get_status()}

  {GREEN}s{RESET}  Setup / edit .env

  {GREEN}1{RESET}  START    {start_info}
  {YELLOW}2{RESET}  STOP     {DIM}(containers stopped, data kept){RESET}
  {GREEN}3{RESET}  RESTART
  {RED}4{RESET}  DESTROY  {DIM}⚠️  removes containers + volumes — all data lost{RESET}

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


def _ctfd_challenge_count(token: str) -> int:
    """Return number of challenges currently in CTFd (0 on error)."""
    try:
        req = urllib.request.Request(
            f"{CTFD_LOCAL}/api/v1/challenges?view=admin",
            headers={"Authorization": f"Token {token}"},
        )
        r    = urllib.request.urlopen(req, timeout=5)
        data = json.loads(r.read()).get("data", [])
        return len(data)
    except Exception:
        return 0


def start(env: dict) -> None:
    token_ok   = bool(env.get("CTFD_ADMIN_TOKEN"))
    fqdn       = env.get("FQDN") or "localhost"
    first_boot = not token_ok   # first boot = no token yet

    # ── First-boot: no token yet ───────────────────────────────────────────────
    if not token_ok:
        if not env.get("CTFD_ADMIN_PASSWORD"):
            print(f"\n{RED}Cannot auto-configure — CTFD_ADMIN_PASSWORD is not set.{RESET}")
            print(f"{DIM}Press s to open the setup wizard and set admin credentials.{RESET}")
            return

        ok = run(["docker", "compose", "up", "-d", "db", "cache", "ctfd"])
        if not ok:
            return

        print(f"\n{CYAN}Auto-configuring CTFd…{RESET}")
        token = _auto_token(env)

        if token:
            write_env({"CTFD_ADMIN_TOKEN": token})
            env["CTFD_ADMIN_TOKEN"] = token
            print(f"  {GREEN}✅  Admin token saved to .env{RESET}")
        else:
            print(f"\n{YELLOW}⚠  Could not auto-generate token.{RESET}")
            print(f"{DIM}CTFd is at http://localhost:8000 — complete the wizard manually,{RESET}")
            print(f"{DIM}then Admin Panel → Settings → Tokens → Generate, press s to paste it.{RESET}")
            return

    # ── Full stack ─────────────────────────────────────────────────────────────
    ok = run(["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger", "caddy"])
    if not ok:
        return

    # ── Restore theme + home page + challenges if needed ──────────────────────
    # On first boot OR when the database was wiped (0 challenges), automatically
    # run bridge-static to push:
    #   • Fortinet dark theme CSS → theme_header config
    #   • Custom home page (CTF Lab / Live CTF mode cards) → CTFd Pages
    #   • 21 static CTF Lab challenges
    token = env.get("CTFD_ADMIN_TOKEN", "")
    n_challenges = _ctfd_challenge_count(token)

    if first_boot or n_challenges == 0:
        if first_boot:
            print(f"\n{CYAN}First start — applying Fortinet theme and home page…{RESET}")
        else:
            print(f"\n{YELLOW}⚠  No challenges found — restoring theme, home page, and CTF Lab challenges…{RESET}")
        print(f"{DIM}(running bridge-static — this takes ~30 s){RESET}\n")
        run(["docker", "compose", "run", "--rm", "bridge-static"])
        print(f"\n{GREEN}✅  Theme, home page, and CTF Lab challenges loaded.{RESET}")
        print(f"{DIM}Open the home page to switch to Live CTF mode or reset at any time.{RESET}")

    print(f"\n{CYAN}Open{RESET} {BOLD}https://{fqdn}{RESET}  {DIM}(self-signed cert — accept the browser warning on first visit){RESET}")


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
            c = input(f"{RED}{BOLD}⚠️  DESTROY — stops all containers and wipes all data. Type YES to confirm: {RESET}").strip()
            if c == "YES":
                run(["docker", "compose", "stop"])
                ok = run(["docker", "compose", "down", "-v", "--remove-orphans"])
                if ok:
                    write_env({"CTFD_ADMIN_TOKEN": ""})
                    print(f"{GREEN}✅  Stack destroyed. All data wiped.{RESET}")
                    print(f"{DIM}Press 1 to start fresh.{RESET}")
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
