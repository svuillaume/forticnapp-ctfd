#!/usr/bin/env python3
"""
FortiCNAPP CTF — main control script
Run from the project root:  python ctl.py
"""

import os
import secrets
import subprocess
import sys
from pathlib import Path

# ── Colour helpers ─────────────────────────────────────────────────────────────
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
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
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
    hint = (
        f" [{DIM}{'*****' if secret and default else default or 'optional'}{RESET}]"
        if default or not required
        else f" [{RED}required{RESET}]"
    )
    while True:
        val = input(f"  {label}{hint}: ").strip()
        if val:
            return val
        if default:
            return default
        if not required:
            return ""
        print(f"  {RED}This field is required.{RESET}")


# ── Setup wizard ───────────────────────────────────────────────────────────────

def setup_wizard(env: dict, force: bool = False) -> dict:
    print(f"""
{BOLD}{CYAN}── Environment Setup ────────────────────────────────────────────{RESET}
Values are saved to {BOLD}.env{RESET}.  Press Enter to keep the current value.
""")
    changes = {}

    # SECRET_KEY
    if force or not env.get("SECRET_KEY") or env["SECRET_KEY"] == "change_me_secret_key":
        print(f"  {DIM}SECRET_KEY — random key for CTFd session security{RESET}")
        changes["SECRET_KEY"] = prompt("SECRET_KEY", default=env.get("SECRET_KEY") or secrets.token_hex(32))

    # DB passwords
    for key, label, default in [
        ("MYSQL_ROOT_PASSWORD", "MariaDB root password", "FortiCTF-root-2026!"),
        ("MYSQL_PASSWORD",      "MariaDB CTFd password", "FortiCTF-ctfd-2026!"),
    ]:
        if force or not env.get(key) or env[key].startswith("change_me"):
            print(f"\n  {DIM}{label}{RESET}")
            changes[key] = prompt(key, default=env.get(key) or default, secret=True)

    # CTFD_ADMIN_TOKEN
    print(f"\n  {DIM}CTFD_ADMIN_TOKEN — generate after the CTFd setup wizard\n"
          f"  (Admin Panel → Settings → Tokens → Generate — leave blank for now){RESET}")
    val = prompt("CTFD_ADMIN_TOKEN", default=env.get("CTFD_ADMIN_TOKEN", ""), secret=True)
    if val or force:
        changes["CTFD_ADMIN_TOKEN"] = val

    # FQDN
    print(f"\n  {DIM}FQDN — your public domain name (e.g. samvblogs.duckdns.org)\n"
          f"  (only needed for HTTPS){RESET}")
    val = prompt("FQDN", default=env.get("FQDN", ""))
    if val or force:
        changes["FQDN"] = val

    # HTTPS_PORT
    print(f"\n  {DIM}HTTPS_PORT — TCP port for CTFd HTTPS\n"
          f"  (443 = standard, 4443 = non-privileged default){RESET}")
    val = prompt("HTTPS_PORT", default=env.get("HTTPS_PORT", "4443"))
    if val or force:
        changes["HTTPS_PORT"] = val

    # DUCKDNS_TOKEN
    print(f"\n  {DIM}DUCKDNS_TOKEN — from duckdns.org (only needed for HTTPS){RESET}")
    val = prompt("DUCKDNS_TOKEN", default=env.get("DUCKDNS_TOKEN", ""), secret=True)
    if val or force:
        changes["DUCKDNS_TOKEN"] = val

    if changes:
        write_env(changes)
        print(f"\n{GREEN}✅  .env updated.{RESET}")
    else:
        print(f"\n{DIM}No changes.{RESET}")

    return {**env, **changes}


# ── Menu ───────────────────────────────────────────────────────────────────────

def get_status() -> str:
    """Return a compact one-line status of key containers."""
    containers = {
        "forticnapp-ctfd":         "CTFd",
        "forticnapp-ctfd-db":      "DB",
        "forticnapp-ctfd-cache":   "Cache",
        "forticnapp-ctf-trigger":  "Trigger",
        "forticnapp-ctf-caddy":    "Caddy",
    }
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}\t{{.State}}"],
            capture_output=True, text=True, cwd=ROOT
        )
        running = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                running[parts[0].strip()] = parts[1].strip()
    except Exception:
        return f"  {DIM}(status unavailable){RESET}"

    parts = []
    for cname, label in containers.items():
        state = running.get(cname, "")
        if state == "running":
            parts.append(f"{GREEN}●{RESET} {label}")
        elif state:
            parts.append(f"{YELLOW}◐{RESET} {label}({state})")
        else:
            parts.append(f"{DIM}○ {label}{RESET}")
    return "  " + "   ".join(parts)


def build_menu(env: dict) -> str:
    token_ok   = bool(env.get("CTFD_ADMIN_TOKEN"))
    fqdn_ok    = bool(env.get("FQDN"))
    duckdns_ok = bool(env.get("DUCKDNS_TOKEN"))
    https_port = env.get("HTTPS_PORT") or "4443"
    fqdn       = env.get("FQDN") or "your-domain"

    token_warn   = f"  {YELLOW}⚠  CTFD_ADMIN_TOKEN not set — run step 1 first{RESET}" if not token_ok  else ""
    https_warn   = (
        f"  {YELLOW}⚠  FQDN or DUCKDNS_TOKEN not set — press s to configure{RESET}"
        if not (fqdn_ok and duckdns_ok) else ""
    )

    http_url  = f"http://localhost:8000"
    https_url = f"https://{fqdn}:{https_port}" if https_port != "443" else f"https://{fqdn}"

    status = get_status()
    return f"""
{BOLD}{RED}╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝{RESET}

{BOLD}STATUS{RESET}
{status}

  {BOLD}SETUP{RESET}
  {GREEN}s{RESET}  Configure .env  {DIM}(tokens, FQDN, HTTPS port, passwords){RESET}

  {BOLD}LIFECYCLE{RESET}
  {GREEN}1{RESET}  First boot      {DIM}→ CTFd only (complete wizard, then press s to add token){RESET}
  {GREEN}2{RESET}  Start HTTP      {DIM}→ {http_url}{RESET}{('  ' + token_warn) if token_warn else ''}
  {GREEN}3{RESET}  Start HTTPS     {DIM}→ {https_url}{RESET}{('  ' + https_warn) if https_warn else ''}
  {YELLOW}4{RESET}  Pause           {DIM}(stop containers, keep data){RESET}
  {YELLOW}5{RESET}  Stop Caddy      {DIM}(revert to HTTP only){RESET}
  {GREEN}6{RESET}  Restart         {DIM}(restart all running containers){RESET}
  {RED}7{RESET}  Full reset      {DIM}⚠️  wipes database + all scores{RESET}

  {BOLD}CHALLENGES{RESET}
  {CYAN}8{RESET}  Load CTF Lab    {DIM}(21 static challenges — no API needed){RESET}
  {CYAN}9{RESET}  Load Live CTF   {DIM}(credentials entered via web UI){RESET}

  {BOLD}MAINTENANCE{RESET}
  {DIM}10{RESET}  Health check
  {DIM}11{RESET}  CTFd logs
  {DIM}12{RESET}  Trigger logs
  {DIM}13{RESET}  Rebuild Trigger image
  {DIM}14{RESET}  Rebuild Static bridge image

  {DIM}q   Quit{RESET}
"""


COMMANDS = {
    "1":  ("First boot",            ["docker", "compose", "up", "-d", "db", "cache", "ctfd"]),
    "2":  ("Start HTTP",            ["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger"]),
    "3":  ("Start HTTPS",           ["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger", "caddy"]),
    "4":  ("Pause (keep data)",     ["docker", "compose", "stop"]),
    "5":  ("Stop Caddy",            ["docker", "compose", "stop", "caddy"]),
    "6":  ("Restart",               ["docker", "compose", "restart"]),
    "7":  ("Full reset",            ["docker", "compose", "down", "-v"]),
    "8":  ("Load CTF Lab",          ["docker", "compose", "run", "--rm", "bridge-static"]),
    "9":  ("Load Live CTF",         ["docker", "compose", "run", "--rm", "bridge"]),
    "10": ("Health check",          ["docker", "compose", "ps"]),
    "11": ("CTFd logs",             ["docker", "compose", "logs", "-f", "ctfd"]),
    "12": ("Trigger logs",          ["docker", "compose", "logs", "-f", "trigger"]),
    "13": ("Rebuild trigger",       ["docker", "compose", "build", "trigger"]),
    "14": ("Rebuild bridge-static", ["docker", "compose", "build", "bridge-static"]),
}

CONFIRM = {"7"}


def build_hints(env: dict) -> dict:
    fqdn       = env.get("FQDN") or "your-domain.duckdns.org"
    https_port = env.get("HTTPS_PORT") or "4443"
    https_url  = f"https://{fqdn}:{https_port}" if https_port != "443" else f"https://{fqdn}"
    return {
        "1": (
            f"\n{CYAN}Next steps:{RESET}\n"
            f"  1. Open {BOLD}http://localhost:8000{RESET} — complete the setup wizard\n"
            f"  2. Admin Panel → Settings → Tokens → Generate\n"
            f"  3. Press {BOLD}s{RESET} here to save the token to .env\n"
            f"  4. Choose {BOLD}option 2{RESET} (or 3 for HTTPS) to start fully"
        ),
        "2": f"\n{CYAN}CTFd is at{RESET} {BOLD}http://localhost:8000{RESET}",
        "3": f"\n{CYAN}CTFd is at{RESET} {BOLD}{https_url}{RESET}",
        "8": f"\n{CYAN}Challenges loaded — click{RESET} {BOLD}Start Challenges{RESET} on the home page",
        "9": f"\n{CYAN}Challenges loaded — click{RESET} {BOLD}Start Challenges{RESET} on the home page",
    }


def run(cmd: list[str]) -> None:
    print(f"\n{DIM}▶ {' '.join(cmd)}{RESET}\n")
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    os.chdir(ROOT)
    env = read_env()

    # First run — no .env or placeholder SECRET_KEY
    if not ENV.exists() or not env.get("SECRET_KEY") or env["SECRET_KEY"] == "change_me_secret_key":
        print(f"\n{YELLOW}No .env found (or SECRET_KEY not set) — let's set it up.{RESET}")
        env = setup_wizard(env)

    while True:
        env = read_env()
        print(build_menu(env))
        choice = input(f"{BOLD}Choose ▶ {RESET}").strip().lower()

        if choice in ("q", "quit", "exit"):
            print(f"{DIM}Bye.{RESET}")
            sys.exit(0)

        if choice == "s":
            env = setup_wizard(env, force=True)
            continue

        if choice not in COMMANDS:
            print(f"{RED}Unknown option — try again.{RESET}")
            continue

        label, cmd = COMMANDS[choice]

        if choice in CONFIRM:
            confirm = input(
                f"{RED}{BOLD}⚠️  {label} — this cannot be undone. Type YES to confirm: {RESET}"
            ).strip()
            if confirm != "YES":
                print(f"{YELLOW}Cancelled.{RESET}")
                continue

        run(cmd)

        hints = build_hints(env)
        if choice in hints:
            print(hints[choice])

        input(f"\n{DIM}Press Enter to return to menu…{RESET}")


if __name__ == "__main__":
    main()
