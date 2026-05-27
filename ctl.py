#!/usr/bin/env python3
"""
FortiCNAPP CTF — main control script
Run from the project root:  python ctl.py
"""

import os
import re
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

# ── .env read / write helpers ──────────────────────────────────────────────────

def read_env() -> dict:
    """Parse .env into a dict (ignores comments and blank lines)."""
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
    """Merge values into .env, preserving comments and existing entries."""
    if ENV.exists():
        lines = ENV.read_text().splitlines()
    else:
        lines = []

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

    # Append any keys not already in the file
    for k, v in values.items():
        if k not in updated:
            new_lines.append(f"{k}={v}")

    ENV.write_text("\n".join(new_lines) + "\n")


def prompt(label: str, default: str = "", secret: bool = False, required: bool = False) -> str:
    """Prompt the user for a value, returning default on empty input."""
    hint = f" [{DIM}{'*****' if secret and default else default or 'optional'}{RESET}]" if default or not required else f" [{RED}required{RESET}]"
    while True:
        val = input(f"  {label}{hint}: ").strip()
        if val:
            return val
        if default:
            return default
        if not required:
            return ""
        print(f"  {RED}This field is required.{RESET}")


# ── First-time / refresh setup wizard ─────────────────────────────────────────

def setup_wizard(env: dict, force: bool = False) -> dict:
    """
    Interactive wizard to fill in .env values.
    Only prompts for fields that are empty (or all fields if force=True).
    """
    print(f"""
{BOLD}{CYAN}── Environment Setup ────────────────────────────────────────────{RESET}
Values are saved to {BOLD}.env{RESET}.  Press Enter to keep the current value.
""")

    changes = {}

    # SECRET_KEY — auto-generate if missing
    if force or not env.get("SECRET_KEY") or env["SECRET_KEY"] == "change_me_secret_key":
        suggested = secrets.token_hex(32)
        print(f"  {DIM}SECRET_KEY — random key for CTFd session security{RESET}")
        val = prompt("SECRET_KEY", default=suggested)
        changes["SECRET_KEY"] = val

    # DB passwords
    for key, label, default in [
        ("MYSQL_ROOT_PASSWORD", "MariaDB root password", "FortiCTF-root-2026!"),
        ("MYSQL_PASSWORD",      "MariaDB CTFd password", "FortiCTF-ctfd-2026!"),
    ]:
        if force or not env.get(key) or env[key].startswith("change_me"):
            print(f"\n  {DIM}{label}{RESET}")
            changes[key] = prompt(key, default=env.get(key) or default, secret=True)

    # CTFD_ADMIN_TOKEN — optional at this stage
    print(f"""
  {DIM}CTFD_ADMIN_TOKEN — generate this AFTER the CTFd setup wizard:
  Admin Panel → Settings → Tokens → Generate
  Leave blank for now if CTFd has not started yet.{RESET}""")
    val = prompt("CTFD_ADMIN_TOKEN", default=env.get("CTFD_ADMIN_TOKEN", ""), secret=True)
    if val or force:
        changes["CTFD_ADMIN_TOKEN"] = val

    # DUCKDNS_TOKEN — optional
    print(f"\n  {DIM}DUCKDNS_TOKEN — only needed for HTTPS (optional){RESET}")
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

def build_menu(env: dict) -> str:
    token_ok  = bool(env.get("CTFD_ADMIN_TOKEN"))
    duckdns_ok = bool(env.get("DUCKDNS_TOKEN"))

    token_warn  = "" if token_ok  else f" {YELLOW}⚠ CTFD_ADMIN_TOKEN not set{RESET}"
    duckdns_warn = "" if duckdns_ok else f" {YELLOW}⚠ DUCKDNS_TOKEN not set{RESET}"

    return f"""
{BOLD}{RED}╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝{RESET}

  {BOLD}FIRST TIME?{RESET}
  {GREEN}1{RESET}  First boot    {DIM}→ starts CTFd only, then run setup wizard{RESET}
  {GREEN}s{RESET}  Edit .env     {DIM}→ update SECRET_KEY / tokens / passwords{RESET}

  {BOLD}START{RESET}
  {GREEN}2{RESET}  Start HTTP    {DIM}(CTFd + Trigger){RESET}{token_warn}
  {GREEN}3{RESET}  Start HTTPS   {DIM}(+ Caddy){RESET}{token_warn}{duckdns_warn}

  {BOLD}STOP{RESET}
  {YELLOW}4{RESET}  Stop          {DIM}(keep data){RESET}
  {YELLOW}5{RESET}  Stop Caddy    {DIM}(revert to HTTP){RESET}

  {BOLD}RESET{RESET}
  {RED}6{RESET}  Full reset    {DIM}⚠️  wipes database + all scores{RESET}

  {BOLD}CHALLENGES{RESET}
  {CYAN}7{RESET}  Load CTF Lab  {DIM}(21 static challenges, no API){RESET}
  {CYAN}8{RESET}  Load Live CTF {DIM}(credentials entered via web UI){RESET}

  {BOLD}MAINTENANCE{RESET}
  {DIM}9{RESET}   Check container health
  {DIM}10{RESET}  Watch CTFd logs
  {DIM}11{RESET}  Watch Trigger logs
  {DIM}12{RESET}  Rebuild Trigger image
  {DIM}13{RESET}  Rebuild Static bridge image

  {DIM}q   Quit{RESET}
"""

COMMANDS = {
    "1":  ("First boot (CTFd only)",    ["docker", "compose", "up", "-d", "db", "cache", "ctfd"]),
    "2":  ("Start HTTP",                ["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger"]),
    "3":  ("Start HTTPS",               ["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger", "caddy"]),
    "4":  ("Stop (keep data)",          ["docker", "compose", "down"]),
    "5":  ("Stop Caddy",                ["docker", "compose", "stop", "caddy"]),
    "6":  ("Full reset",                ["docker", "compose", "down", "-v"]),
    "7":  ("Load CTF Lab",              ["docker", "compose", "run", "--rm", "bridge-static"]),
    "8":  ("Load Live CTF",             ["docker", "compose", "run", "--rm", "bridge"]),
    "9":  ("Health check",              ["docker", "compose", "ps"]),
    "10": ("CTFd logs",                 ["docker", "compose", "logs", "-f", "ctfd"]),
    "11": ("Trigger logs",              ["docker", "compose", "logs", "-f", "trigger"]),
    "12": ("Rebuild trigger",           ["docker", "compose", "build", "trigger"]),
    "13": ("Rebuild bridge-static",     ["docker", "compose", "build", "bridge-static"]),
}

CONFIRM = {"6"}

HINTS = {
    "1": (
        f"\n{CYAN}Next steps:{RESET}\n"
        f"  1. Open {BOLD}http://localhost:8000{RESET} and complete the setup wizard\n"
        f"  2. Admin Panel → Settings → Tokens → Generate\n"
        f"  3. Come back here and press {BOLD}s{RESET} to paste the token into .env\n"
        f"  4. Then choose {BOLD}option 2{RESET} to start the trigger service"
    ),
    "2": f"\n{CYAN}Open{RESET} {BOLD}http://localhost:8000{RESET}",
    "3": f"\n{CYAN}Open{RESET} {BOLD}https://your-domain.duckdns.org{RESET}",
    "7": f"\n{CYAN}Challenges loaded — click{RESET} {BOLD}Start Challenges{RESET} on the home page",
    "8": f"\n{CYAN}Challenges loaded — click{RESET} {BOLD}Start Challenges{RESET} on the home page",
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

    # First run — .env missing or SECRET_KEY is a placeholder
    if not ENV.exists() or not env.get("SECRET_KEY") or env["SECRET_KEY"] == "change_me_secret_key":
        print(f"\n{YELLOW}No .env found (or SECRET_KEY not set) — let's set it up.{RESET}")
        env = setup_wizard(env)

    while True:
        # Reload env on every loop iteration so warnings update after edits
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

        if choice in HINTS:
            print(HINTS[choice])

        input(f"\n{DIM}Press Enter to return to menu…{RESET}")


if __name__ == "__main__":
    main()
