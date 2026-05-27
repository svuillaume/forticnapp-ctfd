#!/usr/bin/env python3
"""
FortiCNAPP CTF — control script
Run from the project root:  python ctl.py
"""

import os
import subprocess
import sys

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

MENU = f"""
{BOLD}{RED}╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝{RESET}

  {BOLD}START{RESET}
  {GREEN}1{RESET}  Start  (HTTP only)
  {GREEN}2{RESET}  Start  (HTTPS — requires DUCKDNS_TOKEN in .env)

  {BOLD}STOP{RESET}
  {YELLOW}3{RESET}  Stop   (keep data)
  {YELLOW}4{RESET}  Stop   Caddy only  (revert to HTTP)

  {BOLD}RESET{RESET}
  {RED}5{RESET}  Full reset  ⚠️  wipes database + all scores

  {BOLD}CHALLENGES{RESET}
  {CYAN}6{RESET}  Load CTF Lab     (21 static challenges, no API)
  {CYAN}7{RESET}  Load Live CTF    (from FortiCNAPP API)

  {BOLD}MAINTENANCE{RESET}
  {DIM}8{RESET}  Check container health
  {DIM}9{RESET}  Watch CTFd logs
  {DIM}10{RESET} Watch Trigger logs
  {DIM}11{RESET} Rebuild Trigger image
  {DIM}12{RESET} Rebuild Static bridge image

  {DIM}q  Quit{RESET}
"""

COMMANDS = {
    "1":  ("Start HTTP",            ["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger"]),
    "2":  ("Start HTTPS",           ["docker", "compose", "up", "-d", "db", "cache", "ctfd", "trigger", "caddy"]),
    "3":  ("Stop (keep data)",      ["docker", "compose", "down"]),
    "4":  ("Stop Caddy",            ["docker", "compose", "stop", "caddy"]),
    "5":  ("Full reset",            ["docker", "compose", "down", "-v"]),
    "6":  ("Load CTF Lab",          ["docker", "compose", "run", "--rm", "bridge-static"]),
    "7":  ("Load Live CTF",         ["docker", "compose", "run", "--rm", "bridge"]),
    "8":  ("Health check",          ["docker", "compose", "ps"]),
    "9":  ("CTFd logs",             ["docker", "compose", "logs", "-f", "ctfd"]),
    "10": ("Trigger logs",          ["docker", "compose", "logs", "-f", "trigger"]),
    "11": ("Rebuild trigger",       ["docker", "compose", "build", "trigger"]),
    "12": ("Rebuild bridge-static", ["docker", "compose", "build", "bridge-static"]),
}

CONFIRM = {"5"}   # choices that require a confirmation prompt


def run(cmd: list[str]) -> None:
    print(f"\n{DIM}▶ {' '.join(cmd)}{RESET}\n")
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")


def main() -> None:
    # Change to the script's directory so docker compose finds the project
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    while True:
        print(MENU)
        choice = input(f"{BOLD}Choose ▶ {RESET}").strip().lower()

        if choice in ("q", "quit", "exit"):
            print(f"{DIM}Bye.{RESET}")
            sys.exit(0)

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
        input(f"\n{DIM}Press Enter to return to menu…{RESET}")


if __name__ == "__main__":
    main()
