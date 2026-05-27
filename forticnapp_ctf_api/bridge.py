"""
Bridge entrypoint - one-shot job.

  docker compose run --rm bridge

Flow:
  1. Pull findings from FortiCNAPP (or load mock data if MOCK_MODE=true).
  2. Sanitize findings if SANITIZE=true (default - required for customer demos).
  3. Build CTFd challenges from the (sanitized) findings.
  4. Push them into CTFd via the admin API, skipping duplicates.
  5. Print a summary.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from . import challenges as ch_mod
from . import ctfd_client
from . import forticnapp_client
from .sanitize import Sanitizer

SAMPLE_DATA_DIR = Path(os.environ.get("SAMPLE_DATA_DIR", "/app/sample_data"))


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _setup_logging() -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    )


def _load_mock(name: str) -> list[dict[str, Any]]:
    p = SAMPLE_DATA_DIR / f"{name}.json"
    if not p.exists():
        logging.getLogger("bridge").warning("Mock file missing: %s", p)
        return []
    with p.open() as f:
        data = json.load(f)
    return data.get("data", data) if isinstance(data, dict) else data


def pull_findings(mock: bool, lookback_hours: int) -> dict[str, list[dict[str, Any]]]:
    log = logging.getLogger("bridge")
    if mock:
        log.info("MOCK_MODE=true - loading fixtures from %s", SAMPLE_DATA_DIR)
        return {
            "alerts": _load_mock("alerts"),
            "container_vulns": _load_mock("container_vulns"),
            "host_vulns": _load_mock("host_vulns"),
            "compliance": _load_mock("compliance"),
        }

    log.info("Connecting to FortiCNAPP (lookback=%dh)", lookback_hours)
    fc = forticnapp_client.from_env()
    return {
        "alerts": fc.get_alerts(lookback_hours),
        "container_vulns": fc.get_container_vulnerabilities(lookback_hours),
        "host_vulns": fc.get_host_vulnerabilities(lookback_hours),
        "compliance": fc.get_compliance_violations(lookback_hours),
    }


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    log = logging.getLogger("bridge")

    mock = _truthy(os.environ.get("MOCK_MODE", "false"))
    sanitize = _truthy(os.environ.get("SANITIZE", "true"))
    lookback = int(os.environ.get("LOOKBACK_HOURS", "72"))
    max_per_cat = int(os.environ.get("MAX_CHALLENGES_PER_CATEGORY", "5"))

    log.info(
        "Run config: MOCK_MODE=%s SANITIZE=%s LOOKBACK_HOURS=%d MAX_PER_CAT=%d",
        mock, sanitize, lookback, max_per_cat,
    )

    # ---- pull
    findings = pull_findings(mock, lookback)
    counts = {k: len(v) for k, v in findings.items()}
    log.info("Pulled findings: %s", counts)

    if not any(findings.values()):
        log.error("No findings returned. Check API credentials, lookback "
                  "window, or enable MOCK_MODE for a smoke test.")
        return 2

    # ---- sanitize
    if sanitize:
        scrubber = Sanitizer(enabled=True)
        findings = {k: scrubber.scrub(v) for k, v in findings.items()}
        log.info("Sanitization applied (%d unique values mapped)",
                 len(scrubber._mapping))
    else:
        log.warning("SANITIZE=false - findings will leak tenant data into "
                    "the CTF. Only safe for internal use!")

    # ---- build
    chals = ch_mod.build_all(
        alerts=findings["alerts"],
        container_vulns=findings["container_vulns"],
        host_vulns=findings["host_vulns"],
        compliance=findings["compliance"],
        max_per_category=max_per_cat,
    )
    log.info("Built %d challenges total", len(chals))
    if not chals:
        log.error("No challenges could be generated from the findings "
                  "available. Inspect findings shape or relax filters.")
        return 3

    # ---- push
    # refresh=True: delete any previously generated dynamic challenges first,
    # so every run gives fresh content from the latest FortiCNAPP findings.
    refresh = _truthy(os.environ.get("REFRESH_DYNAMIC", "true"))
    cli = ctfd_client.from_env()
    cli.wait_until_ready()
    cli.apply_fortinet_theme()
    stats = cli.push_many(chals, refresh=refresh)
    log.info("Push complete: %s", stats)

    if stats["failed"] > 0:
        log.warning("%d challenge(s) failed to create — build still considered successful.", stats["failed"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
