"""
CTFd admin API pusher.

Uses CTFd's REST API (v1) with an admin token from
  Admin Panel -> Settings -> Tokens.

Reference: https://docs.ctfd.io/docs/api/redoc

Idempotent: a challenge with the same `name` is skipped (we do not patch
existing challenges, to avoid trampling event-day customizations).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .challenges import Challenge

log = logging.getLogger(__name__)


class CTFdError(RuntimeError):
    pass


class CTFdClient:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    # --- wait for CTFd to be reachable ----------------------------------

    def wait_until_ready(self, max_wait_s: int = 120) -> None:
        deadline = time.time() + max_wait_s
        last_err: Exception | None = None
        while time.time() < deadline:
            try:
                r = self.session.get(f"{self.base_url}/api/v1/users/me",
                                     timeout=5)
                # 200 = authenticated, 403 = reachable but token invalid,
                # 401 = also reachable.
                if r.status_code in (200, 401, 403):
                    log.info("CTFd is reachable at %s (status %d)",
                             self.base_url, r.status_code)
                    if r.status_code in (401, 403):
                        raise CTFdError(
                            "CTFd is up but the admin token is rejected. "
                            "Generate a fresh token in Admin Panel -> Settings "
                            "-> Tokens and put it in CTFD_ADMIN_TOKEN."
                        )
                    return
            except requests.RequestException as e:
                last_err = e
            time.sleep(3)
        raise CTFdError(
            f"CTFd not reachable at {self.base_url} after {max_wait_s}s: {last_err}"
        )

    # --- helpers --------------------------------------------------------

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self.session.get(f"{self.base_url}{path}", params=params,
                             timeout=self.timeout)
        if not r.ok:
            raise CTFdError(f"GET {path} failed [{r.status_code}]: {r.text[:300]}")
        return r.json()

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.session.post(f"{self.base_url}{path}", json=body,
                              timeout=self.timeout)
        if not r.ok:
            raise CTFdError(f"POST {path} failed [{r.status_code}]: {r.text[:300]}")
        return r.json()

    # --- existing challenge lookup --------------------------------------

    def list_challenge_names(self) -> set[str]:
        data = self._get("/api/v1/challenges", params={"view": "admin"})
        return {c["name"] for c in data.get("data", [])}

    # --- create -----------------------------------------------------------

    def create_challenge(self, ch: Challenge) -> int:
        """Create a challenge + its flags + tags + hints. Returns the new id."""
        payload = {
            "name": ch.name,
            "category": ch.category,
            "description": ch.description,
            "value": ch.value,
            "type": ch.type,
            "state": ch.state,
        }
        log.info("POST /api/v1/challenges  name=%r value=%d", ch.name, ch.value)
        created = self._post("/api/v1/challenges", payload)
        challenge_id = created["data"]["id"]

        # Flags
        for f in ch.flags:
            flag_payload = {
                "challenge": challenge_id,
                "content": f.content,
                "type": f.type,
                "data": "case_insensitive" if f.case_insensitive else "",
            }
            self._post("/api/v1/flags", flag_payload)

        # Tags
        for tag in ch.tags:
            self._post("/api/v1/tags", {"challenge": challenge_id, "value": tag})

        # Hints (0-cost, freely visible — tune as needed)
        for hint in ch.hints:
            self._post("/api/v1/hints", {
                "challenge": challenge_id,
                "content": hint,
                "cost": 0,
            })

        return challenge_id

    # --- branding -------------------------------------------------------

    FORTINET_CSS_PATH = "/app/forticnapp_ctf_api/theme/fortinet.css"

    def apply_fortinet_theme(self) -> None:
        """Push Fortinet brand CSS + event name to CTFd appearance settings."""
        css = ""
        # Try reading the CSS from the mounted theme file
        import pathlib
        for candidate in (
            self.FORTINET_CSS_PATH,
            "/app/theme/fortinet.css",
            "/opt/CTFd/CTFd/themes/core/static/custom/fortinet.css",
        ):
            p = pathlib.Path(candidate)
            if p.exists():
                css = p.read_text()
                log.info("Applying Fortinet theme CSS from %s", candidate)
                break

        # CTFd base.html renders {{ Configs.theme_header }} — NOT {{ Configs.css }}.
        # The "css" config key is stored but never output to the page.
        # Wrap the CSS in a <style> block and push it to theme_header.
        payload: dict[str, str] = {
            "ctf_name": "FortiCNAPP Cloud Defender Challenge",
            "ctf_description": "Triage real cloud threats. Powered by FortiCNAPP.",
        }
        if css:
            payload["theme_header"] = f"<style>\n{css}\n</style>"

        try:
            r = self.session.patch(
                f"{self.base_url}/api/v1/configs",
                json=payload,
                timeout=self.timeout,
            )
            if r.ok:
                log.info("Fortinet theme applied (CSS=%d chars)", len(css))
            else:
                log.warning("Theme apply failed [%d]: %s", r.status_code, r.text[:200])
        except Exception as e:
            log.warning("Could not apply theme: %s", e)

    # --- bulk -----------------------------------------------------------

    def push_many(self, challenges: list[Challenge]) -> dict[str, int]:
        existing = self.list_challenge_names()
        stats = {"created": 0, "skipped": 0, "failed": 0}
        for ch in challenges:
            if ch.name in existing:
                log.info("Skip (already exists): %s", ch.name)
                stats["skipped"] += 1
                continue
            try:
                self.create_challenge(ch)
                stats["created"] += 1
            except CTFdError as e:
                log.error("Failed to create %r: %s", ch.name, e)
                stats["failed"] += 1
        return stats


def from_env() -> CTFdClient:
    url = os.environ.get("CTFD_API_URL", "http://ctfd:8000")
    token = os.environ.get("CTFD_ADMIN_TOKEN")
    if not token:
        raise CTFdError(
            "CTFD_ADMIN_TOKEN is not set. After first CTFd boot, generate a "
            "token in Admin Panel -> Settings -> Tokens and put it in .env."
        )
    return CTFdClient(url, token)
