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

    def list_challenges(self) -> list[dict[str, Any]]:
        data = self._get("/api/v1/challenges", params={"view": "admin"})
        return data.get("data", [])

    def list_challenge_names(self) -> set[str]:
        return {c["name"] for c in self.list_challenges()}

    def _delete(self, path: str) -> None:
        r = self.session.delete(f"{self.base_url}{path}", timeout=self.timeout)
        if not r.ok:
            log.warning("DELETE %s failed [%d]: %s", path, r.status_code, r.text[:100])

    def purge_dynamic_challenges(self) -> int:
        """Delete all challenges tagged 'dynamic' (created by the live bridge)."""
        all_chals = self.list_challenges()
        deleted = 0
        for ch in all_chals:
            cid = ch["id"]
            try:
                tags_data = self._get(f"/api/v1/challenges/{cid}/tags")
                tags = [t.get("value", "") for t in tags_data.get("data", [])]
                if "dynamic" in tags:
                    self._delete(f"/api/v1/challenges/{cid}")
                    log.info("Deleted dynamic challenge [%d]: %s", cid, ch.get("name"))
                    deleted += 1
            except Exception as e:
                log.warning("Could not inspect/delete challenge %d: %s", cid, e)
        return deleted

    # --- create -----------------------------------------------------------

    # CTFd enforces a max challenge name length of 80 characters
    _MAX_NAME = 80

    def create_challenge(self, ch: Challenge) -> int:
        """Create a challenge + its flags + tags + hints. Returns the new id."""
        name = ch.name
        if len(name) > self._MAX_NAME:
            name = name[:self._MAX_NAME - 1] + "…"
        payload = {
            "name": name,
            "category": ch.category,
            "description": ch.description,
            "value": ch.value,
            "type": ch.type,
            "state": ch.state,
        }
        log.info("POST /api/v1/challenges  name=%r value=%d", name, ch.value)
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

    _MODE_BANNER_JS = """
<script>
(function(){try{
  localStorage.setItem('fctf_mode','live-ctf');
  function _mb(){
    if(document.getElementById('_fctf_mode_bar'))return;
    var p=location.pathname;if(p==='/'||p==='')return;
    var b=document.createElement('div');b.id='_fctf_mode_bar';
    b.style.cssText='background:rgba(0,176,204,0.12);border-bottom:2px solid #00b0cc;'+
      'padding:0.4rem 1rem;text-align:center;font-family:Inter,system-ui,sans-serif;'+
      'font-size:0.78rem;font-weight:700;letter-spacing:0.07em;text-transform:uppercase;color:#00b0cc;';
    b.innerHTML='&#128225; Live CTF &nbsp;&mdash;&nbsp; <span style="font-weight:400;text-transform:none;'+
      'letter-spacing:0;opacity:0.85">Challenges from your FortiCNAPP tenant &nbsp;&bull;&nbsp; '+
      '<a href="/" style="color:#00b0cc;opacity:0.7">&#8592; Back to mode selector</a></span>';
    var n=document.querySelector('nav.navbar')||document.querySelector('nav');
    if(n&&n.parentNode)n.parentNode.insertBefore(b,n.nextSibling);
    else document.body.insertBefore(b,document.body.firstChild);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',_mb);else _mb();
}catch(e){}})();
</script>"""

    def apply_fortinet_theme(self) -> None:
        """Push Fortinet brand CSS + Live CTF mode banner JS to CTFd theme_header."""
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
            "ctf_name": "Live CTF — FortiCNAPP CTF",
            "ctf_description": "Challenges generated from your live FortiCNAPP tenant.",
        }
        if css:
            payload["theme_header"] = f"<style>\n{css}\n</style>\n{self._MODE_BANNER_JS}"

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

    def push_many(self, challenges: list[Challenge], refresh: bool = False) -> dict[str, int]:
        if refresh:
            deleted = self.purge_dynamic_challenges()
            log.info("Refresh: purged %d existing dynamic challenge(s)", deleted)

        # Build a map of name → id for any remaining challenges
        all_chals = self.list_challenges()
        existing_by_name = {c["name"]: c["id"] for c in all_chals}

        stats = {"created": 0, "skipped": 0, "failed": 0}
        for ch in challenges:
            name = ch.name
            if len(name) > self._MAX_NAME:
                name = name[:self._MAX_NAME - 1] + "…"

            if name in existing_by_name:
                if refresh:
                    # In refresh mode, delete the old one and recreate fresh
                    self._delete(f"/api/v1/challenges/{existing_by_name[name]}")
                    log.info("Refresh: replaced existing challenge: %s", name)
                else:
                    log.info("Skip (already exists): %s", name)
                    stats["skipped"] += 1
                    continue
            try:
                self.create_challenge(ch)
                stats["created"] += 1
            except CTFdError as e:
                log.error("Failed to create %r: %s", name, e)
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
