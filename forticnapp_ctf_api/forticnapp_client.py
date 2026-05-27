"""
FortiCNAPP / Lacework API v2 client.

Auth flow (per Fortinet docs):
  POST https://<account>.lacework.net/api/v2/access/tokens
       -X-LW-UAKS: <secret>
       { "keyId": "<keyId>", "expiryTime": 3600 }
  -> returns { "token": "...", "expiresAt": "..." }

Subsequent requests use:
  Authorization: Bearer <token>
  Account-Name:  <subaccount>   (optional; only when using sub-accounts)

Docs:
  https://docs.fortinet.com/document/forticnapp/latest/api-reference/802081/full-lacework-forticnapp-api-reference
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

log = logging.getLogger(__name__)


class FortiCNAPPError(RuntimeError):
    """Any non-retryable API failure."""


@dataclass
class FortiCNAPPClient:
    account: str
    key_id: str
    secret: str
    subaccount: str | None = None
    timeout: int = 30
    _token: str | None = field(default=None, init=False, repr=False)
    _token_expiry: float = field(default=0.0, init=False, repr=False)
    _session: requests.Session = field(default_factory=requests.Session, init=False, repr=False)

    @property
    def base_url(self) -> str:
        return f"https://{self.account}.lacework.net/api/v2"

    # ---- auth ----------------------------------------------------------------

    def _need_refresh(self) -> bool:
        # Refresh 60s before expiry to avoid edge-of-token failures
        return self._token is None or time.time() > (self._token_expiry - 60)

    @retry(
        reraise=True,
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _refresh_token(self) -> None:
        url = f"{self.base_url}/access/tokens"
        headers = {
            "X-LW-UAKS": self.secret,
            "Content-Type": "application/json",
        }
        body = {"keyId": self.key_id, "expiryTime": 3600}
        log.debug("POST %s (token refresh)", url)
        resp = self._session.post(url, json=body, headers=headers, timeout=self.timeout)
        if resp.status_code != 201 and resp.status_code != 200:
            raise FortiCNAPPError(
                f"Token refresh failed [{resp.status_code}]: {resp.text[:200]}"
            )
        data = resp.json()
        self._token = data["token"]
        # expiresAt is ISO-8601; fall back to +50min if missing
        try:
            exp = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
            self._token_expiry = exp.timestamp()
        except Exception:
            self._token_expiry = time.time() + 50 * 60
        log.info("FortiCNAPP token refreshed (expires %s)",
                 datetime.fromtimestamp(self._token_expiry, tz=timezone.utc).isoformat())

    def _auth_headers(self) -> dict[str, str]:
        if self._need_refresh():
            self._refresh_token()
        h = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if self.subaccount:
            h["Account-Name"] = self.subaccount
        return h

    # ---- low-level request --------------------------------------------------

    @retry(
        reraise=True,
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = self._session.post(
            url, json=body, headers=self._auth_headers(), timeout=self.timeout
        )
        if resp.status_code == 401:
            # Token may have been invalidated; force a refresh and retry once
            log.warning("401 from %s, forcing token refresh", path)
            self._token = None
            resp = self._session.post(
                url, json=body, headers=self._auth_headers(), timeout=self.timeout
            )
        if not resp.ok:
            raise FortiCNAPPError(
                f"POST {path} failed [{resp.status_code}]: {resp.text[:300]}"
            )
        # 204 No Content or genuinely empty body — treat as empty dataset
        if not resp.content:
            return {}
        return resp.json()

    @retry(
        reraise=True,
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = self._session.get(
            url, params=params, headers=self._auth_headers(), timeout=self.timeout
        )
        if resp.status_code == 401:
            self._token = None
            resp = self._session.get(
                url, params=params, headers=self._auth_headers(), timeout=self.timeout
            )
        if not resp.ok:
            raise FortiCNAPPError(
                f"GET {path} failed [{resp.status_code}]: {resp.text[:300]}"
            )
        return resp.json()

    # ---- public API ---------------------------------------------------------

    @staticmethod
    def _time_window(lookback_hours: int) -> tuple[str, str]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=lookback_hours)
        # Lacework expects ISO-8601 with millis + Z
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        return start.strftime(fmt), end.strftime(fmt)

    def get_alerts(self, lookback_hours: int = 72) -> list[dict[str, Any]]:
        start, end = self._time_window(lookback_hours)
        # GET /Alerts?startTime=...&endTime=...
        data = self._get("/Alerts", params={"startTime": start, "endTime": end})
        return data.get("data", [])

    def get_container_vulnerabilities(self, lookback_hours: int = 72) -> list[dict[str, Any]]:
        start, end = self._time_window(lookback_hours)
        # Note: omit the "status" filter — not all accounts use VULNERABLE status;
        # filter only on severity so we don't miss data.
        body = {
            "timeFilter": {"startTime": start, "endTime": end},
            "filters": [
                {"field": "severity", "expression": "in",
                 "values": ["Critical", "High"]},
            ],
            "returns": [
                "vulnId", "severity", "status", "imageId", "imageRepo",
                "imageTag", "fixInfo", "featureKey", "evalCtx",
            ],
        }
        try:
            data = self._post("/Vulnerabilities/Containers/search", body)
            return data.get("data", [])
        except FortiCNAPPError as e:
            log.warning("Container vulns endpoint failed (%s); returning empty set", e)
            return []

    def get_host_vulnerabilities(self, lookback_hours: int = 72) -> list[dict[str, Any]]:
        start, end = self._time_window(lookback_hours)
        body = {
            "timeFilter": {"startTime": start, "endTime": end},
            "filters": [
                {"field": "severity", "expression": "in",
                 "values": ["Critical", "High"]},
                {"field": "status", "expression": "eq", "value": "Active"},
            ],
            "returns": [
                "vulnId", "severity", "status", "machineTags",
                "fixInfo", "featureKey", "evalCtx",
            ],
        }
        try:
            data = self._post("/Vulnerabilities/Hosts/search", body)
            return data.get("data", [])
        except FortiCNAPPError as e:
            log.warning("Host vulns endpoint failed (%s); returning empty set", e)
            return []

    def get_compliance_violations(self, lookback_hours: int = 72) -> list[dict[str, Any]]:
        """Pull non-compliant policy violations via the Policies evaluation endpoint."""
        # Try the v2 policy violations search endpoint first
        body = {
            "filters": [
                {"field": "status", "expression": "eq", "value": "NonCompliant"},
            ],
            "returns": [
                "id", "title", "description", "severity", "status",
                "resource", "service", "account", "recommendation",
            ],
        }
        for path in (
            "/Configs/ComplianceEvaluations/search",
            "/ComplianceEvaluations/search",
            "/Configs/Policies/search",
        ):
            try:
                data = self._post(path, body)
                results = data.get("data", [])
                if results:
                    log.info("Compliance data from %s: %d records", path, len(results))
                    return results
            except FortiCNAPPError as e:
                log.debug("Compliance path %s failed: %s", path, e)

        # Last resort: pull all policies and use custom ones with severity set
        try:
            data = self._get("/Policies", params={"policyType": "Compliance"})
            policies = data.get("data", [])
            # Return policies that have severity as a proxy for "has violations"
            violations = [p for p in policies if p.get("severity") in
                         ("critical", "high", "medium") and p.get("title")]
            log.info("Fell back to /Policies: %d compliance policies found", len(violations))
            return violations[:50]
        except FortiCNAPPError as e:
            log.warning("All compliance endpoints failed (%s); returning empty set", e)
            return []


# --- factory --------------------------------------------------------------

def from_env() -> FortiCNAPPClient:
    """Build a client from environment variables."""
    missing = [
        v for v in ("FORTICNAPP_ACCOUNT", "FORTICNAPP_API_KEY_ID", "FORTICNAPP_API_SECRET")
        if not os.environ.get(v)
    ]
    if missing:
        raise FortiCNAPPError(
            "Missing required env vars: " + ", ".join(missing) +
            ". Set MOCK_MODE=true to run without a real tenant."
        )
    return FortiCNAPPClient(
        account=os.environ["FORTICNAPP_ACCOUNT"],
        key_id=os.environ["FORTICNAPP_API_KEY_ID"],
        secret=os.environ["FORTICNAPP_API_SECRET"],
        subaccount=os.environ.get("FORTICNAPP_SUBACCOUNT") or None,
    )
