"""
Sanitization layer.

CRITICAL: Customer-facing demos must never leak the tenant's real account
IDs, ARNs, IPs, hostnames, emails, or bucket names. This module walks a
findings list/dict and replaces customer-identifiable data with stable,
realistic-looking placeholders.

Design choices:
- Stable mapping per run (same real value -> same fake value) so a single
  challenge stays internally consistent (e.g. the same fake bucket name
  appears in both the alert title and the resource field).
- Realistic placeholders (not "REDACTED") so the challenges still look like
  authentic findings to participants.
- Never reverses: this is one-way scrubbing for display only.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# --- patterns ---------------------------------------------------------------

AWS_ACCOUNT_RE = re.compile(r"\b\d{12}\b")
AWS_ARN_RE = re.compile(r"arn:aws[\w-]*:[\w-]*:[\w-]*:(\d{12})?:[^\s\"']+")
AZURE_SUB_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
GCP_PROJECT_RE = re.compile(r"\bprojects/([a-z][a-z0-9-]{4,28}[a-z0-9])\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.){1,}(?:com|net|org|io|cloud|internal|local|aws|azure|gcp)\b"
)
S3_BUCKET_HINT_RE = re.compile(r"(s3://|arn:aws:s3:::)([a-z0-9.\-]{3,63})")

# Demo-safe placeholders
FAKE_ACCOUNTS = [
    "210987654321", "112233445566", "998877665544", "555000111222",
    "444333222111", "777666555444",
]
FAKE_AZURE_SUBS = [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
    "00000000-0000-4000-8000-000000000003",
]
FAKE_GCP_PROJECTS = ["acme-prod-1", "acme-staging-2", "acme-shared-3"]
FAKE_BUCKETS = [
    "acme-public-assets", "acme-logs-archive", "acme-backups-cold",
    "acme-data-lake", "acme-cdn-origin",
]
FAKE_DOMAINS = ["acme.example.com", "internal.acme.example.com", "api.acme.example.com"]
FAKE_EMAILS = ["alice@acme.example.com", "bob@acme.example.com",
               "ops@acme.example.com"]


class Sanitizer:
    """One sanitizer instance = one consistent mapping for a CTF run."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._mapping: dict[str, str] = {}

    # --- helpers ---------------------------------------------------------

    def _stable_pick(self, key: str, pool: list[str]) -> str:
        """Pick a deterministic placeholder for a real value."""
        if key in self._mapping:
            return self._mapping[key]
        h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        choice = pool[h % len(pool)]
        # Disambiguate if collision (same fake for two reals)
        if choice in self._mapping.values():
            choice = f"{choice}-{h % 1000:03d}"
        self._mapping[key] = choice
        return choice

    # --- scrubbers -------------------------------------------------------

    def _scrub_string(self, s: str) -> str:
        if not isinstance(s, str) or not s:
            return s

        # Order matters: ARN first (it contains an account ID), then standalone IDs
        def _arn(m: re.Match) -> str:
            arn = m.group(0)
            # rebuild ARN with fake account
            real_acct = m.group(1) or ""
            if real_acct:
                fake_acct = self._stable_pick(real_acct, FAKE_ACCOUNTS)
                arn = arn.replace(real_acct, fake_acct)
            return arn
        s = AWS_ARN_RE.sub(_arn, s)

        s = AWS_ACCOUNT_RE.sub(
            lambda m: self._stable_pick(m.group(0), FAKE_ACCOUNTS), s
        )
        s = AZURE_SUB_RE.sub(
            lambda m: self._stable_pick(m.group(0), FAKE_AZURE_SUBS), s
        )
        s = GCP_PROJECT_RE.sub(
            lambda m: "projects/" + self._stable_pick(m.group(1), FAKE_GCP_PROJECTS), s
        )
        s = S3_BUCKET_HINT_RE.sub(
            lambda m: m.group(1) + self._stable_pick(m.group(2), FAKE_BUCKETS), s
        )
        # IPs: keep RFC1918 / loopback as-is (those are demo-safe & informative),
        # only fake public IPs.
        def _ip(m: re.Match) -> str:
            ip = m.group(0)
            octets = ip.split(".")
            try:
                if (octets[0] == "10"
                        or (octets[0] == "192" and octets[1] == "168")
                        or (octets[0] == "172" and 16 <= int(octets[1]) <= 31)
                        or octets[0] == "127"):
                    return ip
            except ValueError:
                return ip
            return self._stable_pick(ip, ["203.0.113.10", "198.51.100.42", "192.0.2.77"])
        s = IPV4_RE.sub(_ip, s)

        s = EMAIL_RE.sub(
            lambda m: self._stable_pick(m.group(0), FAKE_EMAILS), s
        )
        s = HOSTNAME_RE.sub(
            lambda m: (m.group(0) if m.group(0).endswith(".local")
                       else self._stable_pick(m.group(0), FAKE_DOMAINS)),
            s,
        )
        return s

    # --- public API ------------------------------------------------------

    def scrub(self, obj: Any) -> Any:
        if not self.enabled:
            return obj
        if isinstance(obj, str):
            return self._scrub_string(obj)
        if isinstance(obj, dict):
            return {k: self.scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.scrub(v) for v in obj]
        return obj
