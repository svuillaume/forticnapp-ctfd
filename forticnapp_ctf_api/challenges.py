"""
Challenge generator.

Maps FortiCNAPP findings to CTFd challenges.  Each generator emits a
`Challenge` dataclass that the CTFd pusher knows how to ship.

Categories
----------
- Alert Triage          : real alerts -> MITRE technique, severity, category
- Container Security    : "find the CVE that... ", "what package is affected?"
- Host Security         : same, but for hosts
- Cloud Compliance      : CIS control or service/severity questions

Flag style
----------
We follow the canonical `FLAG{...}` convention. Static flags are used for
exact answers (a CVE ID, a control number); regex flags are used when
several phrasings are acceptable.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

log = logging.getLogger(__name__)


SEVERITY_POINTS = {
    "Critical": 500,
    "High": 300,
    "Medium": 200,
    "Low": 100,
    "Info": 50,
}

CATEGORY_NARRATIVE = {
    "Alert Triage": (
        "You are the on-call SOC analyst at Acme Corp. FortiCNAPP just "
        "raised the alert below. Investigate and answer."
    ),
    "Container Security": (
        "Your DevOps team pushed a new container image; FortiCNAPP flagged "
        "a vulnerability. Use the finding to answer."
    ),
    "Host Security": (
        "FortiCNAPP's host agent reported a vulnerability on a production "
        "workload. Triage the finding."
    ),
    "Cloud Compliance": (
        "FortiCNAPP's CSPM engine flagged a non-compliant configuration in "
        "your cloud account. Identify the gap."
    ),
}


@dataclass
class Flag:
    content: str
    type: str = "static"  # "static" | "regex"
    case_insensitive: bool = True


@dataclass
class Challenge:
    name: str
    category: str
    description: str
    value: int
    flags: list[Flag] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    state: str = "visible"
    type: str = "standard"


# --- helpers ---------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CIS_CTRL_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def _first_cve(text: str) -> str | None:
    if not text:
        return None
    m = _CVE_RE.search(text)
    return m.group(0).upper() if m else None


def _wrap_flag(answer: str) -> str:
    """Wrap an answer in the canonical FLAG{...} format."""
    return "FLAG{" + answer.strip() + "}"


def _safe_name(s: str, limit: int = 32) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit].rstrip(" .,:-")


def _sev_points(sev: str) -> int:
    return SEVERITY_POINTS.get(sev.capitalize(), 200)


# --- alert -> challenge ---------------------------------------------------

def _extract_mitre_technique(alert: dict[str, Any]) -> str | None:
    """Extract the first MITRE technique ID (T####) from an alert."""
    mitre = (
        alert.get("alertModel", {}).get("mitre", {}).get("techniqueId")
        or (alert.get("alertInfo") or {}).get("mitreTechniqueId")
    )
    if mitre:
        return mitre.upper()
    for entry in alert.get("tagMetadata", []):
        tid = (entry.get("tagMetadata") or {}).get("id", "")
        if tid.startswith("T") and not tid.startswith("TA") and tid[1:].replace(".", "").isdigit():
            return tid.upper()
    return None


def _alert_ctf_category(alert: dict[str, Any]) -> str:
    """
    Map a FortiCNAPP alert to a CTFd challenge category.
    Uses the FortiCNAPP alertCategory directly so challenges are grouped
    by their real domain (IAM, CloudActivity, User, etc.).
    Falls back to 'Alert Triage' if no category is available.
    """
    derived = alert.get("derivedFields") or {}
    info    = alert.get("alertInfo") or {}
    cat = (
        alert.get("alertCategory")
        or derived.get("category")
        or derived.get("source")
        or info.get("category")
        or ""
    ).strip()
    return cat if cat else "Alert Triage"


def alert_to_challenge(alert: dict[str, Any]) -> Challenge | None:
    """
    Build an Alert Triage challenge from a FortiCNAPP alert.
    The CTFd category is derived from the alert's own category field
    (IAM, CloudActivity, User, Composite, etc.) so challenges are grouped
    by their real domain on the challenge board.

    Priority order:
      1. MITRE technique ID  (most educational)
      2. Alert severity
      3. Alert category / source
    """
    name = alert.get("alertName") or alert.get("name") or ""
    if not name:
        return None

    sev_raw = alert.get("severity", "Medium")
    sev     = sev_raw.capitalize()
    info    = alert.get("alertInfo") or {}
    description_text = info.get("description") or alert.get("description") or ""
    derived = alert.get("derivedFields") or {}

    # Resolve the CTFd category from the alert's own category field
    ctf_category = _alert_ctf_category(alert)
    category = (
        alert.get("alertCategory")
        or derived.get("category")
        or derived.get("source")
        or info.get("category")
        or ""
    )

    # ── variant 1: MITRE technique ───────────────────────────────────────
    mitre = _extract_mitre_technique(alert)
    if mitre:
        desc = f"""### Scenario
{CATEGORY_NARRATIVE['Alert Triage']}

### Alert
- **Name**: {name}
- **Category**: {ctf_category}
- **Severity**: {sev}
- **Summary**: {description_text or '_(no summary available)_'}

### Question
Based on this alert, which MITRE ATT&CK **Technique ID** is FortiCNAPP
attributing this activity to? (e.g. `T1078`)

### Flag format
`FLAG{{T####}}` — technique ID only, no tactic prefix.
"""
        return Challenge(
            name=f"{_safe_name(name)}",
            category=ctf_category,
            description=desc,
            value=_sev_points(sev),
            flags=[Flag(content=_wrap_flag(mitre), type="static")],
            tags=["forticnapp", "alert", "mitre", sev.lower(), "dynamic"],
            hints=[
                "Look at the MITRE ATT&CK tag on the FortiCNAPP alert — "
                "technique IDs start with T followed by 4 digits.",
                f"The technique is: {mitre}",
            ],
        )

    # ── variant 2: severity as the answer ────────────────────────────────
    if description_text and sev.lower() in ("critical", "high", "medium", "low"):
        desc = f"""### Scenario
{CATEGORY_NARRATIVE['Alert Triage']}

### Alert
- **Name**: {name}
- **Category**: {ctf_category}
- **Summary**: {description_text}

### Question
What **severity** did FortiCNAPP assign to this alert?
(Answer: `Critical`, `High`, `Medium`, `Low`, or `Info`)

### Flag format
`FLAG{{Severity}}` — capitalise first letter only.
"""
        return Challenge(
            name=f"{_safe_name(name)} — sev",
            category=ctf_category,
            description=desc,
            value=_sev_points(sev),
            flags=[Flag(content=_wrap_flag(sev), type="static", case_insensitive=True)],
            tags=["forticnapp", "alert", "severity", sev.lower(), "dynamic"],
            hints=[
                "FortiCNAPP uses five severity levels: Critical, High, Medium, Low, Info.",
                f"The severity is: {sev}",
            ],
        )

    # ── variant 3: alert category ─────────────────────────────────────────
    if category:
        desc = f"""### Scenario
{CATEGORY_NARRATIVE['Alert Triage']}

### Alert
- **Name**: {name}
- **Severity**: {sev}
- **Summary**: {description_text or '_(check FortiCNAPP for details)_'}

### Question
FortiCNAPP categorises every alert. What is the **category** of this alert?
(e.g. `Policy`, `Composite`, `CloudActivity`, `User`)

### Flag format
`FLAG{{CategoryName}}`
"""
        return Challenge(
            name=f"{_safe_name(name)}",
            category=ctf_category,
            description=desc,
            value=_sev_points(sev),
            flags=[Flag(content=_wrap_flag(category), type="static", case_insensitive=True)],
            tags=["forticnapp", "alert", sev.lower(), "dynamic"],
            hints=[
                "Look at the alertCategory field in the FortiCNAPP alert.",
                f"The category is: {category}",
            ],
        )

    return None


# --- container vuln -> challenge -----------------------------------------

def container_vuln_to_challenge(v: dict[str, Any]) -> Challenge | None:
    cve = v.get("vulnId") or _first_cve(str(v))
    if not cve:
        return None
    sev = v.get("severity", "High").capitalize()
    eval_ctx = v.get("evalCtx") or {}
    image_repo = v.get("imageRepo") or eval_ctx.get("image_id") or "unknown/image"
    image_tag = v.get("imageTag") or "latest"
    if ":" in image_repo and image_repo.rsplit(":", 1)[1] == image_tag:
        image_repo = image_repo.rsplit(":", 1)[0]
    pkg = (v.get("featureKey") or {}).get("name") or "unknown-package"
    pkg_ver = (v.get("featureKey") or {}).get("version") or ""
    fix = (v.get("fixInfo") or {}).get("fix_available", 0)
    fixed_version = (v.get("fixInfo") or {}).get("fixed_version", "")

    desc = f"""### Scenario
{CATEGORY_NARRATIVE['Container Security']}

### Finding
- **Image**: `{image_repo}:{image_tag}`
- **Package**: `{pkg} {pkg_ver}`
- **Severity**: {sev}
- **Fix available**: {"yes → " + fixed_version if fix and fixed_version else "yes" if fix else "no"}

### Question
What is the **CVE identifier** for this vulnerability? (Format: `CVE-YYYY-NNNN`)

### Flag format
`FLAG{{CVE-YYYY-NNNN}}`
"""
    return Challenge(
        name=f"{_safe_name(image_repo, 20)} · {_safe_name(pkg, 12)} ({cve})",
        category="Container Security",
        description=desc,
        value=_sev_points(sev),
        flags=[Flag(content=_wrap_flag(cve.upper()), type="static")],
        tags=["forticnapp", "container", "vulnerability", sev.lower(), "dynamic"],
        hints=["The CVE identifier is listed directly on the FortiCNAPP finding."],
    )


# --- host vuln -> challenge ----------------------------------------------

def host_vuln_to_challenge(v: dict[str, Any]) -> Challenge | None:
    cve = v.get("vulnId") or _first_cve(str(v))
    if not cve:
        return None
    sev = v.get("severity", "High").capitalize()
    machine_tags = v.get("machineTags") or {}
    hostname = machine_tags.get("Hostname") or machine_tags.get("InstanceId") or "unknown-host"
    os_name = machine_tags.get("os") or machine_tags.get("OperatingSystem") or "linux"
    pkg = (v.get("featureKey") or {}).get("name") or "unknown-package"
    pkg_ver = (v.get("featureKey") or {}).get("version") or ""
    fix_info = v.get("fixInfo") or {}
    fix_available = fix_info.get("fix_available", 0)
    fixed_ver = fix_info.get("fixed_version", "")

    desc = f"""### Scenario
{CATEGORY_NARRATIVE['Host Security']}

### Finding
- **Host**: `{hostname}`
- **OS**: {os_name}
- **Package**: `{pkg} {pkg_ver}`
- **Severity**: {sev}
- **Patch available**: {"yes → upgrade to " + fixed_ver if fix_available and fixed_ver else "yes" if fix_available else "no"}

### Question
What is the **CVE identifier** flagged on this host? (Format: `CVE-YYYY-NNNN`)

### Flag format
`FLAG{{CVE-YYYY-NNNN}}`
"""
    return Challenge(
        name=f"{_safe_name(hostname, 20)} · {_safe_name(pkg, 12)} ({cve})",
        category="Host Security",
        description=desc,
        value=_sev_points(sev),
        flags=[Flag(content=_wrap_flag(cve.upper()), type="static")],
        tags=["forticnapp", "host", "vulnerability", sev.lower(), "dynamic"],
        hints=["The CVE identifier is the primary key on the FortiCNAPP host vulnerability finding."],
    )


# --- compliance -> challenge --------------------------------------------

def compliance_to_challenge(c: dict[str, Any]) -> Challenge | None:
    """
    Generate a compliance challenge. Works with multiple data shapes:
    - ComplianceEvaluations (with resource + CIS number in title)
    - Policy objects (title/severity/service — fallback from /Policies)
    """
    title = (c.get("title") or c.get("id") or "").strip()
    if not title:
        return None

    sev_raw = c.get("severity", "Medium") or "Medium"
    sev = sev_raw.capitalize()
    resource = (c.get("resource") or "").strip()
    service = (c.get("service") or "").strip()
    rec = (c.get("recommendation") or "").strip()
    desc_text = (c.get("description") or "").strip()

    # ── variant 1: CIS control number in title/description/recommendation ──
    blob = f"{title} {desc_text} {rec}"
    m = _CIS_CTRL_RE.search(blob)
    if m:
        control = m.group(1)
        desc = f"""### Scenario
{CATEGORY_NARRATIVE['Cloud Compliance']}

### Finding
- **Title**: {title}
- **Service**: `{service or 'n/a'}`
- **Resource**: `{resource or 'n/a'}`
- **Severity**: {sev}
- **Recommendation**: {rec or '_see FortiCNAPP for details_'}

### Question
This finding maps to a CIS Benchmark control.
What is the **control number**? (Format: `1.2` or `1.2.3`)

### Flag format
`FLAG{{X.Y}}` or `FLAG{{X.Y.Z}}`
"""
        pattern = rf"FLAG\{{\s*{re.escape(control)}(?:\.0)?\s*\}}"
        return Challenge(
            name=f"{_safe_name(title)}",
            category="Cloud Compliance",
            description=desc,
            value=_sev_points(sev),
            flags=[Flag(content=pattern, type="regex", case_insensitive=True)],
            tags=["forticnapp", "compliance", "cis", sev.lower(), "dynamic"],
            hints=[
                "Look for the control number in the finding title or recommendation.",
                f"The control number is: {control}",
            ],
        )

    # ── variant 2: known service → ask which cloud service is misconfigured ──
    if service:
        # Normalise service name: "AWS::EC2::SecurityGroup" → "EC2"
        svc_short = service.split("::")[-1] if "::" in service else service
        # Strip common suffixes for a clean answer
        svc_clean = re.sub(r'(Instance|Group|Bucket|Table|Function|Cluster|Role)$',
                           '', svc_short).strip() or svc_short

        desc = f"""### Scenario
{CATEGORY_NARRATIVE['Cloud Compliance']}

### Finding
- **Control**: {title}
- **Severity**: {sev}
- **Recommendation**: {rec or '_see FortiCNAPP for details_'}

### Question
Which **cloud service** does this misconfiguration affect?
Give the short service name (e.g. `EC2`, `S3`, `IAM`, `CloudTrail`).

### Flag format
`FLAG{{ServiceName}}`
"""
        pattern = rf"FLAG\{{\s*{re.escape(svc_short)}\s*\}}"
        return Challenge(
            name=f"{_safe_name(title)} — svc",
            category="Cloud Compliance",
            description=desc,
            value=_sev_points(sev),
            flags=[Flag(content=pattern, type="regex", case_insensitive=True)],
            tags=["forticnapp", "compliance", "cspm", sev.lower(), "dynamic"],
            hints=[
                "Look at the resource type or the finding title for the service name.",
                f"The service is: {svc_short}",
            ],
        )

    # ── variant 3: severity question (always possible) ──────────────────
    if sev.lower() in ("critical", "high", "medium", "low"):
        desc = f"""### Scenario
{CATEGORY_NARRATIVE['Cloud Compliance']}

### Finding
- **Control**: {title}
- **Description**: {desc_text or '_see FortiCNAPP for details_'}
- **Recommendation**: {rec or '_n/a_'}

### Question
What **severity** did FortiCNAPP assign to this compliance violation?
(Answer: `Critical`, `High`, `Medium`, or `Low`)

### Flag format
`FLAG{{Severity}}`
"""
        return Challenge(
            name=f"{_safe_name(title)} — sev",
            category="Cloud Compliance",
            description=desc,
            value=_sev_points(sev),
            flags=[Flag(content=_wrap_flag(sev), type="static", case_insensitive=True)],
            tags=["forticnapp", "compliance", "cspm", sev.lower(), "dynamic"],
            hints=[
                "FortiCNAPP uses four severity levels for compliance: Critical, High, Medium, Low.",
                f"The severity is: {sev}",
            ],
        )

    return None


# --- orchestrator --------------------------------------------------------

def build_all(
    alerts: list[dict[str, Any]],
    container_vulns: list[dict[str, Any]],
    host_vulns: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    max_per_category: int = 5,
) -> list[Challenge]:
    out: list[Challenge] = []

    def _take(items: Iterable, builder, label: str):
        count = 0
        seen_keys: set[str] = set()
        for item in items:
            if count >= max_per_category:
                break
            ch = builder(item)
            if ch is None:
                continue
            # Dedupe identical flags (same CVE / technique appearing many times)
            key = ch.flags[0].content if ch.flags else ch.name
            if key in seen_keys:
                continue
            seen_keys.add(key)
            out.append(ch)
            count += 1
        log.info("Generated %d challenges in category '%s'", count, label)

    _take(alerts, alert_to_challenge, "Alert Triage")
    _take(container_vulns, container_vuln_to_challenge, "Container Security")
    _take(host_vulns, host_vuln_to_challenge, "Host Security")
    _take(compliance, compliance_to_challenge, "Cloud Compliance")
    return out
