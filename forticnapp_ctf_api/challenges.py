"""
Challenge generator.

Maps FortiCNAPP findings to CTFd challenges.  Each generator emits a
`Challenge` dataclass that the CTFd pusher knows how to ship.

Categories
----------
- Alert Triage          : real alerts -> "what is the MITRE technique?" etc.
- Container Vulnerabilities : "find the CVE that... ", "what package is affected?"
- Host Vulnerabilities  : same, but for hosts
- Compliance            : "which CIS control is violated by this finding?"

Flag style
----------
We follow the canonical `FLAG{...}` convention. Static flags are used for
exact answers (a CVE ID, a control number); regex flags are used when
several phrasings are acceptable (e.g. "T1190" or "T1190.001").
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


def _first_cve(text: str) -> str | None:
    if not text:
        return None
    m = _CVE_RE.search(text)
    return m.group(0).upper() if m else None


def _wrap_flag(answer: str) -> str:
    """Wrap an answer in the canonical FLAG{...} format."""
    return "FLAG{" + answer.strip() + "}"


def _safe_name(s: str, limit: int = 60) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit].rstrip(" .,:-")


# --- alert -> challenge ---------------------------------------------------

def _extract_mitre_technique(alert: dict[str, Any]) -> str | None:
    """Extract the first MITRE technique ID (T####) from an alert's tagMetadata."""
    # Primary: alertModel.mitre (older format)
    mitre = (
        alert.get("alertModel", {}).get("mitre", {}).get("techniqueId")
        or (alert.get("alertInfo") or {}).get("mitreTechniqueId")
    )
    if mitre:
        return mitre.upper()
    # Real API format: tagMetadata is a list of {tagMetadata: {id: "T1078", ...}}
    for entry in alert.get("tagMetadata", []):
        tid = (entry.get("tagMetadata") or {}).get("id", "")
        # Technique IDs start with T and are followed by digits (not TA = tactic)
        if tid.startswith("T") and not tid.startswith("TA") and tid[1:].replace(".", "").isdigit():
            return tid.upper()
    return None


def alert_to_challenge(alert: dict[str, Any]) -> Challenge | None:
    """
    Build a challenge where the flag is the MITRE technique ID surfaced in
    the alert. Falls back to the alert source/category if no MITRE field is present.
    """
    name = alert.get("alertName") or alert.get("name") or "Untitled Alert"
    sev = alert.get("severity", "Medium").capitalize()
    info = alert.get("alertInfo") or {}
    description_text = info.get("description") or alert.get("description") or ""

    # MITRE technique is the most fun puzzle target
    mitre = _extract_mitre_technique(alert)
    if mitre:
        answer = mitre.upper()
        question = (
            "Based on the alert below, which MITRE ATT&CK "
            "**Technique ID** (e.g. `T1078`) is FortiCNAPP attributing "
            "this activity to?"
        )
        hints = [
            "Look at the tagMetadata list in the alert — each entry has an id field.",
            "Submit only the technique ID (not the tactic TA####), wrapped in FLAG{...}.",
        ]
    else:
        # Fall back to derivedFields.category (real API shape) or alertCategory
        derived = alert.get("derivedFields") or {}
        category = (
            alert.get("alertCategory")
            or derived.get("category")
            or derived.get("source")
            or info.get("category")
        )
        if not category:
            return None
        answer = category
        question = (
            "FortiCNAPP categorises every alert. What is the **category** of "
            "the alert below? (e.g. `Policy`, `Composite`, `CloudActivity`)"
        )
        hints = ["Look at the derivedFields.category field in the alert JSON."]

    desc = f"""### Scenario
{CATEGORY_NARRATIVE['Alert Triage']}

### Alert
- **Name**: {name}
- **Severity**: {sev}
- **Summary**: {description_text or '_(no summary)_'}

### Question
{question}

### Flag format
`FLAG{{your_answer}}`
"""
    return Challenge(
        name=f"Alert Triage: {_safe_name(name)}",
        category="Alert Triage",
        description=desc,
        value=SEVERITY_POINTS.get(sev, 200),
        flags=[Flag(content=_wrap_flag(answer), type="static")],
        tags=["forticnapp", "alert", sev.lower()],
        hints=hints,
    )


# --- container vuln -> challenge -----------------------------------------

def container_vuln_to_challenge(v: dict[str, Any]) -> Challenge | None:
    cve = v.get("vulnId") or _first_cve(str(v))
    if not cve:
        return None
    sev = v.get("severity", "High").capitalize()
    eval_ctx = v.get("evalCtx") or {}
    # Prefer imageRepo (bare path, no tag); fall back to evalCtx.image_id only
    # if needed. image_id often already includes the tag, which would double up.
    image_repo = v.get("imageRepo") or eval_ctx.get("image_id") or "unknown/image"
    image_tag = v.get("imageTag") or "latest"
    # If image_repo already contains ":tag", drop it so we don't duplicate
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
- **Fix available**: {"yes -> " + fixed_version if fix and fixed_version else "no"}

### Question
What is the **CVE identifier** for this vulnerability? (Format: `CVE-YYYY-NNNN`)

### Flag format
`FLAG{{CVE-YYYY-NNNN}}`
"""
    return Challenge(
        name=f"Container: {_safe_name(image_repo, 30)} / {pkg} ({cve})",
        category="Container Security",
        description=desc,
        value=SEVERITY_POINTS.get(sev, 300),
        flags=[Flag(content=_wrap_flag(cve.upper()), type="static")],
        tags=["forticnapp", "container", "vulnerability", sev.lower()],
        hints=["The CVE is the canonical identifier on the finding itself."],
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

    desc = f"""### Scenario
{CATEGORY_NARRATIVE['Host Security']}

### Finding
- **Host**: `{hostname}`
- **OS**: {os_name}
- **Package**: `{pkg}`
- **Severity**: {sev}

### Question
What is the **CVE identifier** flagged on this host? (Format: `CVE-YYYY-NNNN`)

### Flag format
`FLAG{{CVE-YYYY-NNNN}}`
"""
    return Challenge(
        name=f"Host Vuln: {_safe_name(hostname, 35)} / {pkg} ({cve})",
        category="Host Security",
        description=desc,
        value=SEVERITY_POINTS.get(sev, 300),
        flags=[Flag(content=_wrap_flag(cve.upper()), type="static")],
        tags=["forticnapp", "host", "vulnerability", sev.lower()],
        hints=["CVEs are listed under vulnId."],
    )


# --- compliance -> challenge --------------------------------------------

_CIS_CTRL_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def compliance_to_challenge(c: dict[str, Any]) -> Challenge | None:
    title = c.get("title") or c.get("id") or "Non-compliant configuration"
    sev = c.get("severity", "Medium").capitalize()
    resource = c.get("resource") or "unknown-resource"
    service = c.get("service") or "unknown-service"
    rec = c.get("recommendation") or ""
    desc_text = c.get("description") or ""

    # Try to extract the CIS control number from the title or description
    blob = f"{title} {desc_text} {rec}"
    m = _CIS_CTRL_RE.search(blob)
    if not m:
        return None
    control = m.group(1)

    desc = f"""### Scenario
{CATEGORY_NARRATIVE['Cloud Compliance']}

### Finding
- **Title**: {title}
- **Service**: `{service}`
- **Resource**: `{resource}`
- **Severity**: {sev}
- **Recommendation**: {rec or "_n/a_"}

### Question
This finding maps to a CIS Benchmark control. What is the **control number**?
(Format: `1.2` or `1.2.3`)

### Flag format
`FLAG{{X.Y}}` or `FLAG{{X.Y.Z}}`
"""
    # Accept both 1.2 and 1.2.0 phrasings via regex
    pattern = rf"FLAG\{{\s*{re.escape(control)}(?:\.0)?\s*\}}"
    return Challenge(
        name=f"Compliance: {_safe_name(title)}",
        category="Cloud Compliance",
        description=desc,
        value=SEVERITY_POINTS.get(sev, 200),
        flags=[Flag(content=pattern, type="regex", case_insensitive=True)],
        tags=["forticnapp", "compliance", "cis", sev.lower()],
        hints=[
            "Look for the control number embedded in the finding title or "
            "recommendation.",
        ],
    )


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
            # Dedupe identical flags (same CVE appearing many times)
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
