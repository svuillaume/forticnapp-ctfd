<div align="center">

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png" alt="Fortinet" width="180"/>

# FortiCNAPP CTF

**A Capture-The-Flag platform for FortiCNAPP workshops and customer events**

![Fortinet Red](https://img.shields.io/badge/Fortinet-DA291C?style=flat&logoColor=white)
![CTFd](https://img.shields.io/badge/CTFd-3.7.5-000000?style=flat&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3572A5?style=flat&logo=python&logoColor=white)
![Challenges](https://img.shields.io/badge/challenges-21_static_%2B_live-DA291C?style=flat)

</div>

---

## Overview

FortiCNAPP CTF turns real cloud security findings into hands-on learning.
Participants navigate the FortiCNAPP console to investigate alerts, triage vulnerabilities,
and map compliance violations — submitting `FLAG{...}` answers to score points on a live leaderboard.

Two modes let you run it with or without a live FortiCNAPP tenant:

| Mode | Challenges | FortiCNAPP required | Best for |
|---|---|---|---|
| **Static** | 21 curated, hand-authored | ❌ No | Demos, travel, rehearsal, offline |
| **Dynamic** | Up to 20, from real findings | ✅ Yes | Live events with a real tenant |

Both modes share the same CTFd scoreboard, Fortinet dark theme, and Docker stack.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Compose Stack                        │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │  MariaDB     │   │  Redis       │   │  CTFd 3.7.5          │ │
│  │  (ctf-db)    │   │  (ctf-cache) │   │  http://localhost:8000│ │
│  └──────────────┘   └──────────────┘   └──────────┬───────────┘ │
│                                                    │ Admin API   │
│  ┌──────────────────────────┐  ┌───────────────────▼───────────┐ │
│  │  bridge-static           │  │  bridge (dynamic)             │ │
│  │  static_ctf/             │  │  forticnapp_ctf_api/          │ │
│  │  reads YAML → CTFd API   │  │  FortiCNAPP API → CTFd API    │ │
│  └──────────────────────────┘  └───────────────────────────────┘ │
│                                            ▲                     │
└────────────────────────────────────────────│─────────────────────┘
                                             │
                               ┌─────────────┴──────────────┐
                               │  FortiCNAPP / Lacework API  │
                               │  partner-demo.lacework.net  │
                               └────────────────────────────┘
```

---

## Prerequisites

- **Docker** + **Docker Compose v2**
- A free port `8000` on localhost
- *(Static mode only)* — nothing else needed
- *(Dynamic mode)* — a FortiCNAPP API key (KeyId + Secret + account name)

---

## Quick Start

### 1 — Clone and configure

```bash
git clone https://github.com/svuillaume/forticnapp-ctfd.git
cd forticnapp-ctfd
cp .env.example .env
```

Edit `.env` with at minimum:

```dotenv
SECRET_KEY=any-strong-random-string        # required for CTFd to start
```

### 2 — Start CTFd

```bash
docker compose up -d db cache ctfd
```

Wait ~15 seconds, then open **http://localhost:8000**.

### 3 — Complete the first-boot wizard

1. Enter your event name — e.g. `FortiCNAPP Cloud Defender Challenge`
2. Create an admin user (remember these credentials)
3. Choose **Users** or **Teams** scoring mode
4. Click **Finish Setup**

### 4 — Generate an admin API token

In the CTFd UI: **Admin Panel → Settings → Tokens → Generate**

Paste it into `.env`:

```dotenv
CTFD_ADMIN_TOKEN=ctfd_xxxxxxxxxxxxxxxx
```

### 5 — Load challenges

Pick your mode:

```bash
# Static — 21 curated challenges, no API needed
docker compose run --rm bridge-static

# Dynamic — live challenges from your FortiCNAPP tenant
docker compose run --rm bridge
```

Open **http://localhost:8000** — challenges, Fortinet dark theme, and leaderboard are live.

---

## Static Mode

Pre-authored challenges covering real FortiCNAPP scenarios. No tenant, no credentials, works offline.

```bash
docker compose run --rm bridge-static
```

**21 challenges across 4 categories:**

| Category | # | Topics |
|---|---|---|
| 🔴 **Alert Triage** | 5 | MITRE ATT&CK T1496, T1078.004, T1571 · alert categories · composite alerts |
| 🟠 **Host Security** | 5 | Hostname lookup · CVE identification · CVSS scoring · agentless scanning |
| 🔵 **Container Security** | 5 | Shadow MCP detection · Docker image forensics · crypto mining · port exposure |
| 🟡 **Cloud Compliance** | 6 | CIS AWS controls 1.5 · 1.14 · 2.1.5 · 3.1 · 5.2x · CSPM acronym |

Challenges live in `static_ctf/ctf/*/challenges.yml`. Edit freely and re-run
`bridge-static` to push updates — it's fully idempotent (create on first run, update on re-run).

---

## Dynamic Mode

Pulls real findings from your FortiCNAPP tenant and auto-generates challenges.

### API credentials

In the FortiCNAPP console: **Settings → API Keys → Create New**.
Download the JSON file — it contains `keyId`, `secret`, and `account`.

Add to `.env`:

```dotenv
MOCK_MODE=false
SANITIZE=true                              # ALWAYS keep true for customer demos

FORTICNAPP_ACCOUNT=acme-prod              # subdomain: acme-prod.lacework.net → acme-prod
FORTICNAPP_SUBACCOUNT=                    # leave blank unless using sub-accounts
FORTICNAPP_API_KEY_ID=ACME_1234...
FORTICNAPP_API_SECRET=_replace_with_secret_

LOOKBACK_HOURS=72                         # how far back to pull alerts
MAX_CHALLENGES_PER_CATEGORY=5             # cap per category
```

Then:

```bash
docker compose run --rm bridge
```

Expected output:

```
bridge | Pulled findings: {'alerts': 6, 'container_vulns': 5, 'host_vulns': 4, 'compliance': 5}
bridge | Sanitization applied (12 unique values mapped)
bridge | Built 17 challenges total
bridge | Push complete: {'created': 17, 'skipped': 0, 'failed': 0}
```

### What each category queries

| Category | API endpoint | Requires |
|---|---|---|
| Alert Triage | `/api/v2/Alerts` | Alerts with MITRE `tagMetadata` |
| Host Security | `/api/v2/Vulnerabilities/Hosts/search` | Lacework agent or agentless scanning |
| Container Security | `/api/v2/Vulnerabilities/Containers/search` | Agentless workload scanning |
| Cloud Compliance | `/api/v2/Configs/ComplianceEvaluations/search` | CSPM integration active |

### Offline rehearsal (mock mode)

```dotenv
MOCK_MODE=true
```

Reads from `sample_data/*.json` instead of the live API — perfect for flights and demos without connectivity.

---

## Running Both Modes Together

Layer them: static first for guaranteed challenges, dynamic on top for live tenant data.

```bash
docker compose run --rm bridge-static   # 21 static challenges
docker compose run --rm bridge          # + live-generated challenges
```

CTFd deduplicates by name — no overlap as long as challenge names differ.

---

## Event Workflow (Two Phases)

### Phase 1 — Setup (before participants arrive)

```
SE / Presenter                 FortiCNAPP Console              CTFd
─────────────────────────────────────────────────────────────────────
1. docker compose up -d        (tenant already has findings)
2. Complete CTFd wizard →
3. Generate admin token →                                  admin panel
4. docker compose run --rm bridge-static   ─────────────▶  21 challenges loaded
   (or bridge for live data)
5. Verify at http://localhost:8000
```

Typical setup time: **5 minutes** (static) or **10 minutes** (dynamic).

### Phase 2 — Live CTF Event (participants)

```
Participants                   FortiCNAPP Console              CTFd
─────────────────────────────────────────────────────────────────────
1. Register at http://localhost:8000
2. Read challenge scenario  ──▶  Navigate console to find answer
3. Submit FLAG{...}         ──────────────────────────────────▶  scored
4. Leaderboard updates live
```

**Suggested 45-minute arc:**
| Time | Round | FortiCNAPP skill reinforced |
|---|---|---|
| 0–2 min | Scene-setting | — |
| 2–17 min | 🔴 Alert Triage | MITRE mapping accelerates IR |
| 17–32 min | 🟠 Host + Container Security | CWPP value vs. siloed scanners |
| 32–42 min | 🟡 Cloud Compliance | CSPM + audit story |
| 42–45 min | Debrief + leaderboard | Walk one finding live in console |

---

## Theme

The platform ships with a **FortiGuard Labs dark theme** — deep navy-black background,
red accent glows, monospace flag inputs, and JetBrains Mono typography.

Inspired by [fortiguard.com/threatintel-search](https://www.fortiguard.com/threatintel-search).

| Token | Value | Used for |
|---|---|---|
| Background | `#09111e` | Page background with grid texture |
| Card surface | `#0e1929` | Challenge cards, modals |
| **Fortinet Red** | `#DA291C` | Buttons, borders, nav accent, rank #1 |
| Cyan | `#00b0cc` | Score chips, countdown timer, blockquotes |
| Text primary | `#e2eaf4` | Body text |
| Mono green | `#7affa0` | Flag input text |

**Theme is applied automatically** every time `bridge` or `bridge-static` runs.
To push CSS changes manually:

```bash
source .env
CSS=$(cat theme/fortinet.css)
curl -X PATCH http://localhost:8000/api/v1/configs \
  -H "Authorization: Token ${CTFD_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"css\": $(echo "$CSS" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}"
```

---

## Project Layout

```
forticnapp-ctf/
├── docker-compose.yml               # CTFd + DB + cache + bridge + bridge-static
├── .env.example                     # template — copy to .env, never commit .env
├── README.md
│
├── theme/
│   └── fortinet.css                 # FortiGuard Labs dark theme CSS
│
├── static_ctf/                      # ── Static mode ──────────────────────────
│   ├── Dockerfile
│   ├── build.py                     # entrypoint: reads env, waits for CTFd, runs build
│   ├── ctfbuilder.py                # idempotent push: create + update challenges
│   ├── ctfd.py                      # CTFd REST API wrapper
│   ├── requirements.txt
│   └── ctf/
│       ├── config.yml               # sets CTFd event name
│       ├── 1_Alert Triage/
│       │   └── challenges.yml       # 5 challenges
│       ├── 2_Host Security/
│       │   └── challenges.yml       # 5 challenges
│       ├── 3_Container Security/
│       │   └── challenges.yml       # 5 challenges
│       └── 4_Cloud Compliance/
│           └── challenges.yml       # 6 challenges
│
├── forticnapp_ctf_api/              # ── Dynamic mode ─────────────────────────
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── __main__.py                  # python -m forticnapp_ctf_api
│   ├── bridge.py                    # orchestrator: pull → sanitize → build → push
│   ├── forticnapp_client.py         # Lacework v2 REST client (auth + queries)
│   ├── ctfd_client.py               # CTFd admin REST client + theme injection
│   ├── challenges.py                # finding → Challenge mapping + FLAG logic
│   └── sanitize.py                  # PII / customer-data scrubber
│
└── sample_data/                     # mock fixtures for MOCK_MODE=true
    ├── alerts.json
    ├── container_vulns.json
    ├── host_vulns.json
    └── compliance.json
```

---

## Flag Format

All challenges use:

```
FLAG{your_answer_here}
```

| Category | Answer is… | Match |
|---|---|---|
| Alert Triage | MITRE technique ID e.g. `T1496`, `T1078.004` | static, case-insensitive |
| Host Security | CVE ID e.g. `CVE-2025-12345`, or hostname regex | static / regex |
| Container Security | Image name, port number, acronym expansion | static, case-insensitive |
| Cloud Compliance | CIS control number e.g. `1.5`, `2.1.5` | static / regex |

---

## Sanitization

When `SANITIZE=true` (default, **always use for customer demos**), the dynamic bridge scrubs:

- AWS 12-digit account IDs and full ARNs
- Azure subscription UUIDs
- GCP `projects/...` identifiers
- S3 bucket names
- Public IPv4 addresses (RFC1918 and loopback are kept — they're demo-safe)
- Email addresses
- Public DNS hostnames

The mapping is stable per run — the same real value always maps to the same fake value,
so challenge descriptions stay internally consistent.

---

## Troubleshooting

**CTFd keeps restarting**
```dotenv
SECRET_KEY=any-strong-random-string    # add this to .env
```

**Admin token rejected (401)**
Regenerate in CTFd UI → Admin Panel → Settings → Tokens, update `CTFD_ADMIN_TOKEN` in `.env`.

**0 challenges generated (dynamic)**
1. Verify credentials: `FORTICNAPP_ACCOUNT`, `FORTICNAPP_API_KEY_ID`, `FORTICNAPP_API_SECRET`
2. Check `FORTICNAPP_SUBACCOUNT` matches the tenant (leave blank if not using sub-accounts)
3. Widen search: `LOOKBACK_HOURS=720`
4. Test offline: `MOCK_MODE=true`

**Container Security returning 0 (dynamic)**
Agentless Workload Scanning must be enabled on the tenant. Try `LOOKBACK_HOURS=720` or `MOCK_MODE=true`.

**YAML error in static_ctf/**
All `content:` values containing `: ` substrings must be quoted. Example:
```yaml
# ❌ breaks YAML
- content: Look for this (hint: check section 5).
# ✅ correct
- content: "Look for this (hint: check section 5)."
```

**Full reset**
```bash
docker compose down -v          # ⚠️ drops the CTFd database — all scores erased
docker compose up -d db cache ctfd
# Redo wizard, generate new token, re-run bridge
```

---

## Roadmap

- [ ] Dynamic scoring (challenge value decays as more teams solve it)
- [ ] Per-challenge raw JSON attachment (download the FortiCNAPP finding)
- [ ] LQL-based challenges ("write the query that catches this pattern")
- [ ] Webhook: new FortiCNAPP alert during the event spawns a live bonus challenge
- [ ] Container Security fallback to mock when live API returns 0 results

---

## License & Attribution

CTFd is [BSD-2-Clause licensed](https://github.com/CTFd/CTFd/blob/master/LICENSE).
This wrapper has no affiliation with the CTFd project.
FortiCNAPP and Lacework are trademarks of Fortinet, Inc.
