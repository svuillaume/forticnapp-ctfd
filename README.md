<div align="center">

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png" alt="Fortinet" width="200"/>

# FortiCNAPP CTF

![Fortinet Red](https://img.shields.io/badge/Fortinet-DA291C?style=flat&logo=fortinet&logoColor=white)
![CTFd](https://img.shields.io/badge/CTFd-3.7.5-000000?style=flat&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-DA291C?style=flat&logo=python&logoColor=white)

</div>

---

A containerized **Capture-The-Flag** platform that pulls real findings from a
**FortiCNAPP** tenant, sanitizes them for safe customer demos, and turns them
into CTFd challenges automatically.

Built for **PreSales workshops and customer events** where the goal is to let
participants experience FortiCNAPP's value through hands-on triage instead of
slides.

```
                ┌───────────────────┐
                │  FortiCNAPP API   │
                │  (Lacework v2)    │
                └─────────┬─────────┘
                          │  alerts + vulns + compliance
                          ▼
                ┌───────────────────┐    sanitize     ┌──────────────────┐
                │  bridge service   │ ──────────────▶ │  CTFd admin API  │
                │  (Python)         │   FLAG{...}     │  (REST v1)       │
                └───────────────────┘                 └────────┬─────────┘
                                                              │
                                                              ▼
                                                      ┌──────────────────┐
                                                      │  CTFd Scoreboard │
                                                      │  http://:8000    │
                                                      └──────────────────┘
```

## What you get

- **CTFd 3.7.5** (official image) backed by MariaDB + Redis
- **One-shot Python bridge** that:
  - Authenticates against FortiCNAPP (Lacework-compatible v2 API)
  - Pulls alerts, container/host vulnerabilities, and compliance violations
  - **Sanitizes** account IDs, ARNs, hostnames, emails, public IPs and bucket names
  - Generates curated CTF challenges with `FLAG{...}` answers across four
    categories: Alert Triage, Container Security, Host Security, Cloud Compliance
- **Mock mode** with realistic fixtures so you can rehearse offline / on a plane
- **Idempotent push** — re-running won't duplicate challenges

## Prerequisites

- Docker + Docker Compose v2
- (Optional) A FortiCNAPP tenant with API key (KeyId + Secret) and account name.
  If you don't have one, run in `MOCK_MODE=true`.

---

## Quick start (mock mode — no tenant needed)

```bash
cd forticnapp-ctf
cp .env.example .env
# edit .env:
#   MOCK_MODE=true
#   SECRET_KEY=any-random-string-you-choose   ← required for CTFd multi-worker

# 1) Start CTFd + DB + cache
docker compose up -d db cache ctfd

# 2) Complete the first-boot wizard
open http://localhost:8000
# - Pick an event name  (e.g. "FortiCNAPP Cloud Defender Challenge")
# - Create the admin user
# - Choose "Users" or "Teams" mode

# 3) Generate an admin API token
# In the CTFd UI:  Admin Panel → Settings → Tokens → Generate
# Paste the token into .env as:  CTFD_ADMIN_TOKEN=ctfd_...

# 4) Run the bridge (one-shot challenge importer)
docker compose run --rm bridge
```

Within ~10 seconds you should see something like:

```
bridge | Pulled findings: {'alerts': 6, 'container_vulns': 5, 'host_vulns': 4, 'compliance': 5}
bridge | Sanitization applied (12 unique values mapped)
bridge | Built 17 challenges total
bridge | Push complete: {'created': 17, 'skipped': 0, 'failed': 0}
```

Refresh CTFd — challenges appear under their categories. Participants log in,
submit flags, and the leaderboard updates in real time.

---

## Live mode (against your FortiCNAPP tenant)

In the FortiCNAPP console: **Settings → API Keys → Create New**. Download the
JSON — it contains `keyId`, `secret`, and `account`.

Edit `.env`:

```dotenv
MOCK_MODE=false
SANITIZE=true                                # KEEP TRUE for customer demos
SECRET_KEY=your-random-secret-key            # required — any strong random string

FORTICNAPP_ACCOUNT=acme-prod                 # subdomain only, e.g. acme-prod.lacework.net → acme-prod
FORTICNAPP_SUBACCOUNT=                       # leave blank unless using a sub-account
FORTICNAPP_API_KEY_ID=ACME_1234567890ABCDEF
FORTICNAPP_API_SECRET=_replace_with_secret_

LOOKBACK_HOURS=72
MAX_CHALLENGES_PER_CATEGORY=5
```

Then:

```bash
docker compose run --rm bridge
```

### What each category needs from your tenant

| Category | Data source | Notes |
|---|---|---|
| **Alert Triage** | `/api/v2/Alerts` | Best results when alerts carry MITRE `tagMetadata`; falls back to `derivedFields.category` |
| **Container Security** | `/api/v2/Vulnerabilities/Containers/search` | Requires Agentless or Agent-based container scanning enabled |
| **Host Security** | `/api/v2/Vulnerabilities/Hosts/search` | Works on any account with the Lacework agent deployed |
| **Cloud Compliance** | `/api/v2/Configs/ComplianceEvaluations/search` | Falls back to `/api/v2/Policies` if the evaluations endpoint is unavailable |

> **Tip — Container Security returning 0?**  
> Container vuln data is only available when Agentless Workload Scanning or the
> Lacework agent container scope is active on the tenant. Extend `LOOKBACK_HOURS`
> (e.g. `720` = 30 days) to widen the search window, or use `MOCK_MODE=true` to
> supplement with fixture data.

---

## Demo narrative (for customer events)

A workshop arc that works well in ~45 min:

1. **Set the scene** (2 min) — "You are the on-call SOC analyst at Acme Corp.
   FortiCNAPP just lit up. Your job: triage."
2. **Round 1 – Alert Triage** (15 min) — participants identify the MITRE ATT&CK
   technique behind each alert. Reinforces *why* FortiCNAPP's MITRE mapping
   accelerates IR.
3. **Round 2 – Container & Host Vulns** (15 min) — find the CVE, identify the
   fix. Reinforces FortiCNAPP's CWPP value vs. siloed scanners.
4. **Round 3 – Compliance** (10 min) — map findings to CIS controls.
   Reinforces CSPM + audit story.
5. **Debrief** (3 min) — review leaderboard live, walk through one finding in
   the FortiCNAPP console, transition to architecture discussion.

---

## Project layout

```
forticnapp-ctf/
├── docker-compose.yml
├── .env.example
├── README.md
├── forticnapp_ctf_api/         # the bridge service (Python package)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── __init__.py
│   ├── __main__.py             # package entry point (python -m forticnapp_ctf_api)
│   ├── bridge.py               # orchestrator: pull → sanitize → build → push
│   ├── forticnapp_client.py    # Lacework v2 REST client (auth + all queries)
│   ├── ctfd_client.py          # CTFd admin REST client
│   ├── challenges.py           # finding → Challenge mapping + FLAG logic
│   └── sanitize.py             # PII / customer-data scrubber
├── sample_data/                # mock fixtures (used when MOCK_MODE=true)
│   ├── alerts.json
│   ├── container_vulns.json
│   ├── host_vulns.json
│   └── compliance.json
└── challenges/                 # hand-authored bonus challenges (optional)
```

---

## Flag format

All generated challenges use the canonical CTF convention:

```
FLAG{your_answer}
```

| Category | Flag answer is… | Match type |
|---|---|---|
| Alert Triage | MITRE technique ID (e.g. `T1078`) | static (case-insensitive) |
| Container Security | CVE identifier (e.g. `CVE-2024-21626`) | static |
| Host Security | CVE identifier | static |
| Cloud Compliance | CIS control number (e.g. `1.4`, `3.1`) | regex — accepts `3.1` and `3.1.0` |

---

## Sanitization — what gets scrubbed

When `SANITIZE=true` (the default), the bridge replaces the following with
realistic-but-fake values before the data hits CTFd:

- AWS 12-digit account IDs and full ARNs
- Azure subscription UUIDs
- GCP `projects/...` identifiers
- S3 bucket names (`s3://...` and `arn:aws:s3:::...`)
- Public IPv4 addresses (RFC1918 / loopback are kept — they're informative
  and demo-safe)
- Email addresses
- Public-DNS hostnames

The mapping is **stable for a single run** — the same real account ID always
maps to the same fake ID, so challenges stay internally consistent.

---

## Troubleshooting

**CTFd container keeps restarting with "SECRET_KEY" error**
CTFd requires `SECRET_KEY` when running with more than 1 worker. Add it to
`.env`:
```dotenv
SECRET_KEY=any-strong-random-string
```

**"CTFd is up but the admin token is rejected"**
Generate a fresh token in the CTFd UI (Admin Panel → Settings → Tokens) and
update `CTFD_ADMIN_TOKEN` in `.env`.

**"Missing required env vars: FORTICNAPP_..."**
Either fill in the FortiCNAPP creds in `.env`, or set `MOCK_MODE=true`.

**Alert Triage generating 0 challenges**
The bridge looks for MITRE technique IDs in `tagMetadata` and falls back to
`derivedFields.category`. If alerts return 0 challenges, widen `LOOKBACK_HOURS`
or check that the API key has access to the correct sub-account.

**Container Security generating 0 challenges**
Container vulnerability data is only present when Agentless Workload Scanning
or agent-based container scoping is active on the tenant. Try:
1. `LOOKBACK_HOURS=720` (30 days)
2. `MOCK_MODE=true` to blend in fixture data

**"No challenges could be generated"**
All finding categories returned 0 results. Check API credentials, sub-account
name, and lookback window. Run with `MOCK_MODE=true` to verify the pipeline
end-to-end without a live tenant.

**Reset everything (start fresh)**
```bash
docker compose down -v   # ⚠️ WARNING: drops the CTFd database
docker compose up -d db cache ctfd
# Redo the wizard and token steps, then re-run the bridge
```

---

## Fortinet Branding

The platform ships with a full **Fortinet brand theme** applied automatically.

| Token | Value | Usage |
|---|---|---|
| Primary Red | `#DA291C` (Pantone 485 C) | Navbar border, buttons, active states, rank highlights |
| Black | `#000000` (Pantone Black 6 C) | Navbar background, card headers, table headers |
| White | `#FFFFFF` | Text on dark surfaces |

**Theme is applied automatically** — every time the bridge runs it calls
`PATCH /api/v1/configs` to push `theme/fortinet.css` into CTFd's
appearance settings. No manual steps needed.

To customize further, edit `theme/fortinet.css` and re-run the bridge:

```bash
docker compose run --rm bridge
```

The CSS file is also mounted read-only into the CTFd container at
`/opt/CTFd/CTFd/themes/core/static/custom/fortinet.css` for direct
reference from custom templates.

---

## Roadmap / nice-to-haves

- Dynamic scoring (decay as more teams solve a challenge)
- Per-challenge attachments (raw FortiCNAPP JSON snippet for download)
- LQL-based challenges (e.g. "write the query that would catch this pattern")
- Webhook so a new FortiCNAPP alert during the event spawns a live bonus challenge
- Container Security fallback to mock data when live API returns 0 results

---

## License & attribution

CTFd is BSD-2-Clause licensed; official image is `ctfd/ctfd`.
This wrapper has no affiliation with the CTFd project.
FortiCNAPP and Lacework are trademarks of Fortinet, Inc.
