<div align="center">

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png" alt="Fortinet" width="180"/>

# FortiCNAPP CTF

**A Capture-The-Flag platform for FortiCNAPP workshops and customer demos**

![CTFd](https://img.shields.io/badge/CTFd-3.7.5-000000?style=flat&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3572A5?style=flat&logo=python&logoColor=white)
![Challenges](https://img.shields.io/badge/challenges-21_static_%2B_live-DA291C?style=flat)

</div>

---

## What is it?

FortiCNAPP CTF turns real cloud security findings into a scored, timed competition.
Participants navigate the FortiCNAPP console to investigate alerts, triage vulnerabilities,
and map compliance violations — then submit `FLAG{...}` answers on a live leaderboard.

**Two modes, one stack:**

| Mode | Challenges | FortiCNAPP tenant | Best for |
|---|---|---|---|
| **CTF Lab** (static) | 21 hand-authored | ❌ Not needed | Demos, offline, rehearsal |
| **Live CTF** (dynamic) | Generated from real data | ✅ Required | Live events with a real tenant |

---

## Architecture

```
Browser
  │
  │  https://your-domain:443        (CTFd UI)
  │  https://your-domain:5555       (Trigger API)
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│  Caddy (HTTPS reverse proxy)                             │
│  Let's Encrypt cert via DuckDNS DNS-01                   │
└────────────┬──────────────────────────────┬─────────────┘
             │                              │
      :8000  ▼                       :5555  ▼
  ┌──────────────────┐       ┌──────────────────────────┐
  │  CTFd 3.7.5      │       │  Trigger Service (Flask) │
  │  challenges      │◀──────│  POST /run/static        │
  │  scoring         │       │  POST /run/dynamic       │
  │  leaderboard     │       │  POST /reset             │
  └────────┬─────────┘       └──────────────────────────┘
           │                          │
    ┌──────┴──────┐            ┌──────┴──────────────────────┐
    │  MariaDB    │            │  bridge-static              │
    │  Redis      │            │  reads YAML → CTFd API      │
    └─────────────┘            │                             │
                               │  bridge (dynamic)           │
                               │  FortiCNAPP API → CTFd API  │
                               └─────────────────────────────┘
                                            │
                                ┌───────────┴──────────┐
                                │  FortiCNAPP / Lacework│
                                │  (live tenant — opt.) │
                                └──────────────────────┘
```

---

## Prerequisites

- **Docker** and **Docker Compose v2** (`docker compose version`)
- **Ports 80, 443, 5555** available for Caddy HTTPS (or just 8000 for HTTP-only)
- A **DuckDNS token** and subdomain (for HTTPS — free at [duckdns.org](https://www.duckdns.org))
- A **FortiCNAPP API key** (dynamic mode only)

---

## Quick Start

### 1 — Configure

```bash
cp .env.example .env
```

Edit `.env` — fill in the required fields:

```dotenv
# Required for CTFd to start
SECRET_KEY=any-strong-random-string

# Fill in after step 3 (CTFd setup wizard)
CTFD_ADMIN_TOKEN=

# For HTTPS (optional — skip for HTTP-only)
DUCKDNS_TOKEN=your-duckdns-token

# For Live CTF mode (optional — skip for CTF Lab)
FORTICNAPP_ACCOUNT=your-account
FORTICNAPP_API_KEY_ID=YOUR_KEY_ID
FORTICNAPP_API_SECRET=_your_secret
```

### 2 — Start the stack

```bash
# HTTP only (quick demo / local)
docker compose up -d db cache ctfd trigger

# HTTPS (production / event)
docker compose up -d db cache ctfd trigger caddy
```

Wait ~15 seconds, then open:
- **HTTP**: `http://localhost:8000`
- **HTTPS**: `https://your-domain.duckdns.org`

### 3 — Complete the CTFd setup wizard

1. Enter your event name (e.g. *Capture the Flag powered by FortiCNAPP*)
2. Create an admin user — **remember these credentials**
3. Choose **Users** or **Teams** scoring mode
4. Click **Finish Setup**

### 4 — Generate an admin API token

**Admin Panel → Settings → Tokens → Generate**

Paste it into `.env`:

```dotenv
CTFD_ADMIN_TOKEN=ctfd_xxxxxxxxxxxxxxxx
```

Then restart the trigger service so it picks up the new token:

```bash
docker compose restart trigger
```

### 5 — Load challenges from the home page

Open the CTFd home page. You will see two cards:

| Card | What it does |
|---|---|
| **CTF Lab** | Loads 21 pre-authored YAML challenges (no API needed) |
| **Live CTF** | Prompts for FortiCNAPP credentials, then generates challenges from live data |

Click **Load Lab Challenges** or **Load Live Challenges**, wait for the status to turn green, then click **Start Challenges**.

> **CLI alternative:** you can also run the bridges directly:
> ```bash
> docker compose run --rm bridge-static   # CTF Lab
> docker compose run --rm bridge          # Live CTF
> ```

---

## Modes in Detail

### CTF Lab (Static)

Pre-authored challenges covering real FortiCNAPP scenarios. No credentials needed. Works offline.

**21 challenges across 4 categories:**

| Category | # | Topics covered |
|---|---|---|
| 🔴 Alert Triage | 5 | MITRE ATT&CK T1496 · T1078.004 · T1571 · alert categories · composite alerts |
| 🟠 Host Security | 5 | CVE identification · CVSS scoring · hostname lookup · agentless scanning |
| 🔵 Container Security | 5 | Shadow MCP detection · crypto mining · Docker forensics · port exposure |
| 🟡 Cloud Compliance | 6 | CIS AWS 1.5 · 1.14 · 2.1.5 · 3.1 · 5.2x · CSPM acronym |

Challenges live in `static_ctf/ctf/*/challenges.yml`. Edit freely and reload — the builder is **fully idempotent** (create on first run, update on re-run).

### Live CTF (Dynamic)

Pulls real findings from your FortiCNAPP tenant and auto-generates challenges.

**FortiCNAPP Console → Settings → API Keys → Create New**

Download the JSON file — it contains `keyId`, `secret`, and `account`.

Add to `.env`:

```dotenv
FORTICNAPP_ACCOUNT=acme-prod          # subdomain: acme-prod.lacework.net → acme-prod
FORTICNAPP_SUBACCOUNT=                # leave blank unless using sub-accounts
FORTICNAPP_API_KEY_ID=ACME_1234...
FORTICNAPP_API_SECRET=_your_secret
LOOKBACK_HOURS=72                     # how far back to pull alerts (72h default)
MAX_CHALLENGES_PER_CATEGORY=5         # cap per category
```

| Category | FortiCNAPP API endpoint |
|---|---|
| Alert Triage | `/api/v2/Alerts` (MITRE-tagged alerts) |
| Host Security | `/api/v2/Vulnerabilities/Hosts/search` |
| Container Security | `/api/v2/Vulnerabilities/Containers/search` |
| Cloud Compliance | `/api/v2/Configs/ComplianceEvaluations/search` |

**Offline rehearsal (mock mode)** — reads from `sample_data/*.json` instead of the live API:

```dotenv
MOCK_MODE=true
```

### Sanitization

When `SANITIZE=true` (default — **always on for customer demos**), the bridge scrubs:

- AWS 12-digit account IDs and ARNs
- Azure subscription UUIDs
- GCP project identifiers
- S3 bucket names
- Public IPv4 addresses
- Email addresses and public DNS hostnames

The mapping is stable per run — the same real value always produces the same anonymized value, so challenge descriptions stay internally consistent.

---

## HTTPS Setup

Uses [Caddy](https://caddyserver.com/) with a custom [DuckDNS](https://www.duckdns.org) DNS-01 plugin.
The cert is issued automatically — **port 80 does not need to be open to the internet.**

### 1 — Get a DuckDNS subdomain

1. Log in at [duckdns.org](https://www.duckdns.org)
2. Create a subdomain (e.g. `samvblogs`)
3. Set its **A record** to your host's public IP
4. Copy your **token** from the top of the page

### 2 — Configure

```dotenv
# In .env
DUCKDNS_TOKEN=your-token-here
```

Update `caddy/Caddyfile` if you are using a different domain:

```
samvblogs.duckdns.org {          # ← change this
    tls { dns duckdns {env.DUCKDNS_TOKEN} }
    reverse_proxy ctfd:8000
}
samvblogs.duckdns.org:5555 {    # ← and this
    tls { dns duckdns {env.DUCKDNS_TOKEN} }
    reverse_proxy trigger:5555
}
```

### 3 — Start

```bash
docker compose up -d db cache ctfd trigger caddy
```

Caddy fetches the certificate on first start (~30 seconds), then renews it automatically.

> ⚠️ **Never delete the `caddy_data` Docker volume** — Let's Encrypt rate-limits to 5 certs per domain per week.

---

## Event Workflow

### Before the event (presenter setup, ~5 min)

```bash
# 1. Start the stack
docker compose up -d db cache ctfd trigger

# 2. Complete the CTFd setup wizard at http://localhost:8000
#    → create admin user, choose Users/Teams mode, Finish Setup

# 3. Generate admin token: Admin Panel → Settings → Tokens → Generate
#    → paste into .env as CTFD_ADMIN_TOKEN=ctfd_...
#    → docker compose restart trigger

# 4. Load challenges — either via home page cards, or:
docker compose run --rm bridge-static   # CTF Lab
docker compose run --rm bridge          # Live CTF (needs .env credentials)

# 5. Make challenges visible
#    Admin Panel → Configs → Challenge Visibility → Public
```

### During the event (participants)

1. **Register** at the CTFd URL
2. **Read** the challenge scenario
3. **Navigate** FortiCNAPP console to find the answer
4. **Submit** `FLAG{answer}` → scored instantly
5. Watch the **live leaderboard** update

**Suggested 45-minute arc:**

| Time | Round | Skill reinforced |
|---|---|---|
| 0–2 min | Scene-setting | — |
| 2–17 min | 🔴 Alert Triage | MITRE mapping accelerates IR |
| 17–32 min | 🟠 🔵 Host + Container Security | CWPP value vs. siloed scanners |
| 32–42 min | 🟡 Cloud Compliance | CSPM + audit story |
| 42–45 min | Debrief + leaderboard | Walk one finding live in console |

---

## Adding Custom Challenges

Edit or create YAML files in `static_ctf/ctf/<category>/challenges.yml`.
Reload with:

```bash
docker compose run --rm bridge-static
# or click "Load Lab Challenges" on the home page
```

**Minimal challenge template:**

```yaml
challenges:
  - name: "My Challenge Title"
    author: "Your Name"
    category: "Alert Triage"
    description: |
      Find the alert triggered by technique **T1496** and submit the MITRE ID.
    value: 100
    type: standard
    flags:
      - content: "FLAG{T1496}"
        type: static
    hints:
      - content: "Check the Alert Triage dashboard in FortiCNAPP."
    tags:
      - mitre
      - alerts
    state: visible
```

---

## Project Layout

```
forticnapp-ctf/
├── docker-compose.yml               # full stack definition
├── .env.example                     # copy to .env — never commit .env
├── README.md
│
├── theme/                           # Fortinet dark theme
│   ├── fortinet.css                 # main theme (injected into CTFd)
│   ├── fortinet-admin.css           # admin panel overrides
│   ├── admin_base.html              # admin panel base template
│   └── SOC.png                      # hero image
│
├── static_ctf/                      # ── CTF Lab (static mode) ─────────────
│   ├── Dockerfile
│   ├── build.py                     # entrypoint: reads env → builds CTF
│   ├── ctfbuilder.py                # idempotent challenge push (create + update)
│   ├── ctfd.py                      # CTFd REST API wrapper
│   ├── home.html                    # custom CTFd home page (mode selector cards)
│   ├── fortinet.css                 # theme copy for static container
│   ├── requirements.txt
│   └── ctf/
│       ├── config.yml               # CTFd event settings
│       ├── 1_Alert Triage/
│       │   └── challenges.yml
│       ├── 2_Host Security/
│       │   └── challenges.yml
│       ├── 3_Container Security/
│       │   └── challenges.yml
│       └── 4_Cloud Compliance/
│           └── challenges.yml
│
├── forticnapp_ctf_api/              # ── Live CTF (dynamic mode) ───────────
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── bridge.py                    # orchestrator: pull → sanitize → push
│   ├── forticnapp_client.py         # FortiCNAPP/Lacework v2 API client
│   ├── ctfd_client.py               # CTFd admin API client
│   ├── challenges.py                # finding → Challenge object mapping
│   └── sanitize.py                  # PII scrubber for customer-safe demos
│
├── trigger/                         # ── Trigger service (always-on) ───────
│   ├── Dockerfile
│   ├── app.py                       # Flask API: /run/static /run/dynamic /reset
│   └── requirements.txt
│
├── caddy/                           # ── HTTPS reverse proxy ───────────────
│   ├── Dockerfile                   # custom Caddy build with DuckDNS plugin
│   └── Caddyfile                    # TLS config + proxy rules
│
└── sample_data/                     # mock data for MOCK_MODE=true
    ├── alerts.json
    ├── container_vulns.json
    ├── host_vulns.json
    └── compliance.json
```

---

## Flag Format

```
FLAG{answer}
```

| Category | Answer is… |
|---|---|
| Alert Triage | MITRE technique ID — `T1496`, `T1078.004` |
| Host Security | CVE ID — `CVE-2025-12345`, or hostname |
| Container Security | Image name, port, or acronym |
| Cloud Compliance | CIS control number — `1.5`, `2.1.5` |

All flags are case-insensitive.

---

## Useful Commands

```bash
# Start (HTTP only)
docker compose up -d db cache ctfd trigger

# Start (HTTPS)
docker compose up -d db cache ctfd trigger caddy

# Stop Caddy only (revert to HTTP)
docker compose stop caddy

# Stop everything (keep data)
docker compose down

# Full reset — wipes database and all scores
docker compose down -v

# Watch logs
docker compose logs -f ctfd
docker compose logs -f trigger

# Check container health
docker compose ps

# Load challenges manually (CLI)
docker compose run --rm bridge-static   # CTF Lab
docker compose run --rm bridge          # Live CTF

# Rebuild an image after code changes
docker compose build trigger
docker compose up -d trigger
```

---

## Troubleshooting

**CTFd keeps restarting**
Add `SECRET_KEY=any-strong-random-string` to `.env`.

**Admin token rejected (401)**
Regenerate: Admin Panel → Settings → Tokens. Update `CTFD_ADMIN_TOKEN` in `.env`, then `docker compose restart trigger`.

**Home page cards show "already running"**
A previous build is still in progress. Check `GET http://localhost:5555/status/static` or wait a minute.

**0 challenges generated (Live CTF)**
1. Check credentials: `FORTICNAPP_ACCOUNT`, `FORTICNAPP_API_KEY_ID`, `FORTICNAPP_API_SECRET`
2. Widen the search window: `LOOKBACK_HOURS=720`
3. Test offline: `MOCK_MODE=true`

**Container Security returns 0 (dynamic)**
Agentless Workload Scanning must be enabled on the tenant. Set `LOOKBACK_HOURS=720` or `MOCK_MODE=true`.

**HTTPS cert not issuing**
- Verify DNS A record points to your host's public IP
- Check `DUCKDNS_TOKEN` is set in `.env`
- View Caddy logs: `docker compose logs -f caddy`

**Challenges not visible to participants**
Admin Panel → Configs → Challenge Visibility → set to **Public**.

---

## License & Attribution

CTFd is [BSD-2-Clause licensed](https://github.com/CTFd/CTFd/blob/master/LICENSE).
FortiCNAPP and Lacework are trademarks of Fortinet, Inc.
This project has no official affiliation with CTFd.
