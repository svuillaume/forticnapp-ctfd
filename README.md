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
  │  https://localhost        (CTFd UI — port 443, self-signed cert)
  │  https://localhost:5555   (Trigger API)
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│  Caddy  (HTTPS reverse proxy — tls internal)             │
│  Self-signed cert via Caddy's built-in local CA          │
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
```

---

## Prerequisites

- **Docker** and **Docker Compose v2** (`docker compose version`)
- **Python 3.10+** (to run `ctl.py`)
- **Ports 443 and 5555** available on the host

> No domain name, no DNS token, no certificate authority needed.
> Caddy issues a self-signed cert automatically on first start.

---

## Quick Start

Everything is driven by a single control script.

### 1 — Run the control script

```bash
python ctl.py
```

On first run it detects a missing `.env` and launches the setup wizard automatically.

The wizard walks through **3 sections**:

| Section | What it asks |
|---|---|
| **CTFd internal** | DB passwords (default `root`/`root`), CTFd admin credentials |
| **HTTPS** | Hostname or IP (blank = `localhost`) |
| **FortiCNAPP API** | Account, Key ID, Secret — for Live CTF mode only |

> Admin credentials (username, email, password) are used by `ctl.py` to complete the
> CTFd first-run wizard automatically — no manual browser step needed.

### 2 — Start

Press **`1`** (START). The script:

1. Starts `db`, `cache`, `ctfd`
2. Waits for CTFd to be healthy
3. Automatically completes the CTFd setup wizard
4. Generates and saves an admin API token to `.env`
5. Starts `trigger` and `caddy`

Open **`https://localhost`** — accept the browser security warning (self-signed cert, one-time click).

### 3 — Load challenges

On the CTFd home page, click **CTF Lab** or **Live CTF** to load challenges.

Or from the command line:

```bash
docker compose run --rm bridge-static   # CTF Lab (21 static challenges)
docker compose run --rm bridge          # Live CTF (requires FortiCNAPP credentials)
```

> `bridge-static` loads both the **home page** and the **challenges**.
> Run it again any time to restore them after a DESTROY.

---

## Control Panel (`ctl.py`)

```
╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝

  STATUS
  ● CTFd   ● DB   ● Cache   ● Trigger   ● Caddy

  s  Setup / edit .env

  1  START    → https://localhost  (self-signed cert)
  2  STOP     (containers stopped, data kept)
  3  RESTART
  4  DESTROY  ⚠️  removes containers + volumes — all data lost

  5  Logs (CTFd)
  6  Logs (Trigger)
  q  Quit
```

| Option | What it does |
|---|---|
| `s` | Re-open the setup wizard to edit any `.env` value |
| `1` | Start full stack; auto-completes CTFd setup on first run |
| `2` | Stop all containers (data kept in Docker volumes) |
| `3` | Stop then start |
| `4` | Stop → remove all containers and volumes → clear admin token |
| `5` / `6` | Tail CTFd / Trigger logs |

---

## HTTPS

Caddy uses `tls internal` — its built-in local certificate authority issues a self-signed cert instantly at startup. No domain name, DNS token, or internet access required.

**On first visit** the browser shows a security warning. Click **Advanced → Accept** (Chrome/Edge) or **Accept the Risk** (Firefox). This is a one-time step per browser.

To use a custom hostname or IP (e.g. for participants on the same network):

```dotenv
# .env
FQDN=192.168.1.100
```

Caddy will issue a self-signed cert for that address. Participants will also need to accept the browser warning once.

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

Download the JSON file — it contains `keyId`, `secret`, and `account`. Enter them when the wizard asks (section 3), or add directly to `.env`:

```dotenv
FORTICNAPP_ACCOUNT=acme-prod
FORTICNAPP_SUBACCOUNT=
FORTICNAPP_API_KEY_ID=ACME_1234...
FORTICNAPP_API_SECRET=_your_secret
LOOKBACK_HOURS=72
MAX_CHALLENGES_PER_CATEGORY=5
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

When `SANITIZE=true` (default), the bridge scrubs all customer-identifiable data:

- AWS account IDs and ARNs · Azure subscription UUIDs · GCP project IDs
- S3 bucket names · Public IPv4 addresses · Email addresses · Public hostnames

The mapping is stable per run — the same real value always produces the same anonymized value, keeping challenge descriptions internally consistent.

---

## Event Workflow

### Before the event (~5 min)

```bash
# 1. Start everything (auto-configures CTFd on first run)
python ctl.py  →  press 1

# 2. Load challenges
docker compose run --rm bridge-static          # CTF Lab
docker compose run --rm bridge                 # Live CTF

# 3. Make challenges visible to participants
#    Admin Panel → Configs → Challenge Visibility → Public
```

### During the event

1. **Register** at `https://localhost` (or your configured FQDN)
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

### After the event — full reset

```
python ctl.py  →  press 4  →  type YES
```

Stops all containers, wipes all volumes (scores, users, challenges), clears the admin token. Press `1` to rebuild from scratch.

---

## Adding Custom Challenges

Edit or create YAML files in `static_ctf/ctf/<category>/challenges.yml`, then reload:

```bash
docker compose run --rm bridge-static
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
├── ctl.py                           # ← single entry point — run this
├── docker-compose.yml
├── .env.example                     # copy to .env — never commit .env
├── README.md
│
├── theme/                           # Fortinet dark theme
│   ├── fortinet.css
│   ├── fortinet-admin.css
│   ├── admin_base.html
│   └── SOC.png
│
├── static_ctf/                      # ── CTF Lab (static mode) ─────────────
│   ├── Dockerfile
│   ├── build.py                     # entrypoint: reads env → builds CTF
│   ├── ctfbuilder.py                # idempotent challenge push (create + update)
│   ├── ctfd.py                      # CTFd REST API wrapper
│   ├── home.html                    # custom home page (CTF Lab / Live CTF cards)
│   ├── requirements.txt
│   └── ctf/
│       ├── config.yml
│       ├── 1_Alert Triage/challenges.yml
│       ├── 2_Host Security/challenges.yml
│       ├── 3_Container Security/challenges.yml
│       └── 4_Cloud Compliance/challenges.yml
│
├── forticnapp_ctf_api/              # ── Live CTF (dynamic mode) ───────────
│   ├── Dockerfile
│   ├── bridge.py                    # orchestrator: pull → sanitize → push
│   ├── forticnapp_client.py         # FortiCNAPP/Lacework v2 API client
│   ├── ctfd_client.py               # CTFd admin API client
│   ├── challenges.py                # finding → Challenge mapping
│   ├── sanitize.py                  # PII scrubber
│   └── requirements.txt
│
├── trigger/                         # ── Trigger service (always-on) ───────
│   ├── Dockerfile
│   ├── app.py                       # Flask: /run/static /run/dynamic /reset
│   └── requirements.txt
│
├── caddy/                           # ── HTTPS reverse proxy ───────────────
│   ├── Dockerfile                   # plain caddy:latest (no plugins needed)
│   └── Caddyfile                    # tls internal — self-signed cert
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
# Start everything
python ctl.py

# Load / reload challenges (also restores the home page)
docker compose run --rm bridge-static   # CTF Lab
docker compose run --rm bridge          # Live CTF

# Watch logs
docker compose logs -f ctfd
docker compose logs -f caddy
docker compose logs -f trigger

# Check container health
docker compose ps

# Rebuild an image after code changes
docker compose build <service>
docker compose up -d <service>
```

---

## Troubleshooting

**Browser shows security warning on HTTPS**
Expected — Caddy uses a self-signed cert. Click **Advanced → Accept** once per browser.

**Home page is blank / CTF Lab card missing**
Run `docker compose run --rm bridge-static` to restore the home page and all challenges.

**CTFd keeps restarting**
Check `SECRET_KEY` is set in `.env` (auto-generated by `ctl.py`).

**Admin token rejected (401)**
Run `python ctl.py` → press `s` → paste a fresh token from **Admin Panel → Settings → Tokens**.

**Home page cards show "already running"**
A previous build is still in progress. Wait ~1 minute or check `docker compose logs trigger`.

**0 challenges generated (Live CTF)**
1. Check `.env`: `FORTICNAPP_ACCOUNT`, `FORTICNAPP_API_KEY_ID`, `FORTICNAPP_API_SECRET`
2. Widen the window: `LOOKBACK_HOURS=720`
3. Test offline: `MOCK_MODE=true`

**Container Security returns 0 (dynamic)**
Agentless Workload Scanning must be enabled on the tenant. Use `LOOKBACK_HOURS=720` or `MOCK_MODE=true`.

**Challenges not visible to participants**
Admin Panel → Configs → Challenge Visibility → set to **Public**.

**Docker permission denied**
`ctl.py` offers to fix this automatically, or run manually:
```bash
sudo usermod -aG docker $USER && newgrp docker
```

---

## License & Attribution

CTFd is [BSD-2-Clause licensed](https://github.com/CTFd/CTFd/blob/master/LICENSE).
FortiCNAPP and Lacework are trademarks of Fortinet, Inc.
This project has no official affiliation with CTFd.
