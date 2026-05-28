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
Participants investigate alerts, triage vulnerabilities, and map compliance violations in the
FortiCNAPP console — then submit answers on a live leaderboard.

**Two modes, one stack:**

| Mode | Challenges | Needs FortiCNAPP tenant | Best for |
|---|---|---|---|
| **CTF Lab** | 21 hand-authored | ❌ No | Demos, offline, rehearsal |
| **Live CTF** | Generated from real findings | ✅ Yes | Live events with a real tenant |

On first boot, **5 random CNAPP warm-up questions** are loaded automatically — no setup needed.

---

## Architecture

```
Browser
  │
  │  https://localhost        (CTFd — port 443)
  │  https://localhost:5555   (Trigger API)
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│  Caddy  (HTTPS reverse proxy — self-signed cert)         │
└────────────┬──────────────────────────────┬─────────────┘
             │                              │
      :8000  ▼                       :5555  ▼
  ┌──────────────────┐       ┌──────────────────────────┐
  │  CTFd 3.7.5      │       │  Trigger Service (Flask) │
  │  challenges      │◀──────│  /run/static             │
  │  scoring         │       │  /run/dynamic            │
  │  leaderboard     │       │  /reset                  │
  └────────┬─────────┘       └──────────────────────────┘
           │                          │
    ┌──────┴──────┐            ┌──────┴──────────────────────┐
    │  MariaDB    │            │  bridge-static              │
    │  Redis      │            │  YAML challenges → CTFd     │
    └─────────────┘            │                             │
                               │  bridge (dynamic)           │
                               │  FortiCNAPP API → CTFd      │
                               └─────────────────────────────┘
```

---

## Prerequisites

- **Docker** and **Docker Compose v2** — `docker compose version`
- **Python 3.10+** — to run `ctl.py`
- **Ports 80, 443, 5555** available on the host

> No domain name, DNS token, or internet access required.
> Caddy issues a self-signed cert automatically.

---

## Quick Start

```bash
python ctl.py
```

On first run, the setup wizard launches automatically. It walks through three sections:

| Section | What it asks |
|---|---|
| **CTFd** | DB passwords, admin username / email / password |
| **HTTPS** | Hostname or IP — leave blank for `localhost` |
| **FortiCNAPP API** | Account, Key ID, Secret — only needed for Live CTF |

Then press **`1` (START)**. The script:

1. Starts `db`, `cache`, `ctfd`
2. Completes the CTFd first-run wizard automatically (no browser step needed)
3. Generates and saves an admin API token to `.env`
4. Starts `trigger` and `caddy`
5. Applies the Fortinet theme
6. Loads 5 random CNAPP warm-up questions if the database is empty

Open **`https://localhost`** — accept the browser security warning once (self-signed cert).

---

## Home Page

The CTFd home page has two mode cards and a reset control:

| Button | Action |
|---|---|
| **Load CTF Lab Challenges** | Loads 21 static challenges; unlocks the CTF Lab *Start Challenges* button |
| **Load Live Challenges** | Pulls findings from your FortiCNAPP tenant; unlocks the Live CTF *Start Challenges* button |
| **Reset** (either card) | Clears all challenges and reloads 5 random CNAPP warm-up questions |

> **Start Challenges** is locked (🔒) until the matching mode has been loaded.
> The warm-up questions are for previewing only — load CTF Lab or Live CTF for the full event.

**Auto-reset:** if no one loads challenges or submits a flag for **24 hours**, the platform resets to warm-up questions automatically. Configurable via `INACTIVITY_RESET_HOURS` in `.env`.

---

## Control Panel (`ctl.py`)

```
╔══════════════════════════════════════════╗
║       FortiCNAPP CTF — Control Panel    ║
╚══════════════════════════════════════════╝

  STATUS
  ● CTFd   ● DB   ● Cache   ● Trigger   ● Caddy

  s  Setup / edit .env

  1  START    → https://localhost
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
| `1` | Start full stack — auto-configures CTFd on first run |
| `2` | Stop all containers (data kept in Docker volumes) |
| `3` | Stop then start |
| `4` | Stop → remove all containers + volumes → clear admin token |
| `5` / `6` | Tail CTFd / Trigger logs |

---

## Flag Format

### Warm-up questions (default / Reset)

Plain answer — no wrapper needed:

```
transport_layer_security
cloud_security_posture_management
misconfiguration
```

The challenge description always shows the expected format, e.g. `Example format: word_word_word`.

### CTF Lab and Live CTF challenges

Standard CTF flag format:

```
FLAG{answer}
```

| Category | Answer is… |
|---|---|
| Alert Triage | MITRE technique ID — `FLAG{T1496}` |
| Host Security | CVE ID or hostname — `FLAG{CVE-2025-12345}` |
| Container Security | Image name, port, or acronym |
| Cloud Compliance | CIS control number — `FLAG{1.5}` |

All flags are case-insensitive.

---

## Modes in Detail

### CTF Lab (Static)

21 hand-authored challenges covering real FortiCNAPP scenarios. No credentials needed. Works offline.

| Category | # | Topics |
|---|---|---|
| 🔴 Alert Triage | 5 | MITRE ATT&CK T1496 · T1078.004 · T1571 · composite alerts |
| 🟠 Host Security | 5 | CVE ID · CVSS scoring · hostname lookup · agentless scanning |
| 🔵 Container Security | 5 | Shadow MCP · crypto mining · Docker forensics · port exposure |
| 🟡 Cloud Compliance | 6 | CIS AWS 1.5 · 1.14 · 2.1.5 · 3.1 · 5.2x · CSPM |

Challenge files: `static_ctf/ctf/*/challenges.yml` — edit freely and reload. The builder is fully idempotent (create on first run, update on re-run).

### Live CTF (Dynamic)

Pulls real findings from your FortiCNAPP tenant and auto-generates challenges.

**FortiCNAPP Console → Settings → API Keys → Create New**

Download the JSON — it contains `keyId`, `secret`, and `account`. Enter them in the setup wizard or add directly to `.env`:

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

**Sanitization** — when `SANITIZE=true` (default), the bridge scrubs all customer-identifiable data: AWS account IDs, Azure subscription UUIDs, GCP project IDs, S3 bucket names, public IPs, email addresses, and hostnames. The mapping is stable per run so challenge descriptions stay internally consistent.

---

## HTTPS

Caddy uses `tls internal` — its built-in local CA issues a self-signed cert at startup. No domain or internet access required.

**First visit:** the browser shows a security warning. Click **Advanced → Accept** (Chrome/Edge) or **Accept the Risk** (Firefox). One-time per browser.

**Custom hostname or IP** (for participants on the same network):

```dotenv
# .env
FQDN=192.168.1.100
```

Caddy will issue a cert for that address. Participants accept the warning once.

---

## Event Workflow

### Before the event (~5 min)

```bash
# 1. Start everything
python ctl.py  →  1

# 2. Load the challenge mode you want
#    — Use the home page buttons, or from the CLI:
docker compose run --rm bridge-static   # CTF Lab
docker compose run --rm bridge          # Live CTF

# 3. Make challenges visible
#    Admin Panel → Configs → Challenge Visibility → Public
```

### During the event

1. Participants **register** at `https://your-host`
2. **Read** the challenge scenario
3. **Navigate** the FortiCNAPP console to find the answer
4. **Submit** the flag — scored instantly
5. Watch the **live leaderboard** update

**Suggested 45-minute arc:**

| Time | Round | Skill |
|---|---|---|
| 0–2 min | Scene-setting | — |
| 2–17 min | 🔴 Alert Triage | MITRE mapping accelerates IR |
| 17–32 min | 🟠🔵 Host + Container Security | CWPP value vs. siloed scanners |
| 32–42 min | 🟡 Cloud Compliance | CSPM + audit story |
| 42–45 min | Debrief + leaderboard | Walk one finding live in console |

### After the event — full reset

```bash
python ctl.py  →  4  →  YES
```

Stops all containers and wipes all volumes (scores, users, challenges). Press `1` to rebuild from scratch.

---

## Adding Custom Challenges

Edit or create YAML files in `static_ctf/ctf/<category>/challenges.yml`, then reload:

```bash
docker compose run --rm bridge-static
```

**Minimal challenge template:**

```yaml
challenges:
  - name: "My Challenge"
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
    state: visible
```

---

## Project Layout

```
forticnapp-ctf/
├── ctl.py                           # ← single entry point
├── docker-compose.yml
├── .env.example                     # copy to .env — never commit .env
│
├── static_ctf/                      # CTF Lab (static mode)
│   ├── build.py                     # entrypoint: reads env → builds CTF
│   ├── ctfbuilder.py                # idempotent challenge push
│   ├── ctfd.py                      # CTFd REST API wrapper
│   ├── fortinet.css                 # Fortinet dark theme
│   ├── home.html                    # home page (mode selector cards)
│   └── ctf/
│       ├── config.yml
│       ├── 1_Alert Triage/
│       ├── 2_Host Security/
│       ├── 3_Container Security/
│       └── 4_Cloud Compliance/
│
├── forticnapp_ctf_api/              # Live CTF (dynamic mode)
│   ├── bridge.py                    # pull → sanitize → push
│   ├── forticnapp_client.py         # FortiCNAPP v2 API client
│   ├── ctfd_client.py               # CTFd admin API client
│   ├── challenges.py                # finding → Challenge mapping
│   └── sanitize.py                  # PII scrubber
│
├── trigger/                         # Always-on trigger service
│   └── app.py                       # Flask: /run/static /run/dynamic /reset
│                                    # Auto-configures CTFd on first boot
│                                    # Auto-resets after inactivity
│
├── caddy/                           # HTTPS reverse proxy
│   └── Caddyfile                    # tls internal — self-signed cert
│
└── sample_data/                     # Mock data for MOCK_MODE=true
    ├── alerts.json
    ├── container_vulns.json
    ├── host_vulns.json
    └── compliance.json
```

---

## Useful Commands

```bash
# Start everything
python ctl.py

# Load / reload challenges
docker compose run --rm bridge-static   # CTF Lab
docker compose run --rm bridge          # Live CTF

# Re-apply Fortinet theme only (no challenge changes)
docker compose run --rm bridge-static --theme-only

# Watch logs
docker compose logs -f ctfd
docker compose logs -f trigger

# Check container health
docker compose ps

# Rebuild an image after code changes
docker compose build <service> && docker compose up -d <service>

# Check inactivity auto-reset timer
curl https://localhost:5555/status/inactivity
```

---

## Troubleshooting

**Browser shows security warning**
Expected — self-signed cert. Click **Advanced → Accept** once per browser.

**Home page is blank or shows default CTFd theme**
Click **Re-apply Fortinet Theme** at the bottom of the home page, or run:
```bash
docker compose run --rm bridge-static --theme-only
```

**Start Challenges button is locked (🔒)**
Click **Load CTF Lab Challenges** or **Load Live Challenges** first. The button unlocks after a successful load.

**CTFd keeps restarting**
Check `SECRET_KEY` is set in `.env` (auto-generated by `ctl.py`).

**Admin token rejected (401)**
Run `python ctl.py` → `s` → paste a fresh token from **Admin Panel → Settings → Tokens**.

**Home page shows "already running"**
A build is in progress. Wait ~1 minute or check `docker compose logs trigger`.

**0 challenges generated (Live CTF)**
1. Verify `.env`: `FORTICNAPP_ACCOUNT`, `FORTICNAPP_API_KEY_ID`, `FORTICNAPP_API_SECRET`
2. Widen the window: `LOOKBACK_HOURS=720`
3. Test offline: `MOCK_MODE=true`

**Container Security returns 0 (dynamic)**
Agentless Workload Scanning must be enabled on the tenant. Use `LOOKBACK_HOURS=720` or `MOCK_MODE=true`.

**Challenges not visible to participants**
Admin Panel → Configs → Challenge Visibility → **Public**.

**Docker layer cache error on build**
```bash
docker builder prune -f
docker compose build --no-cache
docker compose up -d
```

---

## License & Attribution

CTFd is [BSD-2-Clause licensed](https://github.com/CTFd/CTFd/blob/master/LICENSE).
FortiCNAPP and Lacework are trademarks of Fortinet, Inc.
This project has no official affiliation with CTFd.
