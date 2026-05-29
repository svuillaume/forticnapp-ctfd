#!/usr/bin/env python3
"""
FortiCNAPP CTF Trigger Service
———————————————————————————————
Provides a lightweight HTTP API that runs the static or dynamic
CTF builders on demand.  Embedded inside CTFd via the home page
JavaScript so presenters can switch modes from the browser.

Endpoints:
  POST /run/static          — run bridge-static (YAML challenges)
  POST /run/dynamic         — run bridge (live FortiCNAPP API)
  POST /reset               — delete all challenges then load 5 default CNAPP questions
  GET  /status/static|dynamic — last build status + tail of log
  GET  /health              — liveness probe

No authentication token is required from the browser.  The admin token
lives only in this container's environment and is never sent to clients.
"""

import os
import subprocess
import threading
import time
import logging
import sys
from flask import Flask, jsonify, request, abort
from flask_cors import CORS

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    level=os.environ.get('LOG_LEVEL', 'INFO').upper(),
    stream=sys.stdout,
)
logger = logging.getLogger('trigger')

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

ADMIN_TOKEN   = os.environ.get('CTFD_ADMIN_TOKEN', '')
CTFD_URL      = os.environ.get('CTFD_API_URL', 'http://ctfd:8000')
ADMIN_PASS    = os.environ.get('CTFD_ADMIN_PASSWORD', 'admin')
ADMIN_NAME    = os.environ.get('CTFD_ADMIN_NAME', 'admin')
ADMIN_EMAIL   = os.environ.get('CTFD_ADMIN_EMAIL', 'admin@ctf.local')
CTF_NAME_ENV  = os.environ.get('CTF_NAME', 'Capture the Flag powered by FortiCNAPP')

# ── State ─────────────────────────────────────────────────────────────────────

STATUS: dict = {
    'static':  {'status': 'idle', 'log': '', 'started': None, 'finished': None},
    'dynamic': {'status': 'idle', 'log': '', 'started': None, 'finished': None},
    'reset':   {'status': 'idle', 'log': '', 'started': None, 'finished': None},
}
LOCK: dict = {
    'static':  threading.Lock(),
    'dynamic': threading.Lock(),
    'reset':   threading.Lock(),
}

# ── Inactivity auto-reset ─────────────────────────────────────────────────────
# Updated whenever a user triggers a build, reset, or submits a challenge flag.
# The watchdog thread compares this against time.time() every 30 min.
INACTIVITY_RESET_HOURS: int = int(os.environ.get('INACTIVITY_RESET_HOURS', 24))
_last_activity: float       = time.time()   # seconds since epoch


# ── Build runners ─────────────────────────────────────────────────────────────

def _run_static():
    """Clear all challenges then run the full CTF Lab build (21 challenges)."""
    global _last_activity
    _last_activity = time.time()

    import importlib.util, io, unittest.mock as mock

    s = STATUS['static']
    s['status']  = 'running'
    s['log']     = ''
    s['started'] = time.time()
    s['finished'] = None

    buf = io.StringIO()
    buf.write('=== Clearing existing challenges ===\n')
    result = _delete_all_challenges()
    buf.write(f"Deleted {result['deleted']} challenge(s).\n\n")
    buf.write('=== Building CTF Lab challenges ===\n')

    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = buf

    try:
        spec = importlib.util.spec_from_file_location('build', '/app/build.py')
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with mock.patch('sys.argv', ['build.py', '--build']):
            mod.main()
        s['status'] = 'success'
    except SystemExit as e:
        s['status'] = 'success' if str(e) == '0' else 'error'
    except Exception:
        logger.exception('Static build failed')
        s['status'] = 'error'
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
        s['log']      = buf.getvalue()[-4000:]
        s['finished'] = time.time()


def _run_dynamic(account: str = '', key_id: str = '', secret: str = '',
                 subaccount: str = ''):
    """Clear all challenges then run the dynamic FortiCNAPP API build."""
    global _last_activity
    _last_activity = time.time()

    s = STATUS['dynamic']
    s['status']  = 'running'
    s['log']     = ''
    s['started'] = time.time()
    s['finished'] = None

    # Clear existing challenges first (clean slate before live build)
    clear_result = _delete_all_challenges()
    prefix_log = f"=== Cleared {clear_result['deleted']} existing challenge(s) ===\n\n"

    env = os.environ.copy()
    if account:    env['FORTICNAPP_ACCOUNT']   = account
    if key_id:     env['FORTICNAPP_API_KEY_ID'] = key_id
    if secret:     env['FORTICNAPP_API_SECRET'] = secret
    if subaccount: env['FORTICNAPP_SUBACCOUNT'] = subaccount

    def _restore_defaults():
        restore = _push_default_challenges(5)
        n = restore.get('created', 0)
        return f'\n[Auto-restored {n} default question(s) — use Reset on the home page to get a fresh set]'

    try:
        result = subprocess.run(
            ['python', '-m', 'dynamic'],
            capture_output=True, text=True, timeout=300,
            env=env, cwd='/app',
        )
        raw_log = prefix_log + (result.stdout + result.stderr)[-3800:]
        if result.returncode == 0:
            s['status'] = 'success'
            s['log']    = raw_log
        else:
            s['status'] = 'error'
            s['log']    = raw_log + _restore_defaults()
    except FileNotFoundError:
        s['status'] = 'error'
        s['log']    = prefix_log + 'Dynamic bridge not found at /app/dynamic.' + _restore_defaults()
    except subprocess.TimeoutExpired:
        s['status'] = 'error'
        s['log']    = prefix_log + 'Build timed out after 300 s.' + _restore_defaults()
    except Exception as exc:
        s['status'] = 'error'
        s['log']    = prefix_log + str(exc) + _restore_defaults()
    finally:
        s['finished'] = time.time()


# ── Default question pool (25 questions, 5 picked randomly on every Reset) ────

_DEFAULT_POOL = [
    {
        "name": "What does CNAPP stand for?",
        "desc": (
            "**CNAPP** is Fortinet's unified cloud security platform.\n\n"
            "What does the acronym stand for? Enter each word separated by underscores, all lowercase.\n\n"
            "Example format: `word_word_word_word_word`"
        ),
        "flag": "cloud_native_application_protection_platform",
        "hint": "Cloud + Native + Application + Protection + Platform",
    },
    {
        "name": "What does CSPM stand for?",
        "desc": (
            "This FortiCNAPP pillar continuously scans your cloud for **misconfigurations** "
            "and compliance violations against CIS, NIST, PCI-DSS, and SOC 2 benchmarks.\n\n"
            "What does **CSPM** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "cloud_security_posture_management",
        "hint": "It manages your cloud security posture. Cloud + Security + Posture + Management.",
    },
    {
        "name": "What does CWPP stand for?",
        "desc": (
            "This FortiCNAPP pillar scans running **VMs, containers, and serverless functions** "
            "for vulnerabilities, malware, and exposed secrets — agentlessly.\n\n"
            "What does **CWPP** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "cloud_workload_protection_platform",
        "hint": "Cloud + Workload + Protection + Platform",
    },
    {
        "name": "What does CIEM stand for?",
        "desc": (
            "Over-privileged IAM roles are among the top cloud attack vectors. "
            "This FortiCNAPP capability maps every identity and surfaces **excessive entitlements**.\n\n"
            "What does **CIEM** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "cloud_infrastructure_entitlements_management",
        "hint": "Cloud + Infrastructure + Entitlements + Management",
    },
    {
        "name": "What does CDR stand for?",
        "desc": (
            "FortiCNAPP uses **ML-based anomaly detection** on activity logs and audit trails "
            "to detect threats at runtime in cloud environments.\n\n"
            "What does **CDR** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "cloud_detection_and_response",
        "hint": "Think: Detect + Respond, in the cloud. Cloud + Detection + and + Response.",
    },
    {
        "name": "What does DSPM stand for?",
        "desc": (
            "This FortiCNAPP capability discovers and classifies **sensitive data** in cloud storage "
            "(S3, Azure Blob, GCS) and flags over-exposed buckets.\n\n"
            "What does **DSPM** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "data_security_posture_management",
        "hint": "Data + Security + Posture + Management",
    },
    {
        "name": "#1 Cloud Risk: One Word",
        "desc": (
            "Every major cloud security report (CSA, Gartner, Verizon DBIR) names the same leading "
            "root cause of cloud data breaches — not a zero-day, but a **preventable human error** "
            "when setting up cloud services.\n\n"
            "What **one-word term** describes this? Lowercase."
        ),
        "flag": "misconfiguration",
        "hint": "S3 bucket left public, SSH port open to the world, MFA disabled. These are all examples.",
    },
    {
        "name": "What does IAM stand for?",
        "desc": (
            "In cloud security, this framework controls **who can do what** on which resources. "
            "FortiCNAPP's CIEM pillar analyses it to detect excessive permissions.\n\n"
            "What does **IAM** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "identity_and_access_management",
        "hint": "Identity + and + Access + Management",
    },
    {
        "name": "What does IaC stand for?",
        "desc": (
            "FortiCNAPP includes **code security scanning** that catches misconfigurations "
            "before they reach production — in Terraform, CloudFormation, Bicep, and Helm.\n\n"
            "What does **IaC** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "infrastructure_as_code",
        "hint": "Your infrastructure defined in code files. Infrastructure + as + Code.",
    },
    {
        "name": "What does SBOM stand for?",
        "desc": (
            "Supply chain attacks like SolarWinds started with a **poisoned dependency**. "
            "This artifact lists every open-source library in a software release so you can "
            "check each one against known CVEs.\n\n"
            "What does **SBOM** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "software_bill_of_materials",
        "hint": "Like a bill of materials in manufacturing, but for software. Software + Bill + of + Materials.",
    },
    {
        "name": "What does RBAC stand for?",
        "desc": (
            "The principle of **least privilege** says users should only have the access they need. "
            "This access control model enforces it by assigning permissions to roles, not individuals.\n\n"
            "What does **RBAC** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "role_based_access_control",
        "hint": "Role + Based + Access + Control",
    },
    {
        "name": "What does CVE stand for?",
        "desc": (
            "FortiCNAPP's CWPP scans workloads and containers for known vulnerabilities, "
            "each identified by a unique ID in this registry maintained by MITRE.\n\n"
            "What does **CVE** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "common_vulnerabilities_and_exposures",
        "hint": "A global dictionary of publicly known security flaws. Common + Vulnerabilities + and + Exposures.",
    },
    {
        "name": "What does MFA stand for?",
        "desc": (
            "Stolen credentials are the #1 initial access vector in cloud breaches. "
            "This control requires a second proof of identity beyond the password — "
            "FortiCNAPP flags cloud accounts that don't enforce it.\n\n"
            "What does **MFA** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "multi_factor_authentication",
        "hint": "Multi + Factor + Authentication",
    },
    {
        "name": "What does SCA stand for?",
        "desc": (
            "This code security technique scans your project's **open-source dependencies** "
            "for known CVEs and licence violations — a key defence against supply chain attacks.\n\n"
            "What does **SCA** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "software_composition_analysis",
        "hint": "Software + Composition + Analysis",
    },
    {
        "name": "What does SIEM stand for?",
        "desc": (
            "FortiCNAPP can forward cloud security events to this platform, which **aggregates "
            "logs** from across the environment and correlates them into alerts for SOC analysts.\n\n"
            "What does **SIEM** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "security_information_and_event_management",
        "hint": "Security + Information + and + Event + Management",
    },
    {
        "name": "What does VPC stand for?",
        "desc": (
            "Cloud providers let you create an isolated network segment for your workloads. "
            "FortiCNAPP checks that **security groups and NACLs** inside this construct "
            "follow the least-privilege rule.\n\n"
            "What does **VPC** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "virtual_private_cloud",
        "hint": "Virtual + Private + Cloud",
    },
    {
        "name": "Least Privilege: Two Words",
        "desc": (
            "A core cloud security principle: every identity should only have the **minimum "
            "permissions** needed to perform its task — nothing more.\n\n"
            "Name this principle (two words, underscore-separated, lowercase).\n\n"
            "Example format: `word_word`"
        ),
        "flag": "least_privilege",
        "hint": "Think about the minimum necessary access. Least + Privilege.",
    },
    {
        "name": "What does XDR stand for?",
        "desc": (
            "FortiCNAPP cloud detections can feed into this platform, which correlates "
            "threats across **endpoint, network, email, and cloud** for a unified investigation view.\n\n"
            "What does **XDR** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "extended_detection_and_response",
        "hint": "Extended + Detection + and + Response",
    },
    {
        "name": "What does WAF stand for?",
        "desc": (
            "FortiCNAPP can detect when a cloud workload is targeted by injection attacks. "
            "The control layer that filters malicious HTTP requests before they reach the app is called…\n\n"
            "What does **WAF** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "web_application_firewall",
        "hint": "Web + Application + Firewall",
    },
    {
        "name": "What does CIS stand for?",
        "desc": (
            "FortiCNAPP maps cloud misconfigurations to benchmarks published by this non-profit "
            "organisation — their AWS, Azure, and GCP guides are the industry standard for "
            "**cloud configuration hardening**.\n\n"
            "What does **CIS** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "center_for_internet_security",
        "hint": "Center + for + Internet + Security",
    },
    {
        "name": "What does SAST stand for?",
        "desc": (
            "FortiCNAPP's code security scans source code **before it is compiled or run** "
            "to find vulnerabilities like hardcoded secrets, SQL injection, and path traversal.\n\n"
            "What does **SAST** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word_word`"
        ),
        "flag": "static_application_security_testing",
        "hint": "Static + Application + Security + Testing",
    },
    {
        "name": "Shared Responsibility: Who owns OS patches?",
        "desc": (
            "In the cloud **shared responsibility model**, the cloud provider secures the "
            "physical infrastructure. When you run a VM (IaaS), patching the operating system "
            "is whose responsibility?\n\n"
            "Answer: `customer` or `provider`"
        ),
        "flag": "customer",
        "hint": "The cloud provider manages the hypervisor and hardware. The OS running on the VM is yours.",
    },
    {
        "name": "What does TLS stand for?",
        "desc": (
            "FortiCNAPP flags cloud resources that expose services over unencrypted connections. "
            "This cryptographic protocol replaced SSL and protects data **in transit**.\n\n"
            "What does **TLS** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "transport_layer_security",
        "hint": "Transport + Layer + Security",
    },
    {
        "name": "What does SOC stand for?",
        "desc": (
            "FortiCNAPP is designed for analysts who work in this centralised team "
            "responsible for monitoring, detecting, and responding to security incidents "
            "across the organisation's cloud and on-premises environments.\n\n"
            "What does **SOC** stand for? Underscores, lowercase.\n\n"
            "Example format: `word_word_word`"
        ),
        "flag": "security_operations_center",
        "hint": "Security + Operations + Center",
    },
    {
        "name": "Agentless or Agent: FortiCNAPP default?",
        "desc": (
            "FortiCNAPP can scan cloud workloads for vulnerabilities and malware without "
            "installing any software on the host — using cloud-provider snapshot APIs instead.\n\n"
            "What is this scanning mode called? (one word, lowercase)"
        ),
        "flag": "agentless",
        "hint": "No software installed on the VM. The scan happens externally via cloud APIs.",
    },
]


# ── Reset helper (server-side — token never leaves this container) ─────────────

def _delete_all_challenges() -> dict:
    """Delete all CTFd challenges using the server-side admin token."""
    import requests as req_lib

    if not ADMIN_TOKEN:
        return {'deleted': 0, 'failed': 0, 'error': 'CTFD_ADMIN_TOKEN not set in trigger container'}

    headers = {
        'Authorization': f'Token {ADMIN_TOKEN}',
        'Content-Type':  'application/json',
    }
    try:
        r = req_lib.get(f'{CTFD_URL}/api/v1/challenges',
                        params={'view': 'admin'}, headers=headers, timeout=15)
        r.raise_for_status()
        chals = r.json().get('data', [])
    except Exception as e:
        return {'deleted': 0, 'failed': 0, 'error': f'Could not list challenges: {e}'}

    deleted, failed = 0, 0
    for ch in chals:
        try:
            d = req_lib.delete(f'{CTFD_URL}/api/v1/challenges/{ch["id"]}',
                               headers=headers, timeout=10)
            if d.ok:
                deleted += 1
            else:
                failed += 1
                logger.warning('Delete challenge %d failed: %s', ch['id'], d.text[:80])
        except Exception as e:
            failed += 1
            logger.warning('Delete challenge %d error: %s', ch['id'], e)

    logger.info('Cleared challenges: deleted=%d failed=%d', deleted, failed)
    return {'deleted': deleted, 'failed': failed}


def _push_default_challenges(n: int = 5) -> dict:
    """Pick n random questions from _DEFAULT_POOL and push them to CTFd.

    Returns {'created': int, 'error': str|None}.
    """
    import random, requests as req_lib

    if not ADMIN_TOKEN:
        return {'created': 0, 'error': 'CTFD_ADMIN_TOKEN not set'}

    headers = {
        'Authorization': f'Token {ADMIN_TOKEN}',
        'Content-Type':  'application/json',
    }

    picks = random.sample(_DEFAULT_POOL, min(n, len(_DEFAULT_POOL)))
    created = 0

    for q in picks:
        try:
            # Create the challenge
            ch_payload = {
                'name':        q['name'],
                'category':    'Default',
                'description': q['desc'],
                'value':       50,
                'type':        'standard',
                'state':       'visible',
            }
            r = req_lib.post(f'{CTFD_URL}/api/v1/challenges',
                             json=ch_payload, headers=headers, timeout=10)
            if not r.ok:
                logger.warning('Create challenge failed [%d]: %s', r.status_code, r.text[:80])
                continue
            cid = r.json()['data']['id']

            # Add flag (case-insensitive)
            req_lib.post(f'{CTFD_URL}/api/v1/flags',
                         json={'challenge': cid, 'content': q['flag'],
                               'type': 'static', 'data': 'case_insensitive'},
                         headers=headers, timeout=10)

            # Add free hint
            req_lib.post(f'{CTFD_URL}/api/v1/hints',
                         json={'challenge': cid, 'content': q['hint'], 'cost': 0},
                         headers=headers, timeout=10)

            # Add tags
            for tag in ('default', 'cnapp', 'basics'):
                req_lib.post(f'{CTFD_URL}/api/v1/tags',
                             json={'challenge': cid, 'value': tag},
                             headers=headers, timeout=5)

            created += 1
            logger.info('Default challenge created: %s [id=%d]', q['name'], cid)

        except Exception as exc:
            logger.warning('Error creating default challenge %r: %s', q['name'], exc)

    return {'created': created, 'error': None}


def _run_reset():
    """Delete all challenges, pick 5 random CNAPP default questions, push them."""
    global _last_activity
    _last_activity = time.time()

    s = STATUS['reset']
    s['status']  = 'running'
    s['log']     = ''
    s['started'] = time.time()
    s['finished'] = None

    lines = ['=== Clearing all challenges ===']
    result = _delete_all_challenges()
    lines.append(f"Deleted {result['deleted']} challenge(s).")

    if result.get('error'):
        lines.append(f"ERROR: {result['error']}")
        s['status']   = 'error'
        s['log']      = '\n'.join(lines)
        s['finished'] = time.time()
        return

    lines.append('\n=== Picking 5 random default CNAPP questions ===')
    push = _push_default_challenges(5)
    if push.get('error'):
        lines.append(f"ERROR: {push['error']}")
        s['status'] = 'error'
    elif push['created'] == 0:
        lines.append('WARNING: No challenges created.')
        s['status'] = 'error'
    else:
        lines.append(f"Created {push['created']} default challenge(s).")
        s['status'] = 'success'

    # Also reapply the Fortinet theme (fast)
    lines.append('\n=== Re-applying Fortinet theme ===')
    try:
        import importlib.util, io, unittest.mock as mock
        buf = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = buf
        try:
            spec = importlib.util.spec_from_file_location('build', '/app/build.py')
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            with mock.patch('sys.argv', ['build.py', '--theme-only']):
                mod.main()
        except SystemExit:
            pass
        finally:
            sys.stdout = old_out
            sys.stderr = old_err
        lines.append(buf.getvalue().strip() or 'Theme applied.')
    except Exception as exc:
        lines.append(f'Theme apply warning: {exc}')

    s['log']      = '\n'.join(lines)[-4000:]
    s['finished'] = time.time()
    logger.info('Reset complete: status=%s created=%d', s['status'], push.get('created', 0))


# ── Inactivity watchdog ───────────────────────────────────────────────────────

def _inactivity_watchdog():
    """
    Background thread: if no build/reset/submission has happened for
    INACTIVITY_RESET_HOURS, automatically reset to 5 random default questions.
    Set INACTIVITY_RESET_HOURS=0 to disable.
    """
    if INACTIVITY_RESET_HOURS <= 0:
        logger.info('Inactivity auto-reset disabled (INACTIVITY_RESET_HOURS=0).')
        return

    CHECK_INTERVAL = 1800   # check every 30 minutes
    threshold_s    = INACTIVITY_RESET_HOURS * 3600
    logger.info('Inactivity watchdog: auto-reset after %dh of no activity.', INACTIVITY_RESET_HOURS)

    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            global _last_activity

            # ── Pull latest challenge-submission timestamp from CTFd ──────────
            import json as _json
            import urllib.request as _ureq
            try:
                req = _ureq.Request(
                    f'{CTFD_URL}/api/v1/submissions?limit=1',
                    headers={'Authorization': f'Token {ADMIN_TOKEN}'},
                )
                data = _json.loads(_ureq.urlopen(req, timeout=10).read()).get('data', [])
                if data:
                    date_str = data[0].get('date', '')
                    if date_str:
                        from datetime import datetime as _dt
                        ts = _dt.fromisoformat(date_str.replace('Z', '+00:00')).timestamp()
                        if ts > _last_activity:
                            logger.debug('Inactivity watchdog: new submission at %.0f — refreshing activity clock.', ts)
                            _last_activity = ts
            except Exception as e:
                logger.debug('Inactivity watchdog: submission check: %s', e)

            # ── Check elapsed time ────────────────────────────────────────────
            elapsed    = time.time() - _last_activity
            elapsed_h  = elapsed / 3600
            remaining_h = max(0.0, (threshold_s - elapsed) / 3600)

            if elapsed < threshold_s:
                logger.debug(
                    'Inactivity watchdog: %.1fh elapsed, %.1fh until auto-reset.',
                    elapsed_h, remaining_h,
                )
                continue

            # ── Threshold crossed — skip if a build/reset is already running ──
            busy = (
                STATUS['reset']['status']   == 'running' or
                STATUS['static']['status']  == 'running' or
                STATUS['dynamic']['status'] == 'running'
            )
            if busy:
                logger.info('Inactivity watchdog: threshold reached but a job is running — postponing.')
                _last_activity = time.time()   # give it another full window
                continue

            logger.info(
                'Inactivity watchdog: %.1fh since last activity (threshold %dh) — '
                'auto-resetting to 5 random default CNAPP questions.',
                elapsed_h, INACTIVITY_RESET_HOURS,
            )
            _last_activity = time.time()   # prevent double-fire
            threading.Thread(target=_run_reset, daemon=True).start()

        except Exception as exc:
            logger.warning('Inactivity watchdog error: %s', exc)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({'ok': True})


@app.route('/status/<mode>')
def status(mode):
    if mode == 'inactivity':
        elapsed = time.time() - _last_activity
        return jsonify({
            'enabled':              INACTIVITY_RESET_HOURS > 0,
            'threshold_hours':      INACTIVITY_RESET_HOURS,
            'elapsed_seconds':      round(elapsed),
            'remaining_seconds':    max(0, round(INACTIVITY_RESET_HOURS * 3600 - elapsed)),
            'last_activity_epoch':  round(_last_activity),
        })
    if mode not in STATUS:
        abort(400, description='Unknown mode. Use static, dynamic, reset, or inactivity.')
    return jsonify(STATUS[mode].copy())


def _run_theme():
    """Apply Fortinet theme CSS + home page to CTFd without touching challenges."""
    import importlib.util, io, unittest.mock as mock

    s = STATUS['static']   # reuse static slot for logging convenience
    old_out, old_err = sys.stdout, sys.stderr
    buf = io.StringIO()
    sys.stdout = sys.stderr = buf

    try:
        spec = importlib.util.spec_from_file_location('build', '/app/build.py')
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with mock.patch('sys.argv', ['build.py', '--theme-only']):
            mod.main()
        return True, buf.getvalue()
    except SystemExit as e:
        ok = str(e) == '0'
        return ok, buf.getvalue()
    except Exception as exc:
        logger.exception('Theme apply failed')
        return False, buf.getvalue() + str(exc)
    finally:
        sys.stdout = old_out
        sys.stderr = old_err


@app.route('/run/theme', methods=['POST'])
def run_theme():
    """Apply Fortinet theme CSS + home page to CTFd. Does not touch challenges."""
    ok, log = _run_theme()
    return jsonify({'ok': ok, 'log': log[-2000:]}), 200 if ok else 500


_GAME_AWARD_NAME = 'CNAPP Game'


@app.route('/game/award', methods=['POST'])
def game_award():
    """Create a CTFd award for a correct CNAPP Game answer."""
    import requests as req_lib

    body    = request.get_json(silent=True) or {}
    user_id = body.get('user_id')
    pts     = body.get('pts', 0)
    question = str(body.get('question', ''))[:200]

    if not user_id or not isinstance(pts, int) or pts <= 0:
        abort(400, description='user_id and positive pts are required')
    if not ADMIN_TOKEN:
        abort(503, description='CTFD_ADMIN_TOKEN not configured')

    headers = {'Authorization': f'Token {ADMIN_TOKEN}', 'Content-Type': 'application/json'}
    payload = {
        'user_id':     user_id,
        'name':        _GAME_AWARD_NAME,
        'value':       pts,
        'description': question,
        'icon':        '',
    }
    try:
        r = req_lib.post(f'{CTFD_URL}/api/v1/awards', json=payload,
                         headers=headers, timeout=10)
        if r.ok:
            award_id = r.json().get('data', {}).get('id')
            logger.info('Game award created: user=%s pts=%d id=%s', user_id, pts, award_id)
            return jsonify({'ok': True, 'award_id': award_id}), 200
        logger.warning('Award create failed [%d]: %s', r.status_code, r.text[:120])
        return jsonify({'ok': False, 'error': r.text[:120]}), r.status_code
    except Exception as exc:
        logger.warning('Award create error: %s', exc)
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/game/reset-awards', methods=['POST'])
def game_reset_awards():
    """Delete all CNAPP Game awards from CTFd (resets game scores on scoreboard)."""
    import requests as req_lib

    if not ADMIN_TOKEN:
        abort(503, description='CTFD_ADMIN_TOKEN not configured')

    headers = {'Authorization': f'Token {ADMIN_TOKEN}', 'Content-Type': 'application/json'}
    try:
        r = req_lib.get(f'{CTFD_URL}/api/v1/awards', headers=headers,
                        params={'limit': 500}, timeout=15)
        r.raise_for_status()
        awards = [a for a in r.json().get('data', []) if a.get('name') == _GAME_AWARD_NAME]
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Could not list awards: {exc}'}), 500

    deleted, failed = 0, 0
    for award in awards:
        try:
            d = req_lib.delete(f'{CTFD_URL}/api/v1/awards/{award["id"]}',
                               headers=headers, timeout=10)
            if d.ok:
                deleted += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    logger.info('Game awards reset: deleted=%d failed=%d', deleted, failed)
    return jsonify({'ok': failed == 0, 'deleted': deleted, 'failed': failed}), 200


@app.route('/run/static', methods=['POST'])
def run_static():
    with LOCK['static']:
        if STATUS['static']['status'] == 'running':
            return jsonify({'queued': False, 'reason': 'already_running',
                            'status': STATUS['static']}), 409
    threading.Thread(target=_run_static, daemon=True).start()
    return jsonify({'queued': True, 'mode': 'static',
                    'message': 'Static build started.'}), 202


@app.route('/run/dynamic', methods=['POST'])
def run_dynamic():
    with LOCK['dynamic']:
        if STATUS['dynamic']['status'] == 'running':
            return jsonify({'queued': False, 'reason': 'already_running',
                            'status': STATUS['dynamic']}), 409

    body       = request.get_json(force=False, silent=True) or {}
    account    = body.get('account', '')
    key_id     = body.get('key_id', '')
    secret     = body.get('secret', '')
    subaccount = body.get('subaccount', '')

    threading.Thread(
        target=_run_dynamic,
        kwargs=dict(account=account, key_id=key_id,
                    secret=secret, subaccount=subaccount),
        daemon=True,
    ).start()
    return jsonify({'queued': True, 'mode': 'dynamic',
                    'message': 'Dynamic build started.'}), 202


@app.route('/reset', methods=['POST'])
def reset():
    """Delete all challenges then load 5 default CNAPP intro questions (async)."""
    with LOCK['reset']:
        if STATUS['reset']['status'] == 'running':
            return jsonify({'queued': False, 'reason': 'already_running',
                            'status': STATUS['reset']}), 409
    threading.Thread(target=_run_reset, daemon=True).start()
    return jsonify({'queued': True, 'mode': 'reset',
                    'message': 'Reset started — clearing challenges and loading defaults.'}), 202


@app.route('/run/<mode>', methods=['POST'])
def run(mode):
    """Legacy catch-all."""
    if mode == 'static':  return run_static()
    if mode == 'dynamic': return run_dynamic()
    abort(400, description='Unknown mode. Use static or dynamic.')


# ── First-boot auto-configure (setup wizard + token) ─────────────────────────

def _auto_configure() -> str:
    """Complete CTFd setup wizard and return a fresh admin token, or '' on failure.

    Safe to call even if CTFd is already set up — the /setup endpoint redirects
    away and the login/token steps still succeed.
    """
    import http.cookiejar, urllib.parse, urllib.request as ureq

    if not ADMIN_PASS:
        logger.warning('Auto-configure: CTFD_ADMIN_PASSWORD not set — skipping.')
        return ''

    jar    = http.cookiejar.CookieJar()
    opener = ureq.build_opener(ureq.HTTPCookieProcessor(jar))

    def _get_nonce(url: str) -> str:
        try:
            body = opener.open(url, timeout=10).read().decode(errors='replace')
            import re
            m = re.search(r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)["\']', body)
            if not m:
                m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']nonce["\']', body)
            return m.group(1) if m else ''
        except Exception:
            return ''

    # 1. Complete setup wizard (no-op if already done)
    nonce = _get_nonce(f'{CTFD_URL}/setup')
    if nonce:
        logger.info('Auto-configure: completing CTFd setup wizard…')
        try:
            data = urllib.parse.urlencode({
                'nonce': nonce, 'ctf_name': CTF_NAME_ENV,
                'name': ADMIN_NAME, 'email': ADMIN_EMAIL,
                'password': ADMIN_PASS, 'user_mode': 'users',
            }).encode()
            opener.open(ureq.Request(
                f'{CTFD_URL}/setup', data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            ), timeout=15)
        except Exception:
            pass  # redirect after setup is expected

    # 2. Log in
    nonce = _get_nonce(f'{CTFD_URL}/login')
    if not nonce:
        logger.warning('Auto-configure: could not get login nonce.')
        return ''
    try:
        data = urllib.parse.urlencode({
            'nonce': nonce, 'name': ADMIN_NAME, 'password': ADMIN_PASS,
        }).encode()
        opener.open(ureq.Request(
            f'{CTFD_URL}/login', data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        ), timeout=10)
    except Exception:
        pass  # redirect after login is expected

    # 3. Get CSRF nonce
    csrf = ''
    for url in (f'{CTFD_URL}/api/v1/tokens', f'{CTFD_URL}/settings'):
        try:
            body = opener.open(url, timeout=10).read().decode(errors='replace')
            import re, json as _json
            try:
                csrf = _json.loads(body).get('data', {}).get('csrfNonce', '')
            except Exception:
                pass
            if not csrf:
                m = re.search(r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)["\']', body)
                if not m:
                    m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']nonce["\']', body)
                csrf = m.group(1) if m else ''
            if csrf:
                break
        except Exception:
            pass

    if not csrf:
        logger.warning('Auto-configure: could not get CSRF nonce.')
        return ''

    # 4. Create admin token
    try:
        import json as _json
        body = opener.open(ureq.Request(
            f'{CTFD_URL}/api/v1/tokens',
            data=_json.dumps({'expiration': None}).encode(),
            headers={'Content-Type': 'application/json', 'CSRF-Token': csrf},
        ), timeout=10).read()
        token = _json.loads(body).get('data', {}).get('value', '')
        if token:
            logger.info('Auto-configure: admin token generated.')
        return token
    except Exception as exc:
        logger.warning('Auto-configure: token generation failed: %s', exc)
        return ''


# ── Startup self-heal ────────────────────────────────────────────────────────
# Runs once in the background when the trigger container starts.
# 1. Waits for CTFd to be reachable.
# 2. Always re-applies the Fortinet theme + home page.
# 3. If CTFd has 0 challenges, loads 5 random default CNAPP questions.
# This guarantees a good-looking default state on every fresh deployment
# without needing ctl.py or any manual step.

def _startup_selfheal():
    import requests as req_lib

    logger.info('Startup self-heal: waiting for CTFd…')

    # Step 1 — wait for CTFd HTTP to be up (up to 3 min)
    for attempt in range(36):
        try:
            r = req_lib.get(f'{CTFD_URL}/', timeout=5)
            if r.status_code < 500:
                break
        except Exception as e:
            logger.debug('Startup self-heal attempt %d: %s', attempt + 1, e)
        time.sleep(5)
    else:
        logger.warning('Startup self-heal: CTFd not reachable after 3 min — skipping.')
        return

    # Step 2 — ensure we have a working admin token
    global ADMIN_TOKEN
    if not ADMIN_TOKEN:
        logger.info('Startup self-heal: no token — running auto-configure…')
        ADMIN_TOKEN = _auto_configure()
        if not ADMIN_TOKEN:
            logger.warning('Startup self-heal: auto-configure failed — cannot apply theme or load challenges.')
            return
        logger.info('Startup self-heal: token acquired.')

    # Step 3 — verify token works (and get challenge count)
    for attempt in range(12):
        try:
            r = req_lib.get(
                f'{CTFD_URL}/api/v1/challenges',
                headers={'Authorization': f'Token {ADMIN_TOKEN}'},
                timeout=5,
            )
            if r.ok:
                chals = r.json().get('data', [])
                logger.info('Startup self-heal: CTFd ready, %d challenge(s) found.', len(chals))
                break
            elif r.status_code in (401, 403):
                logger.warning('Startup self-heal: token rejected — trying auto-configure…')
                ADMIN_TOKEN = _auto_configure()
                if not ADMIN_TOKEN:
                    logger.warning('Startup self-heal: could not get valid token — aborting.')
                    return
        except Exception as e:
            logger.debug('Startup self-heal token check %d: %s', attempt + 1, e)
        time.sleep(5)
    else:
        logger.warning('Startup self-heal: CTFd API not responding — skipping.')
        return

    # Step 4 — always apply Fortinet theme + home page
    ok, log = _run_theme()
    if ok:
        logger.info('Startup self-heal: Fortinet theme applied.')
    else:
        logger.warning('Startup self-heal: theme apply warning: %s', log[-200:])

    # Step 5 — load 5 random defaults only if DB is empty
    if len(chals) == 0:
        logger.info('Startup self-heal: no challenges — loading 5 random defaults.')
        _run_reset()
        logger.info('Startup self-heal: default challenges loaded.')


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('TRIGGER_PORT', 5555))
    logger.info('FortiCNAPP CTF Trigger Service starting on :%d', port)
    threading.Thread(target=_startup_selfheal, daemon=True).start()
    threading.Thread(target=_inactivity_watchdog, daemon=True).start()
    app.run(host='0.0.0.0', port=port, threaded=True)
