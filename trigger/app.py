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

ADMIN_TOKEN = os.environ.get('CTFD_ADMIN_TOKEN', '')
CTFD_URL    = os.environ.get('CTFD_API_URL', 'http://ctfd:8000')

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


# ── Build runners ─────────────────────────────────────────────────────────────

def _run_static():
    """Clear all challenges then run the full CTF Lab build (21 challenges)."""
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

    try:
        result = subprocess.run(
            ['python', '-m', 'dynamic'],
            capture_output=True, text=True, timeout=300,
            env=env, cwd='/app',
        )
        s['status'] = 'success' if result.returncode == 0 else 'error'
        s['log']    = prefix_log + (result.stdout + result.stderr)[-3800:]
    except FileNotFoundError:
        s['status'] = 'error'
        s['log']    = prefix_log + 'Dynamic bridge not found at /app/dynamic.'
    except subprocess.TimeoutExpired:
        s['status'] = 'error'
        s['log']    = prefix_log + 'Build timed out after 300 s.'
    except Exception as exc:
        s['status'] = 'error'
        s['log']    = prefix_log + str(exc)
    finally:
        s['finished'] = time.time()


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


def _run_reset():
    """Delete all challenges then load the 5 default CNAPP intro questions."""
    s = STATUS['reset']
    s['status']  = 'running'
    s['log']     = ''
    s['started'] = time.time()
    s['finished'] = None

    import io, importlib.util
    import unittest.mock as mock

    buf = io.StringIO()
    buf.write('=== Clearing all challenges ===\n')

    result = _delete_all_challenges()
    buf.write(f"Deleted {result['deleted']} challenge(s).\n")
    if result.get('error'):
        buf.write(f"ERROR: {result['error']}\n")
        s['status']   = 'error'
        s['log']      = buf.getvalue()
        s['finished'] = time.time()
        return

    buf.write('\n=== Loading default CNAPP challenges + applying theme ===\n')
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = buf

    try:
        spec = importlib.util.spec_from_file_location('build', '/app/build.py')
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Load only the 'default' category (5 intro CNAPP questions) + theme
        with mock.patch('sys.argv', ['build.py', '--build', '--category', 'default']):
            mod.main()
        s['status'] = 'success'
    except SystemExit as e:
        s['status'] = 'success' if str(e) == '0' else 'error'
    except Exception:
        logger.exception('Default challenge load failed')
        s['status'] = 'error'
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
        s['log']      = buf.getvalue()[-4000:]
        s['finished'] = time.time()

    logger.info('Reset complete: status=%s', s['status'])


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({'ok': True})


@app.route('/status/<mode>')
def status(mode):
    if mode not in STATUS:
        abort(400, description='Unknown mode. Use static, dynamic, or reset.')
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


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('TRIGGER_PORT', 5555))
    logger.info('FortiCNAPP CTF Trigger Service starting on :%d', port)
    app.run(host='0.0.0.0', port=port, threaded=True)
