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
  POST /reset               — delete all CTFd challenges (server-side, no token in browser)
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
}
LOCK: dict = {
    'static':  threading.Lock(),
    'dynamic': threading.Lock(),
    'reset':   threading.Lock(),
}


# ── Build runners ─────────────────────────────────────────────────────────────

def _run_static():
    """Run bridge-static build in-process (imports build.py)."""
    import importlib.util, io, unittest.mock as mock

    s = STATUS['static']
    s['status']  = 'running'
    s['log']     = ''
    s['started'] = time.time()
    s['finished'] = None

    old_out, old_err = sys.stdout, sys.stderr
    buf = io.StringIO()
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
    """Run bridge (dynamic FortiCNAPP API build) via subprocess."""
    s = STATUS['dynamic']
    s['status']  = 'running'
    s['log']     = ''
    s['started'] = time.time()
    s['finished'] = None

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
        s['log']    = (result.stdout + result.stderr)[-4000:]
    except FileNotFoundError:
        s['status'] = 'error'
        s['log']    = 'Dynamic bridge not found at /app/dynamic.'
    except subprocess.TimeoutExpired:
        s['status'] = 'error'
        s['log']    = 'Build timed out after 300 s.'
    except Exception as exc:
        s['status'] = 'error'
        s['log']    = str(exc)
    finally:
        s['finished'] = time.time()


# ── Reset helper (server-side — token never leaves this container) ─────────────

def _do_reset() -> dict:
    """Delete all CTFd challenges using the server-side admin token."""
    import requests as req_lib

    if not ADMIN_TOKEN:
        return {'deleted': 0, 'error': 'CTFD_ADMIN_TOKEN not set in trigger container'}

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
        return {'deleted': 0, 'error': f'Could not list challenges: {e}'}

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

    logger.info('Reset: deleted=%d failed=%d', deleted, failed)
    return {'deleted': deleted, 'failed': failed}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({'ok': True})


@app.route('/status/<mode>')
def status(mode):
    if mode not in STATUS:
        abort(400, description='Unknown mode. Use static or dynamic.')
    return jsonify(STATUS[mode].copy())


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
    """Delete all CTFd challenges server-side. No token needed from the browser."""
    with LOCK['reset']:
        result = _do_reset()
    if 'error' in result:
        return jsonify({'ok': False, **result}), 500
    return jsonify({'ok': True, **result}), 200


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
