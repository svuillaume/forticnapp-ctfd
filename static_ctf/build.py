#!/usr/bin/env python3
"""
FortiCNAPP Static CTF Builder.

Reads YAML challenge schema from ./ctf/, substitutes template variables,
and pushes challenges into a running CTFd instance.

Usage (Docker — recommended):
    docker compose run --rm bridge-static

Usage (direct):
    python build.py -g -s ctf                         # generate config JSON
    python build.py -c config.json -b                 # push challenges
    python build.py -c config.json -a                 # print all flags
"""

import argparse
import json
import logging
import os
import sys
import time

from ctfbuilder import CTFBuilder
from ctfd import CTFd
from os.path import isdir, isfile

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    level=os.environ.get('LOG_LEVEL', 'INFO').upper(),
    stream=sys.stdout,
)
logger = logging.getLogger('build')


# ── Config from environment (Docker-friendly, no interactive prompts) ────────

def config_from_env() -> dict:
    url   = os.environ.get('CTFD_API_URL', 'http://ctfd:8000')
    token = os.environ.get('CTFD_ADMIN_TOKEN', '')
    if not token:
        raise SystemExit(
            'CTFD_ADMIN_TOKEN is not set.\n'
            'Generate a token in CTFd: Admin Panel → Settings → Tokens\n'
            'Then add it to .env as CTFD_ADMIN_TOKEN=ctfd_...'
        )
    return {
        'ctfd_url':      url,
        'ctfd_api_key':  token,
        'schema':        os.environ.get('STATIC_SCHEMA_DIR', '/app/ctf'),
        # FortiCNAPP tenant vars — used in {{ CONFIG_ACCOUNT }} etc.
        'account':       os.environ.get('FORTICNAPP_ACCOUNT', 'forticnapp-demo'),
        'subaccount':    os.environ.get('FORTICNAPP_SUBACCOUNT', ''),
        'ctf_name':      os.environ.get('CTF_NAME', 'Capture the Flag powered by FortiCNAPP'),
    }


def wait_for_ctfd(url: str, token: str, max_wait: int = 120) -> None:
    import requests
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(
                f"{url}/api/v1/users/me",
                headers={"Authorization": f"Token {token}"},
                timeout=5,
            )
            if r.status_code in (200, 401, 403):
                if r.status_code in (401, 403):
                    raise SystemExit(
                        'CTFd is up but rejected the token. '
                        'Generate a fresh token in Admin Panel → Settings → Tokens.'
                    )
                logger.info('CTFd is ready at %s', url)
                return
        except requests.RequestException:
            pass
        logger.info('Waiting for CTFd at %s ...', url)
        time.sleep(5)
    raise SystemExit(f'CTFd not reachable at {url} after {max_wait}s')


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description='FortiCNAPP Static CTF Builder')
    g = p.add_mutually_exclusive_group()
    g.add_argument('-g', '--generate-config', action='store_true',
                   help='Generate config JSON from schema and env (print to stdout)')
    g.add_argument('-c', '--config', type=argparse.FileType('r'),
                   help='JSON config file (overrides env vars)')
    p.add_argument('-s', '--schema', default=None,
                   help='Path to CTF schema directory (default: ./ctf)')
    p.add_argument('-b', '--build',   action='store_true', help='Push challenges to CTFd')
    p.add_argument('-a', '--answers', action='store_true', help='Print all flags')
    p.add_argument('-C', '--category', default=None,
                   help='Comma-separated category directory names to limit build')
    p.add_argument('--theme-only', action='store_true',
                   help='Apply Fortinet theme CSS + home page only — skip all challenge loading')
    return p.parse_args()


def main():
    args = parse_args()

    if args.generate_config:
        schema = args.schema or os.environ.get('STATIC_SCHEMA_DIR', './ctf')
        config = config_from_env()
        config['schema'] = schema
        print(json.dumps(config, indent=2))
        sys.exit(0)

    # Load config — from file if supplied, else from env
    if args.config:
        config = json.loads(args.config.read())
    else:
        config = config_from_env()

    if args.schema:
        config['schema'] = args.schema

    # Fast path: --theme-only skips all schema/challenge work
    if args.theme_only:
        ctfd = CTFd(config['ctfd_api_key'], config['ctfd_url'])
        wait_for_ctfd(config['ctfd_url'], config['ctfd_api_key'])
        logger.info('Applying Fortinet theme + home page + game page (theme-only mode).')
        _apply_theme(ctfd, config)
        _apply_home_page(ctfd, config)
        _apply_game_page(ctfd, config)
        logger.info('Theme applied.')
        sys.exit(0)

    schema = config['schema']
    if not isdir(schema):
        raise SystemExit(f'Schema directory not found: {schema}')
    if not isfile(f'{schema}/config.yml'):
        raise SystemExit(f'No config.yml in schema directory: {schema}')

    ctfd = CTFd(config['ctfd_api_key'], config['ctfd_url'])
    wait_for_ctfd(config['ctfd_url'], config['ctfd_api_key'])

    cb = CTFBuilder(ctfd, config)

    if args.answers:
        print(cb.get_answers())
        sys.exit(0)

    if args.build or (not args.answers):
        logger.info('Building static CTF from schema: %s', schema)
        cb.build_ctf(schema, args.category)
        _apply_theme(ctfd, config)
        _apply_home_page(ctfd, config)
        _apply_game_page(ctfd, config)
        logger.info('Static CTF build complete.')
        sys.exit(0)


_MODE_BANNER_JS = """
<script>
(function(){try{
  var _trig=window.location.port==='8000'
    ?'http://'+window.location.hostname+':5556':'/trigger';
  function _mb(){
    if(document.getElementById('_fctf_mode_bar'))return;
    var p=location.pathname;if(p==='/'||p==='')return;
    var mode=localStorage.getItem('fctf_mode');
    if(!mode)return;
    var isLab=(mode==='ctf-lab'),col=isLab?'#DA291C':'#00b0cc';
    var b=document.createElement('div');b.id='_fctf_mode_bar';
    b.style.cssText='background:'+(isLab?'rgba(218,41,28,0.12)':'rgba(0,176,204,0.12)')+
      ';border-bottom:2px solid '+col+';padding:0.4rem 1rem;text-align:center;'+
      'font-family:Inter,system-ui,sans-serif;font-size:0.78rem;font-weight:700;'+
      'letter-spacing:0.07em;text-transform:uppercase;color:'+col+';';
    b.innerHTML=(isLab?'&#9724; CTF Lab':'&#128225; Live CTF')+
      '&nbsp;&mdash;&nbsp;<span style="font-weight:400;text-transform:none;letter-spacing:0;opacity:0.85">'+
      (isLab?'21 hand-crafted FortiCNAPP scenarios':'Challenges from your FortiCNAPP tenant')+
      '&nbsp;&bull;&nbsp;<a href="/" style="color:'+col+';opacity:0.7">&#8592; Back to mode selector</a></span>';
    var n=document.querySelector('nav.navbar')||document.querySelector('nav');
    if(n&&n.parentNode)n.parentNode.insertBefore(b,n.nextSibling);
    else document.body.insertBefore(b,document.body.firstChild);
  }
  function _sbReset(){
    if(location.pathname!=='/scoreboard')return;
    if(document.getElementById('_fctf_sb_reset'))return;
    var btn=document.createElement('button');
    btn.id='_fctf_sb_reset';
    btn.innerHTML='<i class="fas fa-trash-alt" style="margin-right:0.4em"></i>Reset Game Scores';
    btn.style.cssText='position:fixed;bottom:1.5rem;right:1.5rem;z-index:9000;'+
      'background:#b91c1c;color:#fff;border:none;border-radius:8px;'+
      'padding:0.65rem 1.25rem;font-size:0.82rem;font-weight:700;cursor:pointer;'+
      'box-shadow:0 4px 18px rgba(185,28,28,0.45);font-family:Inter,system-ui,sans-serif;'+
      'transition:opacity 0.15s;';
    btn.onmouseover=function(){btn.style.opacity='0.85';};
    btn.onmouseout=function(){btn.style.opacity='1';};
    btn.onclick=function(){
      if(!confirm('Remove ALL CNAPP Game points from the scoreboard for every player?\\n\\nThis cannot be undone.'))return;
      btn.disabled=true;btn.innerHTML='Resetting…';
      fetch(_trig+'/game/reset-awards',{method:'POST'})
        .then(function(r){return r.json();})
        .then(function(d){
          btn.disabled=false;
          btn.innerHTML='<i class="fas fa-trash-alt" style="margin-right:0.4em"></i>Reset Game Scores';
          alert('Done — '+(d.deleted||0)+' award(s) removed. Reload to see updated scores.');
          window.location.reload();
        })
        .catch(function(){
          btn.disabled=false;
          btn.innerHTML='<i class="fas fa-trash-alt" style="margin-right:0.4em"></i>Reset Game Scores';
          alert('Could not reach trigger service.');
        });
    };
    document.body.appendChild(btn);
  }
  function _init(){_mb();_sbReset();}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',_init);else _init();
}catch(e){}})();
</script>"""


def _apply_theme(ctfd, config: dict) -> None:
    """Push FortiGuard Labs dark theme CSS + mode banner JS to CTFd theme_header.

    CTFd's base.html renders {{ Configs.theme_header }} — the 'css' config
    key is stored but never output to the page. CSS must be wrapped in a
    <style> block and written to theme_header.
    """
    import requests

    # Look for the bundled CSS alongside this script
    css_candidates = [
        os.path.join(os.path.dirname(__file__), 'fortinet.css'),
        '/app/fortinet.css',
        '/app/theme/fortinet.css',
    ]
    css = ''
    for path in css_candidates:
        if isfile(path):
            with open(path) as fh:
                css = fh.read()
            logger.info('Applying Fortinet theme from %s (%d chars)', path, len(css))
            break

    if not css:
        logger.warning('fortinet.css not found — skipping theme injection')
        return

    payload = {
        'theme_header': f'<style>\n{css}\n</style>\n{_MODE_BANNER_JS}',
        'ctf_name':     'CTF Lab — FortiCNAPP CTF',
    }
    try:
        r = requests.patch(
            f"{config['ctfd_url']}/api/v1/configs",
            json=payload,
            headers={
                'Authorization': f"Token {config['ctfd_api_key']}",
                'Content-Type': 'application/json',
            },
            timeout=30,
        )
        if r.ok:
            logger.info('FortiGuard Labs dark theme + CTF Lab banner applied.')
        else:
            logger.warning('Theme apply failed [%d]: %s', r.status_code, r.text[:200])
    except Exception as exc:
        logger.warning('Could not apply theme: %s', exc)


def _apply_home_page(ctfd, config: dict) -> None:
    """Replace CTFd index page with FortiCNAPP landing page (two mode cards)."""
    import requests

    html_candidates = [
        os.path.join(os.path.dirname(__file__), 'home.html'),
        '/app/home.html',
    ]
    html = ''
    for path in html_candidates:
        if isfile(path):
            with open(path) as fh:
                html = fh.read()
            logger.info('Applying home page from %s', path)
            break

    if not html:
        logger.warning('home.html not found — skipping home page update')
        return

    headers = {
        'Authorization': f"Token {config['ctfd_api_key']}",
        'Content-Type': 'application/json',
    }
    base = config['ctfd_url']

    # Find the index page id
    try:
        r = requests.get(f'{base}/api/v1/pages', headers=headers, timeout=15)
        pages = r.json().get('data', [])
        page_id = next((p['id'] for p in pages if p.get('route') == 'index'), None)

        payload = {
            'title': config.get('ctf_name', 'Capture the Flag powered by FortiCNAPP'),
            'content': html,
            'route': 'index',
            'format': 'html',
            'draft': False,
            'auth_required': False,
        }

        if page_id:
            r2 = requests.patch(f'{base}/api/v1/pages/{page_id}',
                                json=payload, headers=headers, timeout=15)
        else:
            r2 = requests.post(f'{base}/api/v1/pages',
                               json=payload, headers=headers, timeout=15)

        if r2.ok and r2.json().get('success'):
            logger.info('Home page (mode selector) applied to CTFd.')
        else:
            logger.warning('Home page update failed [%d]: %s', r2.status_code, r2.text[:200])
    except Exception as exc:
        logger.warning('Could not apply home page: %s', exc)


def _apply_game_page(ctfd, config: dict) -> None:
    """Push the Knowledge CNAPP Game as a CTFd page at /game."""
    import requests

    html_candidates = [
        os.path.join(os.path.dirname(__file__), 'game.html'),
        '/app/game.html',
    ]
    html = ''
    for path in html_candidates:
        if isfile(path):
            with open(path) as fh:
                html = fh.read()
            logger.info('Applying game page from %s', path)
            break

    if not html:
        logger.warning('game.html not found — skipping game page update')
        return

    headers = {
        'Authorization': f"Token {config['ctfd_api_key']}",
        'Content-Type': 'application/json',
    }
    base = config['ctfd_url']

    try:
        r = requests.get(f'{base}/api/v1/pages', headers=headers, timeout=15)
        pages = r.json().get('data', [])
        page_id = next((p['id'] for p in pages if p.get('route') == 'game'), None)

        payload = {
            'title': 'CNAPP Game',
            'content': html,
            'route': 'game',
            'format': 'html',
            'draft': False,
            'auth_required': False,
        }

        if page_id:
            r2 = requests.patch(f'{base}/api/v1/pages/{page_id}',
                                json=payload, headers=headers, timeout=15)
        else:
            r2 = requests.post(f'{base}/api/v1/pages',
                               json=payload, headers=headers, timeout=15)

        if r2.ok and r2.json().get('success'):
            logger.info('Game page applied to CTFd at /game.')
        else:
            logger.warning('Game page update failed [%d]: %s', r2.status_code, r2.text[:200])
    except Exception as exc:
        logger.warning('Could not apply game page: %s', exc)


if __name__ == '__main__':
    main()
