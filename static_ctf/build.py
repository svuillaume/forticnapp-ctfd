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
        'ctf_name':      os.environ.get('CTF_NAME', 'FortiCNAPP Cloud Defender Challenge'),
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
        logger.info('Static CTF build complete.')
        sys.exit(0)


if __name__ == '__main__':
    main()
