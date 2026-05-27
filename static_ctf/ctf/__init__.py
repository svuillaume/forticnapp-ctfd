"""
FortiCNAPP Static CTF — top-level schema module.

build_config() is called by build.py -g to generate the config JSON.
In Docker mode, config is read from env vars — no interactive prompts needed.
"""
import os


def init_schema(config):
    """Called before each category's parse_challenge. No-op for now."""
    pass


def build_config(config):
    """
    Non-interactive config builder — reads from environment variables.
    Falls back to safe defaults so the build always works.
    """
    config['ctfd_url']     = os.environ.get('CTFD_API_URL', 'http://ctfd:8000')
    config['ctfd_api_key'] = os.environ.get('CTFD_ADMIN_TOKEN', '')
    config['account']      = os.environ.get('FORTICNAPP_ACCOUNT', 'forticnapp-demo')
    config['subaccount']   = os.environ.get('FORTICNAPP_SUBACCOUNT', '')
    config['ctf_name']     = os.environ.get('CTF_NAME', 'FortiCNAPP Cloud Defender Challenge')
    return config
