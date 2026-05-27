"""
CTFBuilder — adapted from lacework-dev/ctfdtools for FortiCNAPP static CTF.

Reads YAML challenge schema, substitutes Jinja2 template variables from
config, and pushes challenges into CTFd (idempotently).
"""
import importlib
import json
import logging
import os
import re
import traceback
import yaml

from jinja2 import Template, DebugUndefined
from os import listdir
from os.path import isdir, isfile


# ── YAML helpers ────────────────────────────────────────────────────────────

def _str_presenter(dumper, data):
    if data.count('\n') > 0:
        data = "\n".join([l.rstrip() for l in data.splitlines()])
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class _YamlDumper(yaml.SafeDumper):
    def write_line_break(self, data=None):
        super().write_line_break(data)
        if len(self.indents) == 2:
            super().write_line_break()


yaml.add_representer(str, _str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, _str_presenter)


# ── Builder ──────────────────────────────────────────────────────────────────

class CTFBuilder:

    def __init__(self, ctfd=None, config=None):
        self._ctfd      = ctfd
        self._config    = config or {}
        self._logger    = logging.getLogger(__name__)
        self._schema    = None
        self._files     = []
        self._challenges = {}
        self._pages     = {}
        self._category  = None

    # ── public ───────────────────────────────────────────────────────────────

    def build_ctf(self, schema, category=None):
        self._schema   = schema
        self._category = ['All'] if category is None else category
        self._challenges = self._get_ctfd_challenges()
        self._pages      = self._get_ctfd_pages()
        if self._category != ['All']:
            try:
                self._category = self._category.split(',')
            except AttributeError:
                raise Exception(f'Invalid category list: {self._category}')
            bad = [c for c in self._category if not isdir(f"{schema}/{c}")]
            if bad:
                raise Exception(f'Unknown categories: {bad}')
        self._files = self._put_ctfd_files()
        self._put_ctfd_pages()
        self._put_ctfd_configuration()
        self._put_ctfd_challenges()

    def generate_config(self):
        config = {
            'ctfd_api_key': '',
            'ctfd_url': '',
            'schema': self._config.get('schema', ''),
        }
        init_path = f"{self._config['schema']}/__init__.py"
        if isfile(init_path):
            saved = os.getcwd()
            os.chdir(f"{saved}/{self._config['schema']}")
            mod = importlib.machinery.SourceFileLoader('schema', '__init__.py').load_module()
            if hasattr(mod, 'build_config'):
                config = mod.build_config(config)
            os.chdir(saved)
        return config

    def get_answers(self):
        banner = """
        .:. FortiCNAPP CTF — Static Challenge Answers .:.
        """
        challenges = self._ctfd.get_challenge_list()
        out = banner
        for ch in challenges.get('data', []):
            out += f"\n  [{ch['category']}] {ch['name']}"
            flags = self._ctfd.get_challenge_flags(ch['id']).get('data', [])
            for f in flags:
                out += f"\n      FLAG: {f['content']}"
            out += "\n"
        return out

    # ── internal: read ────────────────────────────────────────────────────────

    def _get_ctfd_challenges(self):
        result = {}
        for ch in self._ctfd.get_challenge_list().get('data', []):
            cid = ch['id']
            result[ch['name']] = {
                'id':    cid,
                'flags': [f['id'] for f in self._ctfd.get_challenge_flags(cid).get('data', [])],
                'hints': [h['id'] for h in self._ctfd.get_challenge_hints(cid).get('data', [])],
                'tags':  [t['id'] for t in self._ctfd.get_challenge_tags(cid).get('data', [])],
            }
        return result

    def _get_ctfd_pages(self):
        pages = {}
        for p in self._ctfd.get_page_list().get('data', []):
            pages[p['route']] = self._ctfd.get_page_details(p['id'])['data']['id']
        return pages

    def _get_yaml_challenges(self):
        if self._category != ['All']:
            dirs = self._category
        else:
            dirs = listdir(self._schema)
        categories = sorted([
            d for d in dirs
            if isdir(f'{self._schema}/{d}') and re.search(r'^\d{1,3}_', d)
        ])
        challenges = {}
        for cat in categories:
            path = f'{self._schema}/{cat}/challenges.yml'
            if not isfile(path):
                self._logger.warning('No challenges.yml in %s, skipping.', cat)
                continue
            with open(path) as f:
                challenges[cat] = yaml.safe_load(f).get('challenges', [])
        return challenges

    # ── internal: transform ───────────────────────────────────────────────────

    def _replace_vars(self, data):
        """Substitute {{ CONFIG_* }} and file references via Jinja2."""
        for file in self._files:
            loc = file.get('location', '')
            key = loc.split('/')[1] if '/' in loc else loc
            data = json.loads(json.dumps(data).replace('{{ ' + key + ' }}', f'/files/{loc}'))
        tpl = Template(json.dumps(data), undefined=DebugUndefined)
        replace_vars = {f'CONFIG_{k.upper()}': v for k, v in self._config.items()}
        return json.loads(tpl.render(replace_vars))

    def _parse_challenges(self, challenges):
        parsed = {}
        saved = os.getcwd()
        for cat, items in challenges.items():
            parsed[cat] = []
            for ch in items:
                try:
                    schema_abs = self._schema if os.path.isabs(self._schema) else os.path.join(saved, self._schema)
                    os.chdir(schema_abs)
                    schema_mod = importlib.machinery.SourceFileLoader(
                        'schema', '__init__.py').load_module()
                    if hasattr(schema_mod, 'init_schema'):
                        schema_mod.init_schema(self._config)
                    cat_mod = importlib.machinery.SourceFileLoader(
                        cat, f'{cat}/__init__.py').load_module()
                    if hasattr(cat_mod, 'parse_challenge'):
                        ch = cat_mod.parse_challenge(schema_mod, ch, self._config)
                except Exception as e:
                    traceback.print_exc()
                    self._logger.warning('parse_challenge failed for %s: %s', ch.get('name'), e)
                finally:
                    os.chdir(saved)
                if not ch.get('flags'):
                    self._logger.warning('%s has no flags — hiding.', ch.get('name'))
                    ch['state'] = 'hidden'
                parsed[cat].append(ch)
        return parsed

    # ── internal: write ───────────────────────────────────────────────────────

    def _put_ctfd_challenges(self):
        self._logger.info('Pushing challenges to CTFd.')
        challenges = self._parse_challenges(self._get_yaml_challenges())
        for cat, items in challenges.items():
            for ch in items:
                # strip leading "N_" from category directory name
                ch['category'] = re.sub(r'^\d+_', '', cat)
                flags  = ch.pop('flags', [])
                hints  = ch.pop('hints', [])
                tags   = ch.pop('tags', [])
                ch.pop('next_id', None)
                ch.pop('requirements', None)

                name = ch['name']
                if name in self._challenges:
                    self._logger.info('Updating: %s', name)
                    self._ctfd.patch_challenge(ch, self._challenges[name]['id'])
                    for fid in self._challenges[name]['flags']: self._ctfd.delete_flag(fid)
                    for hid in self._challenges[name]['hints']: self._ctfd.delete_hint(hid)
                    for tid in self._challenges[name]['tags']:  self._ctfd.delete_tag(tid)
                else:
                    self._logger.info('Creating: %s', name)
                    new_id = self._ctfd.post_challenge(ch)['data']['id']
                    self._challenges[name] = {'id': new_id, 'flags': [], 'hints': [], 'tags': []}

                cid = self._challenges[name]['id']
                for f in flags:
                    f['challenge_id'] = cid
                    self._ctfd.post_flag(f)
                for h in hints:
                    h['challenge_id'] = cid
                    self._ctfd.post_hint(h)
                for t in tags:
                    t['challenge_id'] = cid
                    self._ctfd.post_tag(t)

    def _put_ctfd_configuration(self):
        cfg_path = f'{self._schema}/config.yml'
        if not isfile(cfg_path):
            return
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f).get('config', {})
        cfg = self._replace_vars(cfg)
        self._ctfd.patch_config_list(cfg)

    def _put_ctfd_files(self):
        files_dir = f'{self._schema}/files'
        if not isdir(files_dir):
            return []
        uploaded = []
        for fname in sorted(listdir(files_dir)):
            fpath = f'{files_dir}/{fname}'
            if isfile(fpath):
                with open(fpath, 'rb') as fh:
                    result = self._ctfd.post_file({'file': fh})
                    uploaded.extend(result.get('data', []))
        return uploaded

    def _put_ctfd_pages(self):
        pages_path = f'{self._schema}/pages.yml'
        if not isfile(pages_path):
            return
        with open(pages_path) as f:
            pages = yaml.safe_load(f).get('pages', [])
        for page in pages:
            page = self._replace_vars(page)
            if page['route'] in self._pages:
                self._ctfd.patch_page(page, self._pages[page['route']])
            else:
                p = self._ctfd.post_page(page)['data']
                self._pages[p['route']] = p['id']
