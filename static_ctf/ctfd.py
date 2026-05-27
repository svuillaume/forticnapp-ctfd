"""
CTFd API wrapper — adapted from lacework-dev/ctfdtools for FortiCNAPP CTF.
"""
import requests
import logging


class CTFd:

    def __init__(self, api_key, url):
        self._api_key = api_key
        self._url = url.rstrip("/")
        self._session = requests.Session()
        self._logger = logging.getLogger(__name__)

    def delete_flag(self, id): return self._request(f'flags/{id}', 'DELETE')
    def delete_hint(self, id): return self._request(f'hints/{id}', 'DELETE')
    def delete_tag(self, id):  return self._request(f'tags/{id}', 'DELETE')

    def get_challenge(self, id):              return self._request(f'challenges/{id}')
    def get_challenge_flags(self, id):        return self._request(f'challenges/{id}/flags')
    def get_challenge_hints(self, id):        return self._request(f'challenges/{id}/hints')
    def get_challenge_list(self):             return self._request('challenges?view=admin')
    def get_challenge_requirements(self, id): return self._request(f'challenges/{id}/requirements')
    def get_challenge_tags(self, id):         return self._request(f'challenges/{id}/tags')
    def get_config_list(self):                return self._request('configs')
    def get_file_list(self):                  return self._request('files')
    def get_page_details(self, id):           return self._request(f'pages/{id}')
    def get_page_list(self):                  return self._request('pages')

    def patch_challenge(self, json, id):   return self._request(f'challenges/{id}', 'PATCH', json)
    def patch_config_list(self, json):     return self._request('configs', 'PATCH', json)
    def patch_page(self, json, id):        return self._request(f'pages/{id}', 'PATCH', json)

    def post_challenge(self, json):        return self._request('challenges', 'POST', json)
    def post_flag(self, json):             return self._request('flags', 'POST', json)
    def post_hint(self, json):             return self._request('hints', 'POST', json)
    def post_tag(self, json):              return self._request('tags', 'POST', json)
    def post_file(self, files):            return self._request('files', 'POST', files=files)
    def post_page(self, json):             return self._request('pages', 'POST', json)

    def _request(self, path, method='GET', json=None, files=None):
        self._logger.debug(f'CTFd API {method} {path}')
        headers = {
            "Authorization": f"Token {self._api_key}",
            "Content-Type": "application/json",
        }
        if files:
            del headers['Content-Type']
        if path.startswith("http"):
            return self._session.request(method, path, headers=headers, stream=True)
        url = f"{self._url}/api/v1/{path}"
        resp = self._session.request(method, url, headers=headers, json=json, files=files)
        try:
            return resp.json()
        except ValueError:
            raise Exception(f'CTFd API returned non-JSON: {resp.text[:300]}')
