"""Mirror signed native release assets to the public Gitee binary repository."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request


REPO = 'IceWorm/r-0e984a1b0d614e6882be'
BASE = f'https://gitee.com/api/v5/repos/{REPO}'
MAX_ASSET = 128 * 1024 * 1024


def download_url(tag: str, name: str) -> str:
    return f'https://gitee.com/{REPO}/releases/download/{tag}/{name}'


class Gitee:
    def __init__(self, token: str):
        if not token:
            raise ValueError('Gitee token is required for publishing')
        self.headers = {'Authorization': 'Bearer ' + token, 'User-Agent': 'AutoTransNative-publisher'}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(self, endpoint: str, fields: dict | None = None, method: str | None = None):
        body = None if fields is None else urllib.parse.urlencode(fields).encode()
        headers = dict(self.headers)
        if body is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        request = urllib.request.Request(BASE + endpoint, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=45) as response:
                return json.load(response) if response.status != 204 else None
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise
            raise RuntimeError(f'Gitee API HTTP {error.code}: {endpoint}') from None

    def check_repository(self) -> str:
        repo = self.api('')
        if repo['private'] or not repo.get('default_branch'):
            raise ValueError('Gitee binary repository must be public and have a default branch')
        return repo['default_branch']

    def release(self, tag: str, name: str, body: str, branch: str):
        try:
            release = self.api('/releases/tags/' + urllib.parse.quote(tag, safe=''))
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            release = None
        if release is None:  # Gitee returns HTTP 200 with JSON null for a missing tag.
            release = self.api('/releases', {'tag_name': tag, 'name': name, 'body': body,
                                            'target_commitish': branch, 'prerelease': 'true'})
        if not isinstance(release, dict) or release.get('tag_name') != tag or not release.get('prerelease'):
            raise ValueError(f'Gitee release {tag} is not the expected native prerelease')
        return release

    def assets(self, release):
        result = self.api(f"/releases/{release['id']}/attach_files")
        if not isinstance(result, list):
            raise ValueError('Gitee returned an invalid attachment list')
        return result

    def upload(self, release, path: Path):
        data = path.read_bytes()
        if not data or len(data) > MAX_ASSET:
            raise ValueError('Gitee asset is empty or too large')
        boundary = 'autotrans-' + secrets.token_hex(16)
        head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="{path.name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
        body = head + data + f'\r\n--{boundary}--\r\n'.encode()
        headers = dict(self.headers, **{'Content-Type': f'multipart/form-data; boundary={boundary}'})
        endpoint = f"/releases/{release['id']}/attach_files"
        request = urllib.request.Request(BASE + endpoint, data=body, headers=headers, method='POST')
        try:
            with self.opener.open(request, timeout=180) as response:
                asset = json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'Gitee upload HTTP {error.code}: {path.name}') from None
        if asset.get('name') != path.name or asset.get('size') != len(data):
            raise ValueError('Gitee reported a different uploaded asset')
        return asset

    def verify_public(self, tag: str, path: Path):
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        for attempt in range(5):
            try:
                if hashlib.sha256(self.read_public(tag, path.name, MAX_ASSET)).hexdigest() == expected:
                    return
            except (OSError, urllib.error.HTTPError):
                pass
            if attempt < 4:
                time.sleep(attempt + 1)
        raise ValueError(f'Gitee public asset is unavailable or differs: {path.name}')

    def read_public(self, tag: str, name: str, limit: int) -> bytes:
        request = urllib.request.Request(download_url(tag, name),
                                         headers={'User-Agent': 'AutoTransNative-publisher',
                                                  'Cache-Control': 'no-cache'})
        with self.opener.open(request, timeout=120) as response:
            if not response.geturl().startswith('https://'):
                raise ValueError('Gitee download redirected outside HTTPS')
            data = response.read(limit + 1)
        if not data or len(data) > limit:
            raise ValueError('Invalid Gitee download size')
        return data

    def ensure_asset(self, release, path: Path):
        matches = [asset for asset in self.assets(release) if asset.get('name') == path.name]
        if len(matches) > 1:
            raise ValueError(f'Duplicate Gitee asset: {path.name}')
        if matches:
            if matches[0].get('size') != path.stat().st_size:
                raise ValueError(f'Existing Gitee asset differs: {path.name}')
        else:
            self.upload(release, path)
        self.verify_public(release['tag_name'], path)

    def replace_channel(self, release, path: Path):
        for asset in self.assets(release):
            if asset.get('name') == path.name:
                self.api(f"/releases/{release['id']}/attach_files/{asset['id']}", method='DELETE')
        self.upload(release, path)
        self.verify_public(release['tag_name'], path)
