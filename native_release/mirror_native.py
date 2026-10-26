"""Public, generic release-mirror worker. No translator source or private keys."""
from __future__ import annotations
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import time
import urllib.request
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
if __package__:
    from .gitee_release import Gitee, REPO
else:
    from gitee_release import Gitee, REPO

MAX = 128 * 1024 * 1024
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def signed(envelope, key):
    key.verify(base64.urlsafe_b64decode(envelope['signature'] + '=='), canonical(envelope['payload']))
    return envelope['payload']


def verify_assets(raw, config, tag):
    key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(config['public_key'] + '=='))
    channel = signed(json.loads(raw['native-update.json']), key)
    if channel['product'] != 'autotrans-native' or tag != 'native-v' + channel['version']:
        raise ValueError('Release/channel identity differs')
    now = int(time.time())
    if (channel['schema'] != 1 or channel['sequence'] <= 0 or channel['published_at'] > now + 300 or
            channel['expires_at'] <= now or channel['expires_at'] <= channel['published_at'] or
            channel['expires_at'] - channel['published_at'] > 366 * 86400 or
            set(channel['packages']) != {'windows-x64'}):
        raise ValueError('Expired/invalid channel or unsupported platforms')
    spec = channel['packages']['windows-x64']
    package = raw['AutoTransNative-windows-x64.atup']
    if len(package) != spec['size'] or hashlib.sha256(package).hexdigest() != spec['sha256']:
        raise ValueError('Signed update hash differs')
    if package[:7] != b'ATUP1\r\n':
        raise ValueError('Invalid package')
    size = struct.unpack('>I', package[7:11])[0]
    if not 0 < size <= 1024 * 1024 or 11 + size > len(package):
        raise ValueError('Invalid manifest length')
    manifest = signed(json.loads(package[11:11+size]), key)
    for field in ('product', 'version', 'sequence', 'channel'):
        if manifest[field] != channel[field]:
            raise ValueError('Manifest/channel differs')
    if manifest['platform'] != 'windows-x64':
        raise ValueError('Unexpected platform')
    expected = {entry['path']: entry for entry in manifest['files']}
    if len(expected) != len(manifest['files']) or sum(e['size'] for e in expected.values()) > MAX:
        raise ValueError('Invalid file list')
    with zipfile.ZipFile(io.BytesIO(raw['AutoTransNative-windows-x64-preview.zip'])) as archive:
        if set(archive.namelist()) != set(expected) or len(archive.namelist()) != len(expected):
            raise ValueError('Bootstrap ZIP file list differs')
        for name, entry in expected.items():
            info = archive.getinfo(name)
            if info.file_size != entry['size']:
                raise ValueError('Bootstrap file size differs')
            if hashlib.sha256(archive.read(name)).hexdigest() != entry['sha256']:
                raise ValueError('Bootstrap file hash differs')
    return channel, key


def read(url, limit=MAX):
    with OPENER.open(urllib.request.Request(url, headers={'User-Agent': 'Native-release-mirror'}), timeout=120) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Oversized release asset')
    return raw


def main():
    tag = os.environ['RELEASE_TAG']
    if not re.fullmatch(r'native-v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('Only native version tags are accepted')
    repository = os.environ['GITHUB_REPOSITORY']
    mirror_repo = os.environ['GITEE_REPO'].strip().removeprefix('https://gitee.com/').removesuffix('.git').strip('/')
    if repository != 'k3l1/r-0e984a1b0d614e6882be' or mirror_repo.casefold() != REPO.casefold():
        raise ValueError('Unexpected binary repository')
    release = json.loads(read(f'https://api.github.com/repos/{repository}/releases/tags/{tag}', 1024*1024))
    if release['draft'] or not release['prerelease']:
        raise ValueError('Expected a published native prerelease')
    names = ('AutoTransNative-windows-x64.atup', 'AutoTransNative-windows-x64-preview.zip', 'native-update.json')
    assets = {a['name']: a for a in release['assets']}
    raw = {name: read(assets[name]['browser_download_url']) for name in names}
    config = json.loads(Path(__file__).with_name('native-update-public.json').read_text())
    channel, key = verify_assets(raw, config, tag)
    gitee = Gitee(os.environ['GITEE_TOKEN'])
    branch = gitee.check_repository()
    mirror = gitee.release(tag, 'Native ' + channel['version'], 'Signed Windows release. Game addon is a separate folder.', branch)
    folder = Path('native-mirror-assets'); folder.mkdir(exist_ok=True)
    for name in names[:2]:
        path = folder / name; path.write_bytes(raw[name])
        gitee.ensure_asset(mirror, path)
        print('Mirrored and verified:', name, flush=True)
    channel_release = gitee.release('native-channel-v3', 'Native update channel v3', 'Signed native-client update metadata.', branch)
    if any(a.get('name') == 'native-update.json' for a in gitee.assets(channel_release)):
        old = signed(json.loads(gitee.read_public('native-channel-v3', 'native-update.json', 1024*1024)), key)
        if old['sequence'] > channel['sequence'] or (old['sequence'] == channel['sequence'] and
                (old['version'] != channel['version'] or old['packages'] != channel['packages'])):
            raise ValueError('Refusing channel rollback or replacement')
    path = folder / 'native-update.json'; path.write_bytes(raw['native-update.json'])
    gitee.replace_channel(channel_release, path)
    print('Gitee channel verified:', channel['version'], channel['sequence'], flush=True)


if __name__ == '__main__':
    main()
