"""Mirror one published, encrypted GitHub release asset to Gitee.

Only the opaque payload.7z asset is transferred. This repository contains no
application source or archive password.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


ASSET = "payload.7z"
API = "https://gitee.com/api/v5"
HEADERS = {"Accept": "application/json", "User-Agent": "EncryptedReleaseMirror/1.0"}
MAX_SIZE = 250 * 1024 * 1024


def json_request(url, token=None, payload=None):
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def optional_json(url, token=None):
    try:
        return json_request(url, token)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def download(url, destination=None):
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(url, headers={"User-Agent": HEADERS["User-Agent"]})
    with urllib.request.urlopen(request, timeout=180) as response:
        if response.geturl().split("?", 1)[0].startswith("http://"):
            raise ValueError("Asset download redirected to insecure HTTP")
        with open(destination, "wb") if destination else open(os.devnull, "wb") as output:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_SIZE:
                    raise ValueError("Asset exceeds size limit")
                digest.update(chunk)
                if destination:
                    output.write(chunk)
    return size, digest.hexdigest()


def upload(repo_path, release_id, token, package):
    boundary = "----ReleaseMirror" + uuid.uuid4().hex
    prefix = (f"--{boundary}\r\n"
              f'Content-Disposition: form-data; name="file"; filename="{ASSET}"\r\n'
              "Content-Type: application/octet-stream\r\n\r\n").encode()
    suffix = f"\r\n--{boundary}--\r\n".encode()
    # Stream small writes: a single 30 MB socket send can time out on the
    # GitHub runner's slower connection to Gitee despite steady progress.
    def chunks():
        yield prefix
        with package.open("rb") as source:
            while chunk := source.read(128 * 1024):
                yield chunk
        yield suffix
    request = urllib.request.Request(
        f"{API}{repo_path}/releases/{release_id}/attach_files", data=chunks(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": f"multipart/form-data; boundary={boundary}",
                 "Content-Length": str(len(prefix) + package.stat().st_size + len(suffix)),
                 "User-Agent": HEADERS["User-Agent"]})
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.load(response)


def verify_gitee(repo_path, tag, repo, expected_size, expected_hash):
    release = json_request(f"{API}{repo_path}/releases/tags/{tag}")
    expected_url = f"https://gitee.com/{repo}/releases/download/{tag}/{ASSET}"
    assets = [asset for asset in release.get("assets", [])
              if asset.get("name") == ASSET and
              asset.get("browser_download_url") == expected_url]
    if len(assets) != 1:
        raise ValueError("Gitee does not expose exactly one encrypted asset")
    # Gitee's CDN may take a moment to expose a new upload.
    for attempt in range(4):
        try:
            actual_size, actual_hash = download(expected_url)
            break
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise
            time.sleep(5 * (attempt + 1))
    if (actual_size, actual_hash) != (expected_size, expected_hash):
        raise ValueError("Gitee asset differs from the GitHub release asset")
    print(f"Gitee mirror verified: {tag}, {actual_size} bytes, SHA-256 {actual_hash}")


def main():
    github_repo = os.environ["GITHUB_REPOSITORY"]
    gitee_repo = os.environ["GITEE_REPO"]
    tag = os.environ["RELEASE_TAG"]
    token = os.environ["GITEE_TOKEN"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", github_repo):
        raise ValueError("Invalid GitHub repository")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", gitee_repo):
        raise ValueError("Invalid Gitee repository")
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("Invalid release tag")
    if not token:
        raise ValueError("GITEE_TOKEN secret is missing")

    github_release = json_request(
        f"https://api.github.com/repos/{github_repo}/releases/tags/{tag}")
    if github_release.get("draft") or github_release.get("prerelease"):
        raise ValueError("Only published stable releases can be mirrored")
    assets = [asset for asset in github_release.get("assets", [])
              if asset.get("name") == ASSET]
    if len(assets) != 1:
        raise ValueError("GitHub release must contain exactly one payload.7z")
    asset = assets[0]
    size = asset.get("size")
    if not isinstance(size, int) or not 0 < size <= MAX_SIZE:
        raise ValueError("Invalid GitHub asset size")
    expected_url = f"https://github.com/{github_repo}/releases/download/{tag}/{ASSET}"
    if asset.get("browser_download_url") != expected_url:
        raise ValueError("Unexpected GitHub asset URL")
    github_digest = asset.get("digest")
    if github_digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", github_digest):
        raise ValueError("Invalid GitHub asset digest")

    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / ASSET
        actual_size, actual_hash = download(expected_url, package)
        if actual_size != size or (github_digest and actual_hash != github_digest[7:]):
            raise ValueError("GitHub download differs from its release metadata")

        repo_path = f"/repos/{gitee_repo}"
        repo = json_request(f"{API}{repo_path}")
        if repo.get("private") or repo.get("full_name", "").lower() != gitee_repo.lower():
            raise ValueError("Gitee destination is not the expected public repository")
        release_path = f"{API}{repo_path}/releases/tags/{tag}"
        gitee_release = optional_json(release_path)
        if gitee_release is None:
            gitee_release = json_request(f"{API}{repo_path}/releases", token, {
                "tag_name": tag, "name": tag,
                "body": "Encrypted binary update.",
                "target_commitish": repo.get("default_branch") or "master"})
        existing = [item for item in gitee_release.get("assets", [])
                    if item.get("name") == ASSET]
        if len(existing) > 1:
            raise ValueError("Gitee release contains duplicate encrypted assets")
        if not existing:
            for attempt in range(3):
                try:
                    uploaded = upload(repo_path, gitee_release["id"], token, package)
                    break
                except (urllib.error.URLError, TimeoutError) as error:
                    if isinstance(error, urllib.error.HTTPError) and error.code < 500 and error.code != 429:
                        raise
                    refreshed = json_request(release_path)
                    recovered = [item for item in refreshed.get("assets", [])
                                 if item.get("name") == ASSET]
                    if len(recovered) == 1:
                        uploaded = recovered[0]
                        break
                    if attempt == 2:
                        raise
                    print(f"Gitee upload attempt {attempt + 1} failed; retrying", flush=True)
                    time.sleep(10 * (attempt + 1))
            if not uploaded.get("browser_download_url", "").startswith(
                    f"https://gitee.com/{gitee_repo}/"):
                raise ValueError("Gitee returned an unexpected upload URL")
            print(f"Uploaded encrypted asset to Gitee: {tag}")
        else:
            print(f"Gitee asset already exists; verifying: {tag}")
        verify_gitee(repo_path, tag, gitee_repo, actual_size, actual_hash)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Release mirror failed: {error}", file=sys.stderr)
        raise SystemExit(1)
