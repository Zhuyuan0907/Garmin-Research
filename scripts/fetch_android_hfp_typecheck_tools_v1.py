#!/usr/bin/env python3
"""Fetch one Android API stub jar and ECJ, not a full SDK or device tools."""
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/android-hfp-typecheck-tools-v1'
PLATFORM = {
    'url': 'https://dl.google.com/android/repository/platform-35_r02.zip',
    'size': 64273788, 'sha1': '0bb560a90a7a2cbd0dd8348224d518b638fe7949',
}
ECJ = 'https://repo.maven.apache.org/maven2/org/eclipse/jdt/ecj/3.41.0/ecj-3.41.0.jar'


def download(url, path, cap):
    h = hashlib.sha1()
    size = 0
    with urllib.request.urlopen(url, timeout=30) as response, path.open('xb') as stream:
        assert response.status == 200
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            assert size <= cap
            h.update(block)
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    return size, h.hexdigest()


def main():
    OUT.mkdir(mode=0o700)
    archive = OUT / 'platform.zip'
    size, digest = download(PLATFORM['url'], archive, PLATFORM['size'])
    assert size == PLATFORM['size'] and digest == PLATFORM['sha1']
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if n.endswith('/android.jar')]
        assert len(names) == 1 and z.getinfo(names[0]).file_size <= 40000000
        raw = z.read(names[0])
    target = OUT / 'android-35.jar'
    target.write_bytes(raw)
    target.chmod(0o444)
    archive.unlink()
    ecj_path = OUT / 'ecj-3.41.0.jar'
    n, ecj_sha1 = download(ECJ, ecj_path, 6000000)
    with urllib.request.urlopen(ECJ + '.sha1', timeout=30) as response:
        expected = response.read(256).decode().strip().split()[0]
    assert len(expected) == 40 and expected == ecj_sha1
    ecj_path.chmod(0o444)
    manifest = {'platform_archive_verified_then_deleted': PLATFORM, 'platform_archive_bytes': size,
                'installed_full_SDK': False, 'device_tools_installed': False,
                'files': [{'path': str(target.relative_to(ROOT)), 'bytes': len(raw),
                           'sha256': hashlib.sha256(raw).hexdigest()},
                          {'path': str(ecj_path.relative_to(ROOT)), 'bytes': n, 'url': ECJ,
                           'sha1': ecj_sha1, 'sha256': hashlib.sha256(ecj_path.read_bytes()).hexdigest()}]}
    p = OUT / 'manifest.json'
    p.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    p.chmod(0o444)
    print(json.dumps({'all_download_checks_passed': True, 'kept_tool_bytes': len(raw) + n,
                      'archive_deleted': True, 'full_SDK_installed': False, 'device_IO': False}))


if __name__ == '__main__':
    main()
