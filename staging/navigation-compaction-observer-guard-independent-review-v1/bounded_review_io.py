"""Read only small pinned ordinary DATA artifacts; never scanner inputs."""
from pathlib import Path
import hashlib
import os
import stat

ROOT = Path('/root/garmin')
LIMIT = 131072

def fingerprint(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]

class Reader:
    def __init__(self):
        self.total = 0
        self.cache = {}
        self.reads = []

    def read(self, relative, expected_sha256=None, expected_bytes=None,
             expected_stat=None, expected_mode=None):
        p = ROOT / relative
        rp = p.resolve(strict=True)
        if not rp.is_relative_to(ROOT / 'staging'):
            raise ValueError('review only permits explicitly selected staging artifacts')
        if rp.suffix.lower() in {'.img', '.disabled', '.pbf', '.gcd', '.vpm'}:
            raise ValueError('map/source/firmware inputs forbidden')
        if 'MAIN' in rp.name.upper() or 'BOOT' in rp.name.upper():
            raise ValueError('firmware content forbidden')
        key = str(rp)
        if key in self.cache:
            data, row = self.cache[key]
            if expected_sha256 and row['sha256'] != expected_sha256:
                raise ValueError('cached content disagrees with new SHA pin')
            return data
        before = rp.stat()
        if not stat.S_ISREG(before.st_mode) or self.total + before.st_size > LIMIT:
            raise ValueError('ordinary artifact read limit/type rejected')
        actual_mode = oct(stat.S_IMODE(before.st_mode))
        if expected_bytes is not None and before.st_size != expected_bytes:
            raise ValueError('size pin failed')
        if expected_stat is not None and fingerprint(before) != expected_stat:
            raise ValueError('stat pin failed')
        if expected_mode is not None and stat.S_IMODE(before.st_mode) != int(expected_mode, 8):
            raise ValueError('declared actual mode pin failed')
        with rp.open('rb') as handle:
            data = handle.read(before.st_size + 1)
        after = rp.stat()
        self.total += len(data)
        digest = hashlib.sha256(data).hexdigest()
        row = dict(path=str(rp.relative_to(ROOT)), bytes=len(data), sha256=digest,
                   stat_before=fingerprint(before), stat_after=fingerprint(after),
                   actual_mode=actual_mode, expected_sha256=expected_sha256,
                   expected_bytes=expected_bytes, expected_stat=expected_stat,
                   expected_mode=expected_mode)
        self.reads.append(row)
        if len(data) != before.st_size or fingerprint(before) != fingerprint(after):
            raise ValueError('content/stat changed during read')
        if expected_sha256 and digest != expected_sha256:
            raise ValueError('SHA pin failed')
        self.cache[key] = (data, row)
        return data

    def assert_unchanged(self):
        for key, (_, row) in self.cache.items():
            s = Path(key).stat()
            if fingerprint(s) != row['stat_after']:
                raise ValueError('review input changed after read')
            if oct(stat.S_IMODE(s.st_mode)) != row['actual_mode']:
                raise ValueError('review input mode changed')
