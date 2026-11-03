#!/usr/bin/env python3
"""Consolidate two verified map duplicates and remove regenerable caches."""
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/garminos-storage-followup-v1'
PAIRS = [
    ('staging/maps/Taiwan_OSM_20261001_UTF8/Taiwan_OSM_20261001.img',
     'staging/maps/Taiwan_OSM_20261001_UTF8/compiled/gmapsupp.img',
     '0c97b5726318a96272d7662b66279c5ca08003cd13f13478be70abe67b4ab5b8'),
    ('staging/maps/Taiwan_OSM_20261001_ZhuYuan/Taiwan_OSM_20261001.img',
     'staging/maps/Taiwan_OSM_20261001_ZhuYuan/gmapsupp.img',
     '2801d07dfa4f3ae8d69fcdaea616e88499da6a6ed4a6d773b378253b9ebcb600'),
]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 << 20), b''):
            h.update(block)
    return h.hexdigest()


def save(name, data):
    with (BASE / name).open('x') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def file_state(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
            s.st_ctime_ns, stat.S_IMODE(s.st_mode), s.st_nlink]


def allocated(path):
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_blocks * 512
    return sum(p.stat().st_blocks * 512 for p in path.rglob('*')
               if p.is_file() and not p.is_symlink())


def main():
    with open('/run/garmin-storage-followup-v1.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not BASE.exists()
        audit = json.loads((ROOT / 'evidence/firmware-analysis/native-os20-allocator-checkpoint-audit.json').read_text())
        assert audit['all_passed']
        assert all(sha(ROOT / p) == h for p, h in audit['canonical_after_sha256'].items())
        backup = ROOT / 'backups/20261002T154458Z/sda.img'
        backup_before = file_state(backup)
        assert backup_before[2] == 3879731200
        readonly = ROOT / 'backups/20261002T154458Z/files'
        assert readonly.is_mount()
        fs = json.loads(subprocess.check_output(
            ['findmnt', '--json', '--mountpoint', str(readonly), '-o', 'FSTYPE,OPTIONS'], text=True))['filesystems'][0]
        assert fs['fstype'] == 'vfat' and 'ro' in fs['options'].split(',')
        processes = subprocess.check_output(['ps', '-eo', 'comm='], text=True).splitlines()
        assert not any(p.strip() in {'apt', 'apt-get', 'dpkg', 'pip', 'pip3', 'java'} for p in processes)
        rows = []
        for source, target, expected in PAIRS:
            a, b = ROOT / source, ROOT / target
            assert not a.is_symlink() and not b.is_symlink()
            sa, sb = a.stat(), b.stat()
            assert sa.st_nlink == sb.st_nlink == 1 and sa.st_dev == sb.st_dev
            assert sa.st_size == sb.st_size == 134852608
            assert stat.S_IMODE(sa.st_mode) == stat.S_IMODE(sb.st_mode) == 0o644
            assert sha(a) == sha(b) == expected
            rows.append(dict(source=source, duplicate=target, sha256=expected,
                             before_source=file_state(a), before_duplicate=file_state(b),
                             duplicate_allocated_bytes=sb.st_blocks * 512))
        map_inodes = {(r['before_source'][0], r['before_source'][1]) for r in rows}
        map_inodes |= {(r['before_duplicate'][0], r['before_duplicate'][1]) for r in rows}
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                for fd in (proc / 'fd').iterdir():
                    try:
                        s = fd.stat()
                        assert (s.st_dev, s.st_ino) not in map_inodes, (proc.name, str(fd))
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        pass
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
        caches = [Path('/var/cache/apt/archives'), Path('/var/cache/apt/pkgcache.bin'),
                  Path('/var/cache/apt/srcpkgcache.bin'), Path('/root/.cache/pip')]
        cache_before = {str(p): allocated(p) for p in caches}
        before = shutil.disk_usage(ROOT)
        BASE.mkdir()
        save('verified-plan.json', dict(created_utc=datetime.now(timezone.utc).isoformat(),
             user_authorized=True, maps=rows, regenerable_cache_allocated_bytes=cache_before,
             before_free_bytes=before.free, sole_backup_excluded=True,
             installed_packages_and_package_lists_excluded=True, VM_disks_excluded=True))
        operations = []
        for row in rows:
            a, b = ROOT / row['source'], ROOT / row['duplicate']
            assert file_state(a) == row['before_source'] and file_state(b) == row['before_duplicate']
            temporary = b.with_name('.storage-followup-v1-' + b.name)
            assert not temporary.exists()
            os.link(a, temporary)
            assert sha(temporary) == row['sha256']
            os.replace(temporary, b)
            os.chmod(a, 0o444)
            assert a.stat().st_ino == b.stat().st_ino
            assert sha(a) == sha(b) == row['sha256']
            operations.append(dict(source=row['source'], retained_path=row['duplicate'],
                sha256=row['sha256'], operation='shared_readonly_inode',
                duplicate_allocated_bytes_removed=row['duplicate_allocated_bytes']))
        save('duplicate-operations.json', operations)
        subprocess.run(['apt-get', 'clean'], check=True, capture_output=True, text=True)
        for p in caches[1:3]:
            assert not p.is_symlink()
            p.unlink(missing_ok=True)
        pip_cache = caches[3]
        assert not pip_cache.is_symlink()
        if pip_cache.exists():
            shutil.rmtree(pip_cache)
        os.sync()
        after = shutil.disk_usage(ROOT)
        assert file_state(backup) == backup_before
        assert all(sha(ROOT / p) == h for p, h in audit['canonical_after_sha256'].items())
        cache_after = {str(p): allocated(p) for p in caches}
        freed = after.free - before.free
        assert freed > 269_000_000
        result = dict(all_passed=True, created_utc=datetime.now(timezone.utc).isoformat(),
            duplicate_map_files_consolidated=2, all_four_map_paths_and_SHA256_preserved=True,
            maps=operations, cache_before_allocated_bytes=cache_before,
            cache_after_allocated_bytes=cache_after,
            cache_bytes_removed=sum(cache_before.values()) - sum(cache_after.values()),
            before_free_bytes=before.free, after_free_bytes=after.free, freed_bytes=freed,
            prior_cleanup_freed_bytes=6561820672,
            cumulative_cleanup_freed_bytes=6561820672 + freed,
            sole_complete_backup='backups/20261002T154458Z/sda.img',
            sole_backup_metadata_unchanged=True, backup_full_SHA256_repeated=False,
            backup_last_verified_sha256='df393136d4d14dd31906c1f161fc354cb097c56e3bf8c2278433d01ca2f1c6e2',
            canonical_research_files_unchanged=True, original_sources_and_distinct_results_preserved=True,
            installed_packages_and_package_lists_removed=False, VM_disks_touched=False,
            device_IO=False, goal_status='active')
        save('cleanup-result.json', result)
        print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
