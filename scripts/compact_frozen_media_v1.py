#!/usr/bin/env python3
"""Keep frozen map/VPM revisions readable while sharing compressed storage.

This does not delete unique revisions, editable sources or the sole USB backup.
All original inodes remain in a hardlink seed until every compressed file and
every replacement path has been verified. Only the verified seed is then freed.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/garminos-media-compaction-v1'
SEED = BASE / 'hardlink-input'
ARCHIVE = ROOT / 'archives/frozen-media-v1.squashfs'
VIEW = ROOT / 'archives/frozen-media-v1'
AUDIT = ROOT / 'evidence/firmware-analysis/native-os20-resident-music-checkpoint-audit.json'

spec = importlib.util.spec_from_file_location(
    'frozen_trace_helpers', ROOT / 'scripts/compact_frozen_traces_v1.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
digest, reject_open_writers = helpers.digest, helpers.reject_open_writers


def save(name, value):
    with (BASE / name).open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def mounts():
    fs = json.loads(run('findmnt', '--json', '--mountpoint', str(VIEW),
                        '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS'))['filesystems'][0]
    assert VIEW.is_mount() and fs['fstype'] == 'squashfs'
    assert 'ro' in fs['options'].split(',')
    return fs


def metadata(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns]


def main():
    with open('/run/garmin-media-compaction-v1.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not BASE.exists() and not ARCHIVE.exists() and not VIEW.exists()
        before = shutil.disk_usage(ROOT).free
        audit = json.loads(AUDIT.read_text())
        assert audit['all_passed']
        canonical = audit['canonical_after_sha256']
        assert all(digest(ROOT / p) == h for p, h in canonical.items())
        backup = ROOT / 'backups/20261002T154458Z/sda-backup-v1.squashfs'
        backup_before = metadata(backup)
        rows, hashes, allocated, link_counts = [], {}, {}, Counter()
        for base, dirs, names in os.walk(ROOT / 'staging', followlinks=False):
            dirs[:] = [n for n in dirs if not (Path(base) / n).is_symlink()]
            for name in names:
                source = Path(base) / name
                if source.is_symlink() or not source.is_file():
                    continue
                s = source.stat()
                path = str(source.relative_to(ROOT))
                chosen = (source.suffix == '.img' and path.startswith('staging/maps/')
                          and s.st_size > 100_000_000)
                chosen |= (source.suffix == '.vpm' and s.st_size > 10_000_000
                           and '/candidate/' not in path and '/rollback/' not in path)
                if not chosen:
                    continue
                key = (s.st_dev, s.st_ino)
                if key not in hashes:
                    hashes[key] = digest(source)
                    allocated[key] = s.st_blocks * 512
                expected = audit['protected_sources'].get(path)
                assert expected is None or hashes[key] == expected, path
                rows.append(dict(path=path, size=s.st_size, sha256=hashes[key],
                                 metadata=metadata(source), nlink=s.st_nlink,
                                 mode=stat.S_IMODE(s.st_mode), previously_protected=expected is not None))
                link_counts[key] += 1
        assert len(rows) == 18 and len(hashes) == 16
        for row in rows:
            assert link_counts[tuple(row['metadata'][:2])] == row['nlink'], row['path']
        reject_open_writers(set(hashes))
        BASE.mkdir()
        plan = dict(all_passed=True, files=rows, selected_paths=len(rows),
                    distinct_original_inodes=len(hashes),
                    logical_bytes=sum(r['size'] for r in rows),
                    original_allocated_bytes=sum(allocated.values()),
                    before_free_bytes=before, prior_audit=str(AUDIT.relative_to(ROOT)),
                    prior_audit_sha256=digest(AUDIT),
                    newly_sealed_unprotected_paths=sum(not r['previously_protected'] for r in rows),
                    original_backup_excluded=True, editable_sources_excluded=True,
                    no_open_writers_observed=True, created_utc=datetime.now(timezone.utc).isoformat())
        save('verified-plan.json', plan)
        SEED.mkdir()
        for row in rows:
            target = SEED / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(ROOT / row['path'], target)
        with (SEED / 'frozen-manifest.json').open('x') as stream:
            json.dump(plan, stream, indent=2)
        print(json.dumps(dict(stage='all_original_media_hashed', paths=len(rows),
                              original_allocated_bytes=plan['original_allocated_bytes'])), flush=True)
        partial = ARCHIVE.with_suffix('.squashfs.partial')
        assert not partial.exists()
        subprocess.run(['mksquashfs', str(SEED), str(partial), '-noappend', '-comp', 'zstd',
                        '-Xcompression-level', '8', '-b', '1M', '-processors', '2',
                        '-mem', '128M', '-no-progress'], check=True)
        assert partial.stat().st_size < plan['original_allocated_bytes'] - 100_000_000
        os.chmod(partial, 0o444)
        partial.rename(ARCHIVE)
        archive_sha = digest(ARCHIVE)
        VIEW.mkdir()
        unit_name = run('systemd-escape', '--path', '--suffix=mount', str(VIEW))
        unit = Path('/etc/systemd/system') / unit_name
        unit_text = f'''[Unit]
Description=Garmin frozen map and VPM revisions, lossless compressed view
After=local-fs.target

[Mount]
What={ARCHIVE}
Where={VIEW}
Type=squashfs
Options=loop,ro,nodev,nosuid,noexec
TimeoutSec=30

[Install]
WantedBy=multi-user.target
'''
        with unit.open('x') as stream:
            stream.write(unit_text)
        subprocess.run(['systemd-analyze', 'verify', str(unit)], check=True)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', unit_name)
        mounts()
        # Exercise startup while all original paths still refer to raw files.
        run('systemctl', 'stop', unit_name)
        assert not VIEW.is_mount()
        run('systemctl', 'start', unit_name)
        fs = mounts()
        assert run('systemctl', 'is-enabled', unit_name) == 'enabled'
        for row in rows:
            compressed = VIEW / row['path']
            assert compressed.stat().st_size == row['size']
            assert digest(compressed) == row['sha256'], row['path']
            assert stat.S_IMODE(compressed.stat().st_mode) == row['mode']
            assert metadata(ROOT / row['path']) == row['metadata']
        assert json.loads((VIEW / 'frozen-manifest.json').read_text()) == plan
        save('archive-readback-before-removal.json', dict(
            all_passed=True, all_complete_file_hashes_match=True, original_inodes_retained=True,
            archive_sha256=archive_sha, archive_bytes=ARCHIVE.stat().st_size,
            cold_mount_start_passed=True, mount=fs, systemd_unit=unit_name, unit_text=unit_text))
        reject_open_writers(set(hashes))
        replaced = []
        try:
            with (BASE / 'replacement-operations.jsonl').open('x') as stream:
                for row in rows:
                    source = ROOT / row['path']
                    assert not source.is_symlink() and metadata(source) == row['metadata']
                    temporary = source.with_name('.frozen-media-v1-' + source.name)
                    assert not temporary.exists() and not temporary.is_symlink()
                    os.symlink(os.path.relpath(VIEW / row['path'], source.parent), temporary)
                    os.replace(temporary, source)
                    replaced.append(row)
                    stream.write(json.dumps(dict(path=row['path'], target=os.readlink(source),
                                                 sha256=row['sha256'])) + '\n')
                    stream.flush()
                    os.fsync(stream.fileno())
            for row in rows:
                path = ROOT / row['path']
                assert path.is_symlink() and digest(path) == row['sha256']
            assert all(digest(ROOT / p) == h for p, h in canonical.items())
            assert metadata(backup) == backup_before
            assert digest(ARCHIVE) == archive_sha
            mounts()
        except BaseException:
            for row in reversed(replaced):
                source = ROOT / row['path']
                temporary = source.with_name('.restore-media-v1-' + source.name)
                os.link(SEED / row['path'], temporary)
                os.replace(temporary, source)
            raise
        shutil.rmtree(SEED)
        os.sync()
        after = shutil.disk_usage(ROOT).free
        result = dict(all_passed=True, user_authorized_space_reduction=True,
                      created_utc=datetime.now(timezone.utc).isoformat(),
                      selected_paths=len(rows), original_allocated_bytes=plan['original_allocated_bytes'],
                      archive=str(ARCHIVE.relative_to(ROOT)), archive_sha256=archive_sha,
                      archive_bytes=ARCHIVE.stat().st_size, mountpoint=str(VIEW.relative_to(ROOT)),
                      systemd_unit=unit_name, cold_mount_start_passed=True,
                      enabled_for_reboot=True, all_original_paths_preserved=True,
                      all_selected_file_hashes_verified_before_and_after=True,
                      distinct_versions_discarded=False, editable_source_code_removed=False,
                      sole_full_backup_changed=False, backup_metadata_unchanged=True,
                      full_backup_hash_repeated=False, all_prior_protected_sources_rehashed=False,
                      canonical_files_unchanged=True, device_IO=False,
                      before_free_bytes=before, after_free_bytes=after, freed_bytes=after-before)
        assert result['freed_bytes'] > 100_000_000
        save('compaction-result.json', result)
        restore = ('Garmin frozen media: all revisions remain readable at their original paths.\n'
                   f'Archive: {ARCHIVE}\nSHA-256: {archive_sha}\n'
                   f'Mount: systemctl start {unit_name}\n'
                   'Extract one editable copy to a NEW destination, leaving these frozen paths intact:\n'
                   f'unsquashfs -d /path/to/external-destination {ARCHIVE}\n'
                   'Original file sizes and hashes are in verified-plan.json.\n')
        (BASE / 'RESTORE.txt').write_text(restore)
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
