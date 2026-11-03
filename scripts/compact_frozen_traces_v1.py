#!/usr/bin/env python3
"""Losslessly archive frozen, large JSON evidence while preserving read paths.

Only hashes listed in the previous checkpoint qualify. Build and verify a
read-only compressed filesystem before replacing any original with a link.
The sole original Garmin disk image and editable research sources are excluded.
"""
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
BASE = ROOT / 'staging/garminos-trace-compaction-v1'
AUDIT = ROOT / 'evidence/firmware-analysis/native-os20-task-index-checkpoint-audit.json'
SEED = BASE / 'hardlink-input'
ARCHIVE = ROOT / 'archives/research-traces-v1.squashfs'
VIEW = ROOT / 'archives/research-traces-v1'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def save(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def reject_open_writers(inodes):
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            descriptors = list((proc / 'fd').iterdir())
        except (PermissionError, FileNotFoundError):
            continue
        for descriptor in descriptors:
            try:
                st = descriptor.stat()
                if (st.st_dev, st.st_ino) not in inodes:
                    continue
                info = (proc / 'fdinfo' / descriptor.name).read_text()
                flags = int(next(x.split()[1] for x in info.splitlines()
                                 if x.startswith('flags:')), 8)
                assert flags & os.O_ACCMODE == os.O_RDONLY, (proc.name, str(descriptor))
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue


def readonly_view():
    assert VIEW.is_mount()
    fs = json.loads(subprocess.check_output(
        ['findmnt', '--json', '--mountpoint', str(VIEW), '-o',
         'TARGET,SOURCE,FSTYPE,OPTIONS'], text=True))['filesystems'][0]
    assert fs['fstype'] == 'squashfs' and 'ro' in fs['options'].split(',')
    return fs


def main():
    with open('/run/garmin-storage-compaction-v1.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not BASE.exists() and not ARCHIVE.exists() and not VIEW.exists()
        before = shutil.disk_usage(ROOT)
        old = json.loads(AUDIT.read_text())
        assert old['all_passed'] and len(old['protected_sources']) == 4654
        assert all(digest(ROOT / p) == h for p, h in old['canonical_after_sha256'].items())
        rows, hashes, allocated = [], {}, {}
        for path, expected in old['protected_sources'].items():
            source = ROOT / path
            if not (path.startswith('staging/') and source.suffix == '.json'
                    and not source.is_symlink() and source.is_file()
                    and source.stat().st_size >= 5_000_000):
                continue
            st = source.stat()
            key = (st.st_dev, st.st_ino)
            if key not in hashes:
                hashes[key] = digest(source)
                allocated[key] = st.st_blocks * 512
            assert hashes[key] == expected, path
            rows.append(dict(path=path, size=st.st_size, sha256=expected,
                             device=st.st_dev, inode=st.st_ino,
                             mode=stat.S_IMODE(st.st_mode), mtime_ns=st.st_mtime_ns))
        assert len(rows) == 88
        reject_open_writers(set(hashes))
        BASE.mkdir()
        plan = dict(all_passed=True, files=rows, previous_audit=str(AUDIT.relative_to(ROOT)),
                    previous_audit_sha256=digest(AUDIT), selected_paths=len(rows),
                    logical_bytes=sum(x['size'] for x in rows),
                    unique_allocated_bytes=sum(allocated.values()),
                    before_free_bytes=before.free, original_backup_excluded=True,
                    editable_sources_excluded=True, no_open_writers_observed=True,
                    created_utc=datetime.now(timezone.utc).isoformat())
        save(BASE / 'verified-plan.json', plan)
        SEED.mkdir()
        for row in rows:
            target = SEED / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(ROOT / row['path'], target)
        save(SEED / 'frozen-manifest.json', plan)
        ARCHIVE.parent.mkdir(exist_ok=True)
        partial = ARCHIVE.with_suffix('.squashfs.partial')
        assert not partial.exists()
        print(json.dumps(dict(stage='all_88_original_files_verified',
                              unique_allocated_bytes=plan['unique_allocated_bytes'],
                              originals_not_removed=True)), flush=True)
        subprocess.run(['mksquashfs', str(SEED), str(partial), '-noappend',
                        '-comp', 'zstd', '-Xcompression-level', '8', '-b', '1M',
                        '-processors', '2', '-mem', '128M', '-no-progress'], check=True)
        os.chmod(partial, 0o444)
        partial.rename(ARCHIVE)
        archive_sha = digest(ARCHIVE)
        VIEW.mkdir()
        unit_name = subprocess.check_output(
            ['systemd-escape', '--path', '--suffix=mount', str(VIEW)], text=True).strip()
        unit = Path('/etc/systemd/system') / unit_name
        assert not unit.exists()
        unit_text = f'''[Unit]
Description=Garmin frozen research traces, lossless read-only compressed view
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
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', '--now', unit_name], check=True)
        fs = readonly_view()
        for row in rows:
            compressed = VIEW / row['path']
            assert compressed.is_file() and compressed.stat().st_size == row['size']
            assert digest(compressed) == row['sha256'], row['path']
            assert stat.S_IMODE(compressed.stat().st_mode) == row['mode']
        assert json.loads((VIEW / 'frozen-manifest.json').read_text()) == plan
        save(BASE / 'archive-readback-before-removal.json',
             dict(all_passed=True, all_88_complete_file_hashes_match=True,
                  originals_still_retained=True, archive_sha256=archive_sha,
                  archive_bytes=ARCHIVE.stat().st_size, mount=fs,
                  systemd_unit=unit_name, unit_text=unit_text))
        print(json.dumps(dict(stage='compressed_archive_all_88_hashes_match',
                              archive_bytes=ARCHIVE.stat().st_size)), flush=True)
        reject_open_writers(set(hashes))
        with (BASE / 'replacement-operations.jsonl').open('x') as log:
            for row in rows:
                source = ROOT / row['path']
                st = source.stat()
                assert not source.is_symlink()
                assert (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == (
                    row['device'], row['inode'], row['size'], row['mtime_ns'])
                temporary = source.with_name('.compact-v1-' + source.name)
                assert not temporary.exists() and not temporary.is_symlink()
                os.symlink(os.path.relpath(VIEW / row['path'], source.parent), temporary)
                assert digest(temporary) == row['sha256']
                os.replace(temporary, source)
                log.write(json.dumps(dict(path=row['path'], sha256=row['sha256'],
                                          target=os.readlink(source))) + '\n')
                log.flush()
                os.fsync(log.fileno())
        # Original inodes are kept by the seed until every old path is checked.
        for row in rows:
            assert (ROOT / row['path']).is_symlink()
            assert digest(ROOT / row['path']) == row['sha256']
        shutil.rmtree(SEED)
        # Verify every prior protected byte at the same path, including firmware.
        for path, expected in old['protected_sources'].items():
            assert digest(ROOT / path) == expected, path
        assert all(digest(ROOT / p) == h for p, h in old['canonical_after_sha256'].items())
        backup = ROOT / 'backups/20261002T154458Z/sda.img'
        assert digest(backup) == 'df393136d4d14dd31906c1f161fc354cb097c56e3bf8c2278433d01ca2f1c6e2'
        assert digest(ARCHIVE) == archive_sha
        readonly_view()
        os.sync()
        after = shutil.disk_usage(ROOT)
        assert after.free > before.free + 4_000_000_000
        result = dict(all_passed=True, user_authorized_space_reduction=True,
                      selected_files=88, logical_bytes=plan['logical_bytes'],
                      original_unique_allocated_bytes=plan['unique_allocated_bytes'],
                      archive=str(ARCHIVE.relative_to(ROOT)), archive_sha256=archive_sha,
                      archive_bytes=ARCHIVE.stat().st_size,
                      mountpoint=str(VIEW.relative_to(ROOT)), systemd_unit=unit_name,
                      mount_enabled_for_reboot=True, original_paths_preserved=True,
                      original_file_contents_unchanged=True, selected_paths_readonly=True,
                      protected_sources_freshly_verified=len(old['protected_sources']),
                      canonical_files_unchanged=True, only_full_backup='backups/20261002T154458Z/sda.img',
                      original_backup_sha256_verified=True, no_original_source_code_removed=True,
                      no_distinct_result_discarded=True, before_free_bytes=before.free,
                      after_free_bytes=after.free, freed_bytes=after.free - before.free,
                      device_IO=False, created_utc=datetime.now(timezone.utc).isoformat())
        save(BASE / 'compaction-result.json', result)
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
