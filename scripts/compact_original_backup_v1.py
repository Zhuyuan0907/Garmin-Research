#!/usr/bin/env python3
"""Losslessly compress the sole USB image; verify before retiring raw storage.

Preserve sda.img and files/ as read-only views. The original raw inode remains
available for rollback until the complete decompressed image, all FAT files,
and the cold systemd mount dependency have passed verification.
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
BACKUP = ROOT / 'backups/20261002T154458Z'
IMAGE = BACKUP / 'sda.img'
FILES = BACKUP / 'files'
ARCHIVE = BACKUP / 'sda-backup-v1.squashfs'
VIEW = ROOT / 'archives/original-disk-v1'
BASE = ROOT / 'staging/garminos-backup-compaction-v1'
SEED = BASE / 'input'
ROLLBACK = BACKUP / 'sda.img.uncompressed-v1'
AUDIT = ROOT / 'evidence/firmware-analysis/native-os20-scheduled-decoder-checkpoint-audit.json'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def save(name, value):
    with (BASE / name).open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def mount_state(path, kind):
    assert path.is_mount(), str(path)
    fs = json.loads(run('findmnt', '--json', '--mountpoint', str(path), '-o',
                        'TARGET,SOURCE,FSTYPE,OPTIONS'))['filesystems'][0]
    assert fs['fstype'] == kind and 'ro' in fs['options'].split(','), fs
    return fs


def unit_name(path):
    return run('systemd-escape', '--path', '--suffix=mount', str(path)).strip()


def reject_open_users():
    """Reject image writers and processes retaining the old FAT mount."""
    inode = (IMAGE.stat().st_dev, IMAGE.stat().st_ino)
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        for item in ('cwd', 'root'):
            try:
                target = (proc / item).resolve()
                assert not target.is_relative_to(FILES), (proc.name, item, str(target))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
        try:
            descriptors = list((proc / 'fd').iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for descriptor in descriptors:
            try:
                target = descriptor.resolve()
                assert not target.is_relative_to(FILES), (proc.name, str(target))
                st = descriptor.stat()
                if (st.st_dev, st.st_ino) != inode:
                    continue
                info = (proc / 'fdinfo' / descriptor.name).read_text()
                flags = int(next(x.split()[1] for x in info.splitlines()
                                 if x.startswith('flags:')), 8)
                assert flags & os.O_ACCMODE == os.O_RDONLY, (proc.name, str(descriptor))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass


def main():
    with open('/run/garmin-backup-compaction-v1.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not BASE.exists() and not ARCHIVE.exists() and not VIEW.exists()
        assert not ROLLBACK.exists() and not IMAGE.is_symlink()
        before = shutil.disk_usage(ROOT)
        expected = json.loads((BACKUP / 'sda.json').read_text())
        old = json.loads(AUDIT.read_text())
        assert old['all_passed']
        assert all(sha(ROOT / p) == h for p, h in old['canonical_after_sha256'].items())
        assert IMAGE.stat().st_nlink == 1 and IMAGE.stat().st_size == expected['size']
        mount_state(FILES, 'vfat')
        reject_open_users()
        BASE.mkdir()
        raw_stat = IMAGE.stat()
        print(json.dumps({'stage': 'verifying_original_full_image',
                          'bytes': expected['size']}), flush=True)
        assert sha(IMAGE) == expected['sha256']
        files_unit_name = unit_name(FILES)
        files_unit = Path('/etc/systemd/system') / files_unit_name
        original_unit = files_unit.read_text()
        save('verified-plan.json', dict(
            created_utc=datetime.now(timezone.utc).isoformat(), user_authorized=True,
            original_image=str(IMAGE.relative_to(ROOT)), size=expected['size'],
            image_sha256=expected['sha256'], raw_allocated_bytes=raw_stat.st_blocks * 512,
            before_free_bytes=before.free, original_file_view_unit=files_unit_name,
            original_file_view_unit_text=original_unit,
            unchanged_canonical_sha256=old['canonical_after_sha256'],
            device_IO=False, working_sources_and_distinct_results_removed=False))
        SEED.mkdir()
        os.link(IMAGE, SEED / 'sda.img')
        save('backup-identity.json', {'logical_image_bytes': expected['size'],
             'logical_image_sha256': expected['sha256'],
             'scope': expected['scope'], 'lossless': True})
        shutil.copyfile(BASE / 'backup-identity.json', SEED / 'backup-identity.json')
        partial = ARCHIVE.with_suffix('.squashfs.partial')
        assert not partial.exists()
        print(json.dumps({'stage': 'compressing_verified_original',
                          'raw_original_retained': True}), flush=True)
        subprocess.run(['mksquashfs', str(SEED), str(partial), '-noappend',
                        '-comp', 'zstd', '-Xcompression-level', '8', '-b', '1M',
                        '-processors', '2', '-mem', '128M', '-no-progress'], check=True)
        assert partial.stat().st_blocks * 512 < raw_stat.st_blocks * 512 - 100_000_000
        os.chmod(partial, 0o444)
        partial.rename(ARCHIVE)
        archive_hash = sha(ARCHIVE)
        VIEW.mkdir()
        archive_unit_name = unit_name(VIEW)
        archive_unit = Path('/etc/systemd/system') / archive_unit_name
        assert not archive_unit.exists()
        archive_text = f'''[Unit]
Description=Garmin sole original USB image, lossless compressed storage
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
        new_files_text = original_unit.replace(
            'After=local-fs.target',
            f'After=local-fs.target {archive_unit_name}\nRequiresMountsFor={VIEW}')
        assert new_files_text != original_unit
        archive_unit.write_text(archive_text)
        run('systemd-analyze', 'verify', str(archive_unit))
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', archive_unit_name)
        mount_state(VIEW, 'squashfs')
        compressed_image = VIEW / 'sda.img'
        assert compressed_image.stat().st_size == expected['size']
        print(json.dumps({'stage': 'verifying_full_decompressed_image',
                          'archive_bytes': ARCHIVE.stat().st_size,
                          'raw_original_retained': True}), flush=True)
        assert sha(compressed_image) == expected['sha256']
        assert json.loads((VIEW / 'backup-identity.json').read_text()) == json.loads(
            (BASE / 'backup-identity.json').read_text())
        save('compressed-image-readback.json', dict(
            all_passed=True, full_image_sha256=expected['sha256'],
            archive=str(ARCHIVE.relative_to(ROOT)), archive_sha256=archive_hash,
            archive_bytes=ARCHIVE.stat().st_size, original_raw_still_retained=True,
            archive_unit=archive_unit_name, archive_unit_text=archive_text,
            proposed_files_unit_text=new_files_text))
        reject_open_users()
        assert IMAGE.stat().st_ino == raw_stat.st_ino
        assert IMAGE.stat().st_mtime_ns == raw_stat.st_mtime_ns
        temporary = IMAGE.with_name('.sda-compaction-v1-link')
        assert not temporary.exists() and not temporary.is_symlink()
        os.symlink(os.path.relpath(compressed_image, IMAGE.parent), temporary)
        IMAGE.rename(ROLLBACK)
        os.replace(temporary, IMAGE)
        try:
            files_unit.write_text(new_files_text)
            run('systemd-analyze', 'verify', str(files_unit), str(archive_unit))
            run('systemctl', 'daemon-reload')
            run('systemctl', 'stop', files_unit_name)
            assert not FILES.is_mount()
            # Exercise the boot dependency: requesting only files.mount must
            # start its compressed-image mount from a completely stopped state.
            run('systemctl', 'stop', archive_unit_name)
            assert not VIEW.is_mount()
            run('systemctl', 'start', files_unit_name)
            archive_fs = mount_state(VIEW, 'squashfs')
            files_fs = mount_state(FILES, 'vfat')
            loop = next(row for row in json.loads(run('losetup', '--list', '--json'))[
                'loopdevices'] if row['name'] == files_fs['source'])
            assert loop['ro'] and loop['back-file'] == str(compressed_image), loop
            manifest = json.loads((BACKUP / 'files-manifest.json').read_text())
            expected_paths = {row['path'] for row in manifest}
            assert len(manifest) == 1402
            actual_paths = {str(p.relative_to(FILES)) for p in FILES.rglob('*') if p.is_file()}
            assert actual_paths == expected_paths
            print(json.dumps({'stage': 'verifying_all_1402_FAT_files',
                              'cold_mount_dependency_passed': True,
                              'original_raw_still_retained': True}), flush=True)
            for row in manifest:
                p = FILES / row['path']
                assert p.stat().st_size == row['size'] and sha(p) == row['sha256'], row['path']
            assert all(sha(ROOT / p) == h for p, h in old['canonical_after_sha256'].items())
            assert IMAGE.is_symlink() and IMAGE.resolve() == compressed_image
            # Write the full successful verification before releasing raw data.
            save('file-view-readback-before-removal.json', dict(
                all_passed=True, full_image_SHA256_verified=True,
                image_sha256=expected['sha256'], all_files_checked=len(manifest),
                all_file_bytes_checked=sum(row['size'] for row in manifest),
                all_file_paths_and_content_unchanged=True,
                cold_mount_dependency_passed=True, archive_mount=archive_fs,
                files_mount=files_fs, files_loop=loop,
                archive_unit_enabled=run('systemctl', 'is-enabled', archive_unit_name).strip(),
                files_unit_enabled=run('systemctl', 'is-enabled', files_unit_name).strip(),
                original_raw_still_retained=True, canonical_research_files_unchanged=True))
        except BaseException:
            # Keep a full raw rollback until every post-switch test completes.
            subprocess.run(['systemctl', 'stop', files_unit_name], capture_output=True)
            assert not FILES.is_mount()
            IMAGE.unlink()
            ROLLBACK.rename(IMAGE)
            files_unit.write_text(original_unit)
            run('systemctl', 'daemon-reload')
            run('systemctl', 'start', files_unit_name)
            mount_state(FILES, 'vfat')
            save('rollback.json', {'original_raw_image_restored': True,
                                  'no_original_raw_data_discarded': True})
            raise
        ROLLBACK.unlink()
        shutil.rmtree(SEED)
        os.sync()
        after = shutil.disk_usage(ROOT)
        assert after.free > before.free + 100_000_000
        result = dict(
            all_passed=True, created_utc=datetime.now(timezone.utc).isoformat(),
            user_authorized_space_reduction=True,
            sole_physical_full_backup=str(ARCHIVE.relative_to(ROOT)),
            archive_sha256=archive_hash, archive_bytes=ARCHIVE.stat().st_size,
            logical_image_path=str(IMAGE.relative_to(ROOT)),
            logical_image_bytes=expected['size'], logical_image_sha256=expected['sha256'],
            full_uncompressed_image_SHA256_freshly_verified=True,
            raw_uncompressed_duplicate_removed=True, raw_rollback_removed=True,
            all_1402_backup_file_hashes_freshly_verified=True,
            original_image_and_file_paths_preserved=True,
            cold_systemd_dependency_test_passed=True,
            compressed_image_mount_unit=archive_unit_name, file_view_mount_unit=files_unit_name,
            boot_mount_units_enabled=True, sole_backup_scope=expected['scope'],
            before_free_bytes=before.free, after_free_bytes=after.free,
            freed_bytes=after.free - before.free,
            original_allocated_bytes=raw_stat.st_blocks * 512,
            compressed_allocated_bytes=ARCHIVE.stat().st_blocks * 512,
            previous_cleanup_freed_bytes=7092342784,
            cumulative_cleanup_freed_bytes=7092342784 + after.free - before.free,
            canonical_research_files_unchanged=True,
            whole_prior_protected_source_rehash_repeated=False,
            original_sources_and_distinct_results_preserved=True,
            device_IO=False, goal_status='active')
        save('compaction-result.json', result)
        print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
