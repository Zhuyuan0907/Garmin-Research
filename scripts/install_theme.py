#!/usr/bin/env python3
"""Add the prepared theme after verified backup, then read it back and unmount."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / 'backups/20261002T154458Z'
THEME = ROOT / 'staging/Themes/Map/Pi_Contrast.kmtf'


def checksum(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.umask(0o077)
    metadata = json.loads((BACKUP / 'sda.json').read_text())
    verification = json.loads((BACKUP / 'verification.json').read_text())
    if metadata['state'] != 'verified' or verification['state'] != 'verified':
        raise RuntimeError('Backup is not verified')
    if (BACKUP / metadata['image']).stat().st_size != metadata['size']:
        raise RuntimeError('Backup image size changed')
    data = THEME.read_bytes()
    theme_hash = hashlib.sha256(data).hexdigest()
    prepared = json.loads((ROOT / 'evidence/prepared-theme.json').read_text())
    if prepared['sha256'] != theme_hash or ET.fromstring(data).tag != 'GARMIN_MAP_THEME':
        raise RuntimeError('Prepared theme changed or is invalid')
    spec = importlib.util.spec_from_file_location('garmin_backup', ROOT / 'scripts/garmin_backup.py')
    backup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backup)
    candidates = [d for d in backup.disks() if int(d['size']) == metadata['size'] and d['usb']['idProduct'] == '2548']
    if len(candidates) != 1:
        raise RuntimeError('Expected exactly one matching Garmin internal disk')
    disk = candidates[0]
    backup.ensure_source(disk)
    mountpoint = Path(tempfile.mkdtemp(prefix='garmin-theme-', dir='/run'))
    mounted = False
    created = False
    succeeded = False
    result = {'started': dt.datetime.now(dt.timezone.utc).isoformat(), 'state': 'started', 'device_file': 'Themes/Map/Pi_Contrast.kmtf', 'sha256': theme_hash, 'original_files_replaced': 0, 'device_ui_verified': False}
    try:
        subprocess.run(['mount', '-t', 'vfat', '-o', 'ro,nosuid,nodev,noexec', disk['path'], str(mountpoint)], check=True, capture_output=True, text=True)
        mounted = True
        xml = mountpoint / 'Garmin/GarminDevice.xml'
        if xml.read_bytes() != (BACKUP / 'files/Garmin/GarminDevice.xml').read_bytes():
            raise RuntimeError('Device identity file differs from verified backup')
        source_theme = mountpoint / 'Themes/Map/United Kingdom.kmtf'
        if checksum(source_theme) != checksum(BACKUP / 'files/Themes/Map/United Kingdom.kmtf'):
            raise RuntimeError('Original theme differs from verified backup')
        target = mountpoint / result['device_file']
        if not target.parent.is_dir() or target.exists():
            raise RuntimeError('Target directory is missing or new theme already exists')
        subprocess.run(['mount', '-o', 'remount,rw,nosuid,nodev,noexec', str(mountpoint)], check=True, capture_output=True, text=True)
        with target.open('xb') as f:
            created = True
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if checksum(target) != theme_hash or target.stat().st_size != len(data):
            raise RuntimeError('Read-back verification failed')
        if source_theme.read_bytes() != (BACKUP / 'files/Themes/Map/United Kingdom.kmtf').read_bytes() or xml.read_bytes() != (BACKUP / 'files/Garmin/GarminDevice.xml').read_bytes():
            raise RuntimeError('Original theme or device metadata changed unexpectedly')
        result.update(state='installed_readback_verified', bytes=len(data), verification='New file SHA-256 and size match; original theme and device XML unchanged')
        succeeded = True
    except Exception as error:
        result.update(state='failed', error=str(error))
        if mounted and created:
            try:
                target.unlink()
                result['failed_new_file_removed'] = True
            except OSError:
                result['failed_new_file_removed'] = False
        raise
    finally:
        if mounted:
            unmount = subprocess.run(['umount', str(mountpoint)], capture_output=True, text=True)
            result['unmounted'] = unmount.returncode == 0
            if unmount.returncode:
                result['unmount_error'] = unmount.stderr.strip()
                succeeded = False
        else:
            result['unmounted'] = True
        # Never recurse into or remove a mount that failed to unmount.
        if result['unmounted']:
            mountpoint.rmdir()
        result['completed'] = dt.datetime.now(dt.timezone.utc).isoformat()
        (ROOT / 'evidence/theme-installation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    if not succeeded:
        raise RuntimeError('Theme installation or unmount failed; inspect installation evidence')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
