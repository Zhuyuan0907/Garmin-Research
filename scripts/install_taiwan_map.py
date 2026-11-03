#!/usr/bin/env python3
"""Verify and add the prepared Taiwan map to the exact backed-up navigator.

Default is a read-only preflight; --install adds one file, reads it back and
unmounts. Existing maps, firmware and unlock files are never replaced.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import garmin_backup
import verify_garmin_map

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / 'backups/20261002T154458Z'
TARGET = Path('Map/Taiwan_OSM_20261001.img')
STOCK = ('.System/gmapprom.img', '.System/gmapprom1.img',
         '.System/gmapbmap.img', '.System/gmaptz.img')


def checksum(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def identity(data):
    root = ET.fromstring(data)
    ns = {'g': root.tag.split('}')[0][1:]}
    values = [root.findtext(key, namespaces=ns) for key in
              ('g:Model/g:PartNumber', 'g:Model/g:SoftwareVersion', 'g:Id')]
    if values[:2] != ['006-B1352-00', '800'] or not values[2]:
        raise RuntimeError('Device is not the expected Taiwan HWID 1352 software 8.00')
    maps = {}
    for item in root.findall('g:MassStorageMode/g:DataType', ns):
        maps[item.findtext('g:Name', namespaces=ns)] = item.findtext(
            'g:File/g:Location/g:Path', namespaces=ns)
    if maps.get('NMaps') != 'Map' or maps.get('UnicodeMaps') != 'Map':
        raise RuntimeError('Expected map interfaces are not declared')
    return tuple(values)


def prepared(manifest_path):
    metadata = json.loads((BACKUP / 'sda.json').read_text())
    backup_check = json.loads((BACKUP / 'verification.json').read_text())
    if metadata['state'] != 'verified' or backup_check['state'] != 'verified':
        raise RuntimeError('Backup is not verified')
    if (BACKUP / metadata['image']).stat().st_size != metadata['size']:
        raise RuntimeError('Verified backup image size changed')
    checked = verify_garmin_map.verify(manifest_path)
    expected_identity = identity((BACKUP / 'files/Garmin/GarminDevice.xml').read_bytes())
    inventory = {item['path']: item for item in json.loads(
        (BACKUP / 'files-manifest.json').read_text())}
    for name in STOCK:
        entry = inventory[name]
        path = BACKUP / 'files' / name
        if path.stat().st_size != entry['size'] or checksum(path) != entry['sha256']:
            raise RuntimeError('A backed-up stock map differs from its verified inventory')
    return metadata, checked, expected_identity, inventory


def same_usb(disk, metadata):
    saved = metadata['disk']['usb']
    current = disk['usb']
    return (int(disk['size']) == metadata['size'] and
            all(current.get(key) == saved.get(key) for key in
                ('idVendor', 'idProduct', 'serial')) and bool(saved.get('serial')))


def confirm_live_identity(disk):
    current = garmin_backup.usb_identity(
        (Path('/sys/class/block') / disk['name']).resolve())
    if current != disk['usb']:
        raise RuntimeError('USB identity changed during preflight')
    size = subprocess.run(['blockdev', '--getsize64', disk['path']],
                          check=True, capture_output=True, text=True, timeout=10)
    if int(size.stdout) != int(disk['size']):
        raise RuntimeError('USB disk size changed during preflight')


def run(install, manifest_path, update_project_map):
    metadata, checked, expected_identity, inventory = prepared(manifest_path)
    map_manifest = json.loads(manifest_path.read_text())
    result = {'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'state': 'prepared_waiting_for_usb', 'source': checked['image'],
              'device_file': str(TARGET), 'bytes': checked['bytes'],
              'sha256': checked['sha256'], 'original_files_replaced': 0,
              'device_display_verified': False, 'device_search_verified': False,
              'device_routing_verified': False, 'install_requested': install,
              'credit_text': map_manifest.get('credit_text'),
              'credit_display_verified': False, 'manifest': str(manifest_path)}
    candidates = [disk for disk in garmin_backup.disks() if same_usb(disk, metadata)]
    if not candidates:
        if install:
            raise RuntimeError('Expected navigator USB mass storage is not present')
        result['reason'] = 'Prepared image verified; connect navigator in USB mass-storage mode'
        return result
    if len(candidates) != 1:
        raise RuntimeError('Expected exactly one matching Garmin internal disk')
    disk = candidates[0]
    garmin_backup.ensure_source(disk)
    if disk.get('children'):
        raise RuntimeError('Unexpected partitioned layout; refusing to infer a write target')
    mountpoint = Path(tempfile.mkdtemp(prefix='garmin-map-', dir='/run'))
    mounted = False
    created_partial = False
    created_target = False
    previous_moved = False
    succeeded = False
    destination = mountpoint / TARGET
    partial = destination.with_suffix('.img.partial')
    previous_file = destination.with_suffix('.img.previous')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    evidence = ROOT / 'evidence' / f'map-installation-{stamp}.json'
    try:
        subprocess.run(['mount', '-t', 'vfat', '-o', 'ro,nosuid,nodev,noexec',
                        disk['path'], str(mountpoint)], check=True, capture_output=True, text=True)
        mounted = True
        xml_path = mountpoint / 'Garmin/GarminDevice.xml'
        xml_data = xml_path.read_bytes()
        if identity(xml_data) != expected_identity:
            raise RuntimeError('Device XML does not match the backed-up navigator identity')
        for name in STOCK:
            path = mountpoint / name
            entry = inventory[name]
            if path.stat().st_size != entry['size'] or checksum(path) != entry['sha256']:
                raise RuntimeError('A stock map differs from the verified backup')
        result['stock_map_hashes_checked'] = True
        space = os.statvfs(mountpoint)
        result['live_free_bytes'] = space.f_bavail * space.f_frsize
        result['required_bytes_with_reserve'] = checked['bytes'] + 16 * 1024 * 1024
        existing_matches = destination.exists() and destination.stat().st_size == checked['bytes'] and checksum(destination) == checked['sha256']
        replacing = destination.exists() and not existing_matches
        if replacing:
            prior = json.loads((ROOT / 'evidence/map-installation-latest.json').read_text())
            if (not update_project_map or prior.get('state') not in
                ('installed_readback_verified', 'already_installed_readback_verified')
                or not prior.get('unmounted') or prior.get('device_file') != str(TARGET)
                or destination.stat().st_size != prior['bytes']
                or checksum(destination) != prior['sha256']):
                raise RuntimeError('Only the previously verified project map can be updated')
            if previous_file.exists():
                raise RuntimeError('A previous update recovery file exists; refusing to overwrite it')
            result['previous_project_image_sha256'] = prior['sha256']
            result['project_map_updated'] = bool(install)
        if existing_matches:
            result['state'] = 'already_installed_readback_verified'
            succeeded = True
        else:
            if result['live_free_bytes'] < result['required_bytes_with_reserve']:
                raise RuntimeError('Insufficient space for the map and reserve')
            if partial.exists():
                raise RuntimeError('A previous partial map exists; refusing to replace it')
            confirm_live_identity(disk)
            if install:
                subprocess.run(['mount', '-o', 'remount,rw,nosuid,nodev,noexec',
                                str(mountpoint)], check=True, capture_output=True, text=True)
                destination.parent.mkdir(exist_ok=True)
                with Path(checked['image']).open('rb') as source, partial.open('xb') as output:
                    created_partial = True
                    for chunk in iter(lambda: source.read(4 * 1024 * 1024), b''):
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if partial.stat().st_size != checked['bytes'] or checksum(partial) != checked['sha256']:
                    raise RuntimeError('New map read-back verification failed')
                # A FAT mount cannot contain symbolic links; only our new file is renamed.
                if destination.exists() and not replacing:
                    raise RuntimeError('Destination appeared while copying')
                if replacing:
                    if checksum(destination) != result['previous_project_image_sha256']:
                        raise RuntimeError('Previous project map changed while copying')
                    destination.rename(previous_file)
                    previous_moved = True
                partial.rename(destination)
                created_partial = False
                created_target = True
                parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
                if xml_path.read_bytes() != xml_data:
                    raise RuntimeError('Device metadata changed unexpectedly')
                for name in STOCK:
                    if checksum(mountpoint / name) != inventory[name]['sha256']:
                        raise RuntimeError('A stock map changed unexpectedly')
                if previous_moved:
                    previous_file.unlink()
                    previous_moved = False
                result['state'] = 'installed_readback_verified'
            else:
                result['state'] = 'device_preflight_passed'
            succeeded = True
    except Exception as error:
        result.update(state='failed', error=str(error))
        for path, created in ((partial, created_partial), (destination, created_target)):
            if created:
                try:
                    path.unlink()
                    result['failed_new_file_removed'] = True
                except OSError:
                    result['failed_new_file_removed'] = False
        if previous_moved:
            try:
                if destination.exists():
                    raise RuntimeError('Cannot restore previous project map over an existing destination')
                previous_file.rename(destination)
                previous_moved = False
                result['previous_project_map_restored'] = True
            except (OSError, RuntimeError):
                result['previous_project_map_restored'] = False
        raise
    finally:
        unmount = subprocess.run(['umount', str(mountpoint)], capture_output=True, text=True) if mounted else None
        result['unmounted'] = unmount is None or unmount.returncode == 0
        if not result['unmounted']:
            result['unmount_error'] = unmount.stderr.strip()
            succeeded = False
        else:
            mountpoint.rmdir()
        result['completed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        evidence.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        if succeeded:
            (ROOT / 'evidence/map-installation-latest.json').write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    if not succeeded:
        raise RuntimeError('Map installation or unmount failed; inspect installation evidence')
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', action='store_true', help='Add the prepared map after successful preflight')
    parser.add_argument('--manifest', type=Path, default=verify_garmin_map.DEFAULT)
    parser.add_argument('--update-project-map', action='store_true',
                        help='Allow updating only the project map matching the prior installation record')
    args = parser.parse_args()
    with (ROOT / 'evidence/usb-operation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(args.install, args.manifest.resolve(), args.update_project_map)
    if not args.install:
        (ROOT / 'evidence/map-installation-preflight.json').write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
