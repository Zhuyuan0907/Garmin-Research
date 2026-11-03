#!/usr/bin/env python3
"""Preflight/install/rollback one verified navigation map on one exact Garmin.

Python standard library only; Linux lsblk, mount and umount are required for
physical USB operations. Default mode mounts read-only and makes no device
changes. No device identifier or USB serial is written to public JSON.
"""
import argparse
import contextlib
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET

NEW_PATH = 'Map/Taiwan_OSM_SearchRepair_v2.img'
OLD_PATH = 'Map/Taiwan_OSM_20261001.img'
OLD_SHA = '2801d07dfa4f3ae8d69fcdaea616e88499da6a6ed4a6d773b378253b9ebcb600'
OLD_BYTES = 134852608
DISK_BYTES = 3879731200
RESERVE_BYTES = 16 * 1024 * 1024
CORE_STOCK = {'.system/gmapprom.img', '.system/gmapprom1.img', '.system/gmapbmap.img', '.system/gmaptz.img'}


class Refusal(RuntimeError):
    """Deliberate rejection with a non-private, stable explanation."""


def need(ok, message):
    if not ok:
        raise Refusal(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def private_hash(value):
    return hashlib.sha256(str(value).strip().encode('utf-8')).hexdigest()


def timestamp():
    return dt.datetime.now().astimezone().isoformat()


def safe_path(root, relative):
    need(isinstance(relative, str) and '\\' not in relative, 'Invalid relative path')
    rel = PurePosixPath(relative)
    need(not rel.is_absolute() and rel.parts and all(p not in ('.', '..', '') for p in relative.split('/')), 'Invalid relative path')
    root = Path(root).resolve()
    result = root
    for part in rel.parts:
        result = result / part
        need(not result.is_symlink(), 'Symlink in bundle/device path')
    return result


def valid_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def load_manifest(bundle):
    bundle = Path(bundle).resolve()
    manifest_path = safe_path(bundle, 'manifest.json')
    need(manifest_path.is_file(), 'Bundle manifest is missing')
    m = json.loads(manifest_path.read_text())
    for key in ('new_map', 'previous_project_map', 'device', 'preserved_stock_files'):
        need(key in m, 'Bundle manifest is incomplete')
    new, old, device = m['new_map'], m['previous_project_map'], m['device']
    need(new.get('bundle_path') == NEW_PATH and new.get('device_path') == NEW_PATH, 'Unexpected new project map path')
    need(old.get('device_path') == OLD_PATH and old.get('disabled_path') == OLD_PATH + '.disabled', 'Unexpected prior project map path')
    need(old.get('bytes') == OLD_BYTES and old.get('sha256') == OLD_SHA, 'Prior project map identity is not the verified one')
    need(isinstance(new.get('bytes'), int) and not isinstance(new['bytes'], bool) and new['bytes'] >= 1024 and valid_sha(new.get('sha256')), 'Invalid new image identity')
    need(device.get('part_number') == '006-B1352-00' and str(device.get('software_version')) == '800', 'Unsupported Garmin model/software')
    need(device.get('disk_bytes') == DISK_BYTES and valid_sha(device.get('unit_id_sha256')), 'Invalid target disk/unit identity')
    usb = device.get('usb', {})
    need(usb.get('vendor') == '091e' and usb.get('product') == '2548' and valid_sha(usb.get('serial_sha256')), 'Invalid USB identity')
    need(isinstance(m['preserved_stock_files'], list), 'Preserved stock inventory is missing')
    seen = set()
    reserved = {NEW_PATH.lower(), OLD_PATH.lower(), (OLD_PATH + '.disabled').lower(), (NEW_PATH + '.partial').lower(), (NEW_PATH + '.rollback.partial').lower()}
    for item in m['preserved_stock_files']:
        p = item.get('device_path')
        safe_path(bundle, p)
        need(p.lower() not in seen | reserved, 'Stock/project inventory path collision')
        need(isinstance(item.get('bytes'), int) and not isinstance(item['bytes'], bool) and item['bytes'] >= 0 and valid_sha(item.get('sha256')), 'Invalid stock file identity')
        seen.add(p.lower())
    need(CORE_STOCK <= seen, 'Four original map identities must be preserved')
    source = safe_path(bundle, new['bundle_path'])
    verify_file(source, new, 'Bundled image')
    with source.open('rb') as stream:
        header = stream.read(512)
    need(len(header) == 512 and header[0] == 0 and header[16:23] == b'DSKIMG\0' and header[65:72] == b'GARMIN\0', 'Bundled image has no expected IMG header')
    return m, source, digest(manifest_path)


def verify_file(path, entry, label):
    need(path.is_file() and not path.is_symlink(), label + ' is missing or not a regular file')
    need(path.stat().st_size == entry['bytes'] and digest(path) == entry['sha256'], label + ' bytes/hash mismatch')


def verify_xml(data, device):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise Refusal('Garmin XML is malformed') from None
    need(root.tag.startswith('{'), 'Garmin XML namespace is missing')
    ns = {'g': root.tag.split('}')[0][1:]}
    need(root.findtext('g:Model/g:PartNumber', namespaces=ns) == device['part_number'], 'Garmin XML model mismatch')
    need(root.findtext('g:Model/g:SoftwareVersion', namespaces=ns) == str(device['software_version']), 'Garmin XML software mismatch')
    unit = root.findtext('g:Id', namespaces=ns)
    need(unit is not None and private_hash(unit) == device['unit_id_sha256'], 'Garmin XML unit identity mismatch')
    interfaces = {}
    for dtype in root.findall('g:MassStorageMode/g:DataType', ns):
        name = dtype.findtext('g:Name', namespaces=ns)
        interfaces[name] = [f.findtext('g:Location/g:Path', namespaces=ns) for f in dtype.findall('g:File', ns)]
    need('Map' in interfaces.get('NMaps', []) and 'Map' in interfaces.get('UnicodeMaps', []), 'Required Map/UnicodeMaps interfaces are absent')


def verify_stock(root, m):
    for item in m['preserved_stock_files']:
        verify_file(safe_path(root, item['device_path']), item, 'Preserved stock file')


def map_state(root, m):
    new, old = m['new_map'], m['previous_project_map']
    target, active, disabled = (safe_path(root, p) for p in (new['device_path'], old['device_path'], old['disabled_path']))
    need(not (active.exists() and disabled.exists()), 'Both active and disabled prior map exist; reconcile before installing')
    need(active.exists() or disabled.exists(), 'Verified previous project map is missing')
    for path in (active, disabled):
        if path.exists():
            verify_file(path, old, 'Prior project map')
    if target.exists():
        verify_file(target, new, 'Existing new project map')
    for suffix in ('.partial', '.rollback.partial'):
        need(not safe_path(root, new['device_path'] + suffix).exists(), 'Recovery/partial project file exists; refusing to overwrite it')
    return {'new_present': target.exists(), 'old_active': active.exists(), 'old_disabled': disabled.exists()}


def device_preflight(root, m, mode):
    xml = safe_path(root, 'Garmin/GarminDevice.xml').read_bytes()
    verify_xml(xml, m['device'])
    verify_stock(root, m)
    state = map_state(root, m)
    space = os.statvfs(root)
    free = space.f_bavail * space.f_frsize
    required = m['new_map']['bytes'] + RESERVE_BYTES if mode != 'rollback' and not state['new_present'] else 0
    need(free >= required, 'Insufficient free device space for image plus reserve')
    return xml, {'state': state, 'free_bytes': free, 'required_free_bytes': required,
                 'xml_unit_and_interfaces_verified': True, 'preserved_stock_hashes_verified': True}


def mountpoints(record):
    values = record.get('mountpoints', record.get('mountpoint'))
    if values is None:
        return []
    return [v for v in (values if isinstance(values, list) else [values]) if v]


def usb_sysfs(name, sys_class=Path('/sys/class/block')):
    need(re.fullmatch('[A-Za-z0-9_-]+', name) is not None and not name.startswith(('loop', 'ram', 'zram', 'dm-')), 'Non-physical block device is forbidden')
    link = sys_class / name
    need(link.exists(), 'USB block device vanished')
    node = link.resolve()
    need((node / 'device').exists(), 'Block device has no physical device')
    usb_parent = None
    for parent in (node, *node.parents):
        if (parent / 'idVendor').is_file() and (parent / 'idProduct').is_file():
            usb_parent = parent
            break
    need(usb_parent is not None, 'USB identity is incomplete')
    vendor = (usb_parent / 'idVendor').read_text().strip().lower()
    product = (usb_parent / 'idProduct').read_text().strip().lower()
    serial = (usb_parent / 'serial').read_text().strip() if (usb_parent / 'serial').is_file() else ''
    interfaces = list(usb_parent.glob(usb_parent.name + ':*/bInterfaceClass'))
    # usbfs places interface nodes beside the USB device on some kernels.
    interfaces += list(usb_parent.parent.glob(usb_parent.name + ':*/bInterfaceClass'))
    sectors = int((node / 'size').read_text().strip())
    return {'vendor': vendor, 'product': product,
            'serial_sha256': private_hash(serial) if serial else None, 'disk_bytes': sectors * 512,
            'mass_storage_interface': any(p.read_text().strip().lower() == '08' for p in interfaces),
            'sysfs_path': str(node), 'major_minor': (node / 'dev').read_text().strip()}


def run_command(command):
    r = subprocess.run(command, capture_output=True, text=True, timeout=60)
    need(r.returncode == 0, 'Required system command failed: ' + command[0])
    return r.stdout


def disk_records():
    return json.loads(run_command(['lsblk', '--json', '--bytes', '--paths', '--output', 'NAME,KNAME,PATH,TYPE,TRAN,SIZE,MOUNTPOINTS,MAJ:MIN']))['blockdevices']


def check_mountinfo(major_minor):
    lines = Path('/proc/self/mountinfo').read_text().splitlines()
    need(not any(len(fields := line.split()) > 2 and fields[2] == major_minor for line in lines), 'Target disk is already mounted')


def select_disk(records, expected, identity_reader=usb_sysfs, mount_checker=check_mountinfo):
    matches = []
    for disk in records:
        if disk.get('type') != 'disk' or disk.get('tran') != 'usb':
            continue
        name = disk.get('kname') or Path(disk.get('name', '')).name
        name = Path(name).name
        if name.startswith(('loop', 'ram', 'zram', 'dm-')):
            continue
        usb = identity_reader(name)
        if usb['vendor'] != expected['usb']['vendor'] or usb['product'] != expected['usb']['product']:
            continue
        need(usb.get('mass_storage_interface') is True, 'Garmin USB device has no mass-storage interface')
        need(usb['serial_sha256'] == expected['usb']['serial_sha256'], 'A Garmin USB disk has a different serial identity')
        # The same Garmin exposes its empty SD reader as a zero-byte USB LUN.
        # Ignore only independently confirmed no-media devices; reject all
        # nonzero size mismatches and disagreements between lsblk and sysfs.
        if int(disk.get('size', -1)) == 0 and usb['disk_bytes'] == 0:
            need(not disk.get('children') and not mountpoints(disk), 'Unexpected mounted/partitioned empty Garmin disk')
            continue
        need(int(disk.get('size', -1)) == expected['disk_bytes'] == usb['disk_bytes'], 'Garmin USB disk size mismatch')
        need(not disk.get('children'), 'Unexpected partitioned/multi-child disk layout')
        need(not mountpoints(disk), 'Target disk is already mounted')
        mount_checker(usb['major_minor'])
        path = disk.get('path') or disk.get('name')
        need(path == '/dev/' + name, 'Unexpected block-device path')
        need(disk.get('maj:min') == usb['major_minor'], 'Block major/minor changed')
        matches.append({'name': name, 'path': path, 'identity': usb})
    need(len(matches) <= 1, 'Multiple matching Garmin disks; refusing ambiguous target')
    return matches[0] if matches else None


def reconfirm_disk(disk, expected):
    info = usb_sysfs(disk['name'])
    need(info == disk['identity'], 'USB identity changed during operation')
    need(info['disk_bytes'] == expected['disk_bytes'], 'USB size changed during operation')
    st = os.stat(disk['path'])
    need(stat.S_ISBLK(st.st_mode), 'Target is no longer a block device')
    need(str(os.major(st.st_rdev)) + ':' + str(os.minor(st.st_rdev)) == info['major_minor'], 'Block node identity changed')


def rename_no_replace(source, destination):
    """Linux atomic rename with NOREPLACE, supported by modern vfat/ext4."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, 'renameat2', None)
    need(function is not None, 'System lacks safe atomic no-replace rename')
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        e = ctypes.get_errno()
        raise OSError(e, 'Atomic no-replace rename failed')


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            os.fsync(fd)
        except OSError as e:
            if e.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
            os.sync()
    finally:
        os.close(fd)


def owned_inode(path):
    st = path.stat()
    return (st.st_dev, st.st_ino)


def remove_owned(path, inode):
    need(path.exists() and not path.is_symlink() and owned_inode(path) == inode, 'Owned file changed; refusing cleanup of another file')
    path.unlink()


def restore_verified(source, destination, expected):
    verify_file(source, expected, 'Owned rename source pending undo')
    rename_no_replace(source, destination)


def transaction(root, m, source, mode, final_check=None, fault=None):
    """True file mutation logic; pure-directory tests call this same function.

    All removals either require own newly-created inode or a complete expected
    map hash. Stock verification executes before writes and before commit.
    """
    need(mode in ('install', 'rollback'), 'Unknown transaction mode')
    root = Path(root)
    verify_stock(root, m)
    before = map_state(root, m)
    new, old = m['new_map'], m['previous_project_map']
    target, active, disabled, partial, quarantine = (safe_path(root, p) for p in
        (new['device_path'], old['device_path'], old['disabled_path'], new['device_path'] + '.partial', new['device_path'] + '.rollback.partial'))
    undo, events = [], []

    def mark(event):
        events.append(event)
        if fault:
            fault(event)

    try:
        if mode == 'install':
            verify_file(source, new, 'Bundled image')
            if not before['new_present']:
                need(target.parent.is_dir(), 'Map directory is missing')
                with source.open('rb') as inp, partial.open('xb') as out:
                    inode = owned_inode(partial)
                    undo.append(lambda p=partial, i=inode: remove_owned(p, i) if p.exists() else None)
                    for chunk in iter(lambda: inp.read(4 * 1024 * 1024), b''):
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                mark('partial_written_and_synced')
                verify_file(partial, new, 'Copied image readback')
                mark('partial_readback_verified')
                rename_no_replace(partial, target)
                undo.append(lambda p=target, i=inode: remove_owned(p, i) if p.exists() else None)
                fsync_directory(target.parent)
                verify_file(target, new, 'Published image readback')
                mark('new_image_published')
            if before['old_active']:
                verify_file(active, old, 'Prior project map')
                rename_no_replace(active, disabled)
                undo.append(lambda: restore_verified(disabled, active, old) if disabled.exists() else None)
                fsync_directory(active.parent)
                mark('previous_map_disabled')
            verify_file(target, new, 'Final new map')
            verify_file(disabled, old, 'Retained disabled prior map')
            need(not active.exists(), 'Prior image remains active')
        else:
            if before['new_present']:
                verify_file(target, new, 'New map eligible for rollback')
                rename_no_replace(target, quarantine)
                undo.append(lambda: restore_verified(quarantine, target, new) if quarantine.exists() else None)
                fsync_directory(target.parent)
                mark('new_map_quarantined')
            if before['old_disabled']:
                verify_file(disabled, old, 'Prior map eligible for restore')
                rename_no_replace(disabled, active)
                undo.append(lambda: restore_verified(active, disabled, old) if active.exists() else None)
                fsync_directory(active.parent)
                mark('previous_map_restored')
            verify_file(active, old, 'Restored prior project map')
            need(not target.exists(), 'New map remains active after rollback')
        verify_stock(root, m)
        if final_check:
            final_check()
        mark('final_original_and_identity_checks_passed')
        if mode == 'rollback' and quarantine.exists():
            verify_file(quarantine, new, 'Own map pending rollback deletion')
            mark('before_own_new_map_removal')
            quarantine.unlink()
            # Deletion is the rollback commit point. Later observation/unmount
            # errors do not reverse the already restored verified old image.
            events.append('own_new_map_removed')
        undo.clear()
        fsync_directory(target.parent)
        return {'mode': mode, 'events': events, 'new_map_present': target.exists(),
                'previous_map_active': active.exists(), 'previous_map_disabled': disabled.exists(),
                'preserved_stock_hashes_verified_after_transaction': True}
    except BaseException as original:
        cleanup_errors = []
        for action in reversed(undo):
            try:
                action()
            except BaseException:
                cleanup_errors.append('One owned-file undo failed; recovery files retained')
        try:
            fsync_directory(target.parent)
        except OSError:
            cleanup_errors.append('Recovery directory sync failed')
        if cleanup_errors:
            raise Refusal('; '.join(cleanup_errors)) from original
        raise


@contextlib.contextmanager
def operation_lock():
    shared = Path('/root/garmin/evidence/usb-operation.lock')
    path = shared if shared.exists() else Path('/run/garmin-navigation-usb-operation.lock')
    with path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('Another USB operation holds the process lock') from None
        yield str(path)


def execute(bundle, mode):
    m, source, manifest_sha = load_manifest(bundle)
    result = {'started_at': timestamp(), 'mode': mode, 'state': 'waiting_for_usb',
              'manifest_sha256': manifest_sha, 'bundle_image_sha256_verified': True,
              'physical_device_present': False, 'device_files_written': False,
              'device_search_verified': False, 'device_routing_verified': False,
              'device_path': m['new_map']['device_path'], 'unmounted': True}
    with operation_lock() as lock_path:
        result['process_lock'] = lock_path
        disk = select_disk(disk_records(), m['device'])
        if disk is None:
            result['completed_at'] = timestamp()
            return result
        need(os.geteuid() == 0, 'Root privileges are needed to mount the exact USB disk')
        reconfirm_disk(disk, m['device'])
        result['physical_device_present'] = True
        mountpoint = Path(tempfile.mkdtemp(prefix='garmin-navigation-', dir='/run'))
        mounted, wrote = False, False
        try:
            run_command(['mount', '-t', 'vfat', '-o', 'ro,nosuid,nodev,noexec', disk['path'], str(mountpoint)])
            mounted = True
            result['unmounted'] = False
            xml, preflight = device_preflight(mountpoint, m, mode)
            result['preflight'] = preflight
            result['state'] = 'device_readonly_preflight_passed'
            if mode in ('install', 'rollback'):
                reconfirm_disk(disk, m['device'])
                run_command(['mount', '-o', 'remount,rw,nosuid,nodev,noexec', str(mountpoint)])
                wrote = True
                result['device_files_written'] = True

                def final_check():
                    need(safe_path(mountpoint, 'Garmin/GarminDevice.xml').read_bytes() == xml, 'Garmin XML changed during transaction')
                    reconfirm_disk(disk, m['device'])

                result['transaction'] = transaction(mountpoint, m, source, mode, final_check=final_check)
                result['state'] = 'installed_readback_verified' if mode == 'install' else 'rolled_back_readback_verified'
        except Exception as e:
            result.update(state='failed', error=type(e).__name__ + ': ' + str(e))
        finally:
            if mounted:
                try:
                    os.sync()
                    run_command(['umount', str(mountpoint)])
                    mounted = False
                    result['unmounted'] = True
                except Exception:
                    result.update(state='failed', unmounted=False, unmount_error='Unmount failed; keep USB attached and inspect recovery mount', recovery_mount=str(mountpoint))
            if not mounted:
                mountpoint.rmdir()
            result['completed_at'] = timestamp()
    return result


def write_evidence(result, bundle):
    local = Path('/root/garmin/evidence')
    evidence_dir = local if local.is_dir() and os.access(local, os.W_OK) else Path(bundle).resolve() / 'evidence'
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = 'navigation-bundle-' + dt.datetime.now().astimezone().strftime('%Y%m%dT%H%M%S%f%z') + '.json'
    path = evidence_dir / name
    with path.open('x') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return path


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent, help='Directory containing manifest.json and Map image')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--install', action='store_true', help='Install the new project IMG and disable its verified old version')
    modes.add_argument('--rollback', action='store_true', help='Remove only the exact new project IMG and restore its verified old version')
    args = parser.parse_args()
    mode = 'install' if args.install else 'rollback' if args.rollback else 'preflight'
    try:
        result = execute(args.bundle, mode)
    except Exception as error:
        result = {'started_at': timestamp(), 'completed_at': timestamp(), 'mode': mode, 'state': 'failed',
                  'error': type(error).__name__ + ': ' + str(error), 'physical_device_present': False,
                  'device_search_verified': False, 'device_routing_verified': False}
    evidence = write_evidence(result, args.bundle)
    print(json.dumps({**result, 'local_evidence': str(evidence)}, ensure_ascii=False))
    return 1 if result['state'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
