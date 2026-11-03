#!/usr/bin/env python3
"""Read-only preflight, explicit install, or exact rollback of one AP candidate.

This nine-address candidate has not been verified on the navigation device.
Only .System/gmapprom1.img is replaced. No firmware, license, other map or
database is edited. The package's sparse physical file ranges reconstruct the
original image; no second full device backup is made. Linux and root privileges
are required for physical operations. There is no simulated-device CLI mode.
"""
import argparse
import contextlib
import datetime as dt
import errno
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET

SCHEMA = 'garmin-native-address-supplement/v1'
ROLLBACK_SCHEMA = 'garmin-native-address-rollback/v1'
TARGET = '.System/gmapprom1.img'
CANDIDATE = 'candidate/gmapprom1.img'
ROLLBACK = 'rollback.json.gz'
PARTIAL = TARGET + '.address-supplement.partial'
IMAGE_BYTES = 96739328
ORIGINAL_SHA = '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
CANDIDATE_SHA = '8e759a435482e945cf6a936a7f2374fdaf5c42dc8ee70a00bbe36e7eb5436287'
DISK_BYTES = 3879731200
UNIT_ID_SHA = '944f1d11f8e44ffb6c4d65c5b96d390719e5c97e70ce69733963827433c1abc9'
USB_SERIAL_SHA = '9dd8b2aabb944029a6caaf812aa0a23bafbf64e2f3a45e50857c16f3e678f127'
RESERVE_BYTES = 16 * 1024 * 1024
CHUNK = 4 * 1024 * 1024
MAX_ROLLBACK_JSON = 16 * 1024 * 1024
REQUIRED_PRESERVED = {
    '.system/gmapbmap.img', '.system/gmapprom.img', '.system/gmaptz.img',
    '.system/jcv/twcnstd.jcv', '.system/jcv/twcnstd.sum',
    '.system/sid/twppd.sid', '.system/g2s/d2878040c.g2s',
    '.system/sqlite/hwm/twnhwm.db', '.system/sqlite/prefecture/twnjai.db',
    '.system/gmapprom.gma', '.system/gmapprom.unl',
    '.system/677068547.gma', '.system/677726936.gma',
}


class Refusal(RuntimeError):
    """Deliberate rejection with a stable explanation containing no unit ID."""


class TransactionFailure(Refusal):
    def __init__(self, message, committed, cleanup_failed=False):
        super().__init__(message)
        self.committed = committed
        self.cleanup_failed = cleanup_failed


def need(ok, message):
    if not ok:
        raise Refusal(message)


def timestamp():
    return dt.datetime.now().astimezone().isoformat()


def valid_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def private_hash(value):
    return hashlib.sha256(str(value).strip().encode('utf-8')).hexdigest()


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def safe_path(root, relative):
    need(isinstance(relative, str) and '\\' not in relative, 'Invalid relative path')
    rel = PurePosixPath(relative)
    need(not rel.is_absolute() and rel.parts and all(p not in ('', '.', '..') for p in relative.split('/')), 'Invalid relative path')
    path = Path(root).resolve()
    for part in rel.parts:
        path /= part
        need(not path.is_symlink(), 'Symlink in package/device path')
    return path


def open_regular(path):
    """Open without following a final symlink, then verify the actual handle."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'Expected regular image/file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def digest(path):
    h = hashlib.sha256()
    with open_regular(path) as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def verify_file(path, size, sha, label):
    need(path.is_file() and not path.is_symlink(), label + ' is missing or not regular')
    with open_regular(path) as stream:
        need(os.fstat(stream.fileno()).st_size == size, label + ' size mismatch')
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(CHUNK), b''):
            h.update(block)
    need(h.hexdigest() == sha, label + ' hash mismatch')


def read_json(path, limit):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, 'Missing/oversized JSON file')
    with open_regular(path) as stream:
        data = stream.read(limit + 1)
    need(len(data) <= limit, 'Oversized JSON file')
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        raise Refusal('Malformed package JSON') from None
    need(isinstance(value, dict), 'Expected JSON object')
    return value


def validate_ranges(rollback, target, source):
    need(isinstance(rollback, dict) and rollback.get('schema') == ROLLBACK_SCHEMA, 'Unsupported rollback schema')
    need(rollback.get('device_path') == TARGET and rollback.get('bytes') == target['bytes'] and
         rollback.get('original_sha256') == target['original_sha256'] and
         rollback.get('candidate_sha256') == target['candidate_sha256'], 'Rollback image identity mismatch')
    rows = rollback.get('ranges')
    need(isinstance(rows, list) and 0 < len(rows) <= 100000, 'Invalid rollback range inventory')
    ranges, end = [], 0
    with open_regular(source) as stream:
        for row in rows:
            need(isinstance(row, dict), 'Invalid rollback range')
            offset, size, before = row.get('offset'), row.get('length'), row.get('before_hex')
            need(integer(offset) and integer(size) and offset >= end and size > 0 and offset + size <= target['bytes'], 'Overlapping/out-of-bounds rollback range')
            need(isinstance(before, str) and len(before) == size * 2 and re.fullmatch('[0-9a-f]+', before) is not None, 'Invalid rollback original bytes')
            need(valid_sha(row.get('after_sha256')), 'Invalid rollback candidate range hash')
            raw = bytes.fromhex(before)
            stream.seek(offset)
            after = stream.read(size)
            need(len(after) == size and hashlib.sha256(after).hexdigest() == row['after_sha256'], 'Rollback candidate range hash mismatch')
            need(raw != after, 'Rollback range has no change')
            ranges.append((offset, raw, row['after_sha256']))
            end = offset + size
    need(reconstructed_sha(source, ranges, target['bytes']) == target['original_sha256'], 'Rollback cannot reconstruct the exact original image')
    return ranges


def image_blocks(source, ranges, size):
    """Stream original from candidate and before ranges without a full backup."""
    with open_regular(source) as stream:
        need(os.fstat(stream.fileno()).st_size == size, 'Image changed while reconstructing')
        position = 0
        for offset, raw, after_sha in ranges:
            remaining = offset - position
            while remaining:
                block = stream.read(min(CHUNK, remaining))
                need(block, 'Unexpected end of image')
                yield block
                position += len(block)
                remaining -= len(block)
            after = stream.read(len(raw))
            need(len(after) == len(raw) and hashlib.sha256(after).hexdigest() == after_sha, 'Changed rollback candidate range')
            yield raw
            position += len(raw)
        while position < size:
            block = stream.read(min(CHUNK, size - position))
            need(block, 'Unexpected end of image')
            yield block
            position += len(block)
        need(not stream.read(1), 'Unexpected trailing image bytes')


def reconstructed_sha(source, ranges, size):
    h = hashlib.sha256()
    for block in image_blocks(source, ranges, size):
        h.update(block)
    return h.hexdigest()


def load_manifest(bundle):
    bundle = Path(bundle).resolve()
    manifest_path = safe_path(bundle, 'manifest.json')
    m = read_json(manifest_path, 1024 * 1024)
    need(m.get('schema') == SCHEMA, 'Unsupported candidate manifest schema')
    target, device, rb = m.get('target', {}), m.get('device', {}), m.get('rollback', {})
    need(target.get('device_path') == TARGET and target.get('bundle_path') == CANDIDATE,
         'Only the original Address Point image is an allowed target')
    need(target.get('bytes') == IMAGE_BYTES and target.get('original_sha256') == ORIGINAL_SHA and
         target.get('candidate_sha256') == CANDIDATE_SHA, 'Unexpected address candidate identity')
    need(device.get('part_number') == '006-B1352-00' and str(device.get('software_version')) == '800', 'Unsupported Garmin model/software')
    need(device.get('disk_bytes') == DISK_BYTES and device.get('unit_id_sha256') == UNIT_ID_SHA, 'Unexpected disk/unit identity')
    usb = device.get('usb', {})
    need(usb.get('vendor') == '091e' and usb.get('product') == '2548' and usb.get('serial_sha256') == USB_SERIAL_SHA, 'Unexpected authorized USB identity')
    need(rb.get('bundle_path') == ROLLBACK and rb.get('schema') == ROLLBACK_SCHEMA and valid_sha(rb.get('sha256')), 'Invalid rollback package identity')
    preserved = m.get('preserved_stock_files')
    need(isinstance(preserved, list), 'Preserved stock file inventory is missing')
    seen = set()
    for row in preserved:
        need(isinstance(row, dict), 'Invalid preserved file inventory')
        p = row.get('device_path')
        safe_path(bundle, p)
        need(p.lower() not in seen | {TARGET.lower(), PARTIAL.lower()}, 'Preserved/target path collision')
        need(integer(row.get('bytes')) and row['bytes'] >= 0 and valid_sha(row.get('sha256')), 'Invalid preserved file identity')
        seen.add(p.lower())
    need(REQUIRED_PRESERVED <= seen, 'Required original maps/licenses/databases are absent from the preservation inventory')
    required = m.get('required_files', [])
    need(isinstance(required, list), 'Invalid required file inventory')
    for row in required:
        need(isinstance(row, dict), 'Invalid required file inventory')
        p = row.get('device_path')
        safe_path(bundle, p)
        need(p.lower() not in seen | {TARGET.lower(), PARTIAL.lower()}, 'Required/preserved/target path collision')
        need(integer(row.get('bytes')) and row['bytes'] >= 0 and valid_sha(row.get('sha256')), 'Invalid required file identity')
        seen.add(p.lower())
    source, rollback_path = safe_path(bundle, CANDIDATE), safe_path(bundle, ROLLBACK)
    verify_file(source, IMAGE_BYTES, CANDIDATE_SHA, 'Bundled address candidate')
    with open_regular(source) as stream:
        header = stream.read(512)
    need(header[0] == 0 and header[16:23] == b'DSKIMG\0' and header[65:72] == b'GARMIN\0', 'Unexpected Garmin IMG header')
    need(rollback_path.is_file() and not rollback_path.is_symlink() and rollback_path.stat().st_size <= MAX_ROLLBACK_JSON, 'Missing/oversized rollback archive')
    need(digest(rollback_path) == rb['sha256'], 'Rollback archive hash mismatch')
    try:
        with open_regular(rollback_path) as compressed, gzip.GzipFile(fileobj=compressed) as stream:
            raw = stream.read(MAX_ROLLBACK_JSON + 1)
        need(len(raw) <= MAX_ROLLBACK_JSON, 'Oversized decompressed rollback JSON')
        rollback = json.loads(raw)
    except (OSError, ValueError, UnicodeError):
        raise Refusal('Malformed rollback archive') from None
    ranges = validate_ranges(rollback, target, source)
    return m, source, ranges, digest(manifest_path)


def verify_xml(data, device):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise Refusal('Garmin XML is malformed') from None
    need(root.tag.startswith('{'), 'Garmin XML namespace is missing')
    ns = {'g': root.tag.split('}')[0][1:]}
    need(root.findtext('g:Model/g:PartNumber', namespaces=ns) == device['part_number'], 'Garmin XML HWID/model mismatch')
    need(root.findtext('g:Model/g:SoftwareVersion', namespaces=ns) == str(device['software_version']), 'Garmin XML software mismatch')
    unit = root.findtext('g:Id', namespaces=ns)
    need(unit is not None and private_hash(unit) == device['unit_id_sha256'], 'Garmin XML unit identity mismatch')


def verify_preserved(root, m):
    for row in m['preserved_stock_files'] + m.get('required_files', []):
        verify_file(safe_path(root, row['device_path']), row['bytes'], row['sha256'], 'Preserved original file')


def image_state(root, m):
    target = safe_path(root, TARGET)
    need(not safe_path(root, PARTIAL).exists(), 'Recovery/partial image exists; refusing to overwrite it')
    need(target.is_file() and not target.is_symlink(), 'Original Address Point image is missing')
    need(target.stat().st_size == m['target']['bytes'], 'Address Point image size mismatch')
    sha = digest(target)
    if sha == m['target']['original_sha256']:
        return 'original'
    if sha == m['target']['candidate_sha256']:
        return 'candidate'
    raise Refusal('Address Point image hash is neither the exact original nor this candidate; external changes refused')


def device_preflight(root, m, mode):
    need(mode in ('preflight', 'install', 'rollback'), 'Unknown operation mode')
    xml = safe_path(root, 'Garmin/GarminDevice.xml').read_bytes()
    verify_xml(xml, m['device'])
    verify_preserved(root, m)
    state = image_state(root, m)
    desired = 'original' if mode == 'rollback' else 'candidate'
    space = os.statvfs(root)
    free = space.f_bavail * space.f_frsize
    required = m['target']['bytes'] + RESERVE_BYTES if state != desired else 0
    need(free >= required, 'Insufficient free space for a full atomic temporary image plus reserve')
    return xml, {'image_state': state, 'free_bytes': free, 'required_free_bytes': required,
                 'xml_unit_verified': True, 'preserved_file_hashes_verified': True}


def owned_inode(path):
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode), 'Owned temporary image is no longer regular')
    return st.st_dev, st.st_ino


def remove_owned(path, identity):
    need(not path.is_symlink() and owned_inode(path) == identity, 'Temporary image changed; refusing cleanup of another file')
    path.unlink()


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.fsync(fd)
        except OSError as e:
            if e.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
            os.sync()
    finally:
        os.close(fd)


def transaction(root, m, source, ranges, mode, final_check=None, fault=None):
    """The same file transaction is used by physical operations and temp tests.

    Before commit, only the process's own temporary inode can be deleted. After
    atomic replacement, errors leave the target in place and explicitly report
    the commit. Recovery never overwrites an unrecognized target. No original
    full image is copied or renamed into a separate backup.
    """
    need(mode in ('install', 'rollback'), 'Unknown transaction mode')
    _, preflight = device_preflight(root, m, mode)
    target, partial = safe_path(root, TARGET), safe_path(root, PARTIAL)
    desired = 'candidate' if mode == 'install' else 'original'
    target_spec = m['target']
    desired_sha = target_spec['candidate_sha256'] if mode == 'install' else target_spec['original_sha256']
    events, owned, committed = [], None, False

    def mark(event):
        events.append(event)
        if fault:
            fault(event)

    if preflight['image_state'] == desired:
        if final_check:
            final_check()
        return {'mode': mode, 'changed': False, 'committed': False, 'image_state': desired,
                'events': ['already_at_requested_image'], 'readback_verified': True}
    try:
        verify_file(source, target_spec['bytes'], target_spec['candidate_sha256'], 'Bundled address candidate')
        need(reconstructed_sha(source, ranges, target_spec['bytes']) == target_spec['original_sha256'], 'Sparse rollback original hash mismatch')
        before_inode = owned_inode(target)
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, target.stat().st_mode & 0o777)
        owned = os.fstat(fd).st_dev, os.fstat(fd).st_ino
        with os.fdopen(fd, 'wb') as out:
            # Preserve the original timestamp; contents are the sole mutation.
            previous = target.stat()
            for block in image_blocks(source, [] if mode == 'install' else ranges, target_spec['bytes']):
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
            os.utime(out.fileno(), ns=(previous.st_atime_ns, previous.st_mtime_ns))
            os.fsync(out.fileno())
        mark('temporary_image_written_and_synced')
        verify_file(partial, target_spec['bytes'], desired_sha, 'Temporary image full readback')
        mark('temporary_image_readback_verified')
        verify_preserved(root, m)
        need(owned_inode(target) == before_inode, 'Target image inode changed before commit')
        verify_file(target, target_spec['bytes'], target_spec['original_sha256'] if mode == 'install' else target_spec['candidate_sha256'], 'Target immediately before commit')
        need(owned_inode(partial) == owned, 'Temporary image inode changed before commit')
        verify_file(partial, target_spec['bytes'], desired_sha, 'Temporary image immediately before commit')
        if final_check:
            final_check()
        mark('precommit_identity_and_hashes_verified')
        # Also fence file changes injected while the precommit observer ran.
        need(owned_inode(target) == before_inode, 'Target image changed before atomic replacement')
        verify_file(target, target_spec['bytes'], target_spec['original_sha256'] if mode == 'install' else target_spec['candidate_sha256'], 'Target at atomic replacement')
        need(owned_inode(partial) == owned, 'Temporary image changed before atomic replacement')
        os.replace(partial, target)
        committed = True
        mark('atomic_target_replacement_committed')
        fsync_directory(target.parent)
        verify_file(target, target_spec['bytes'], desired_sha, 'Committed image full readback')
        verify_preserved(root, m)
        if final_check:
            final_check()
        mark('final_readback_preservation_and_identity_verified')
        return {'mode': mode, 'changed': True, 'committed': True, 'image_state': desired,
                'events': events, 'readback_verified': True, 'preserved_file_hashes_verified': True,
                'original_full_backup_created': False}
    except BaseException as error:
        cleanup_failed = False
        # A signal may arrive after rename's kernel commit but before Python
        # records it. Recover that fact from the newly-created inode.
        if not committed and owned is not None and not partial.exists():
            try:
                committed = owned_inode(target) == owned
            except (OSError, Refusal):
                pass
        if not committed and owned is not None:
            try:
                if partial.exists() or partial.is_symlink():
                    remove_owned(partial, owned)
                    fsync_directory(partial.parent)
            except BaseException:
                cleanup_failed = True
        message = 'Atomic image commit completed; verification failed, inspect target before further action' if committed else 'Transaction stopped before image commit'
        if isinstance(error, Refusal):
            message += ': ' + str(error)
        if cleanup_failed:
            message += '; owned temporary cleanup failed, recovery file retained'
        raise TransactionFailure(message, committed, cleanup_failed) from error


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
    parent = next((p for p in (node, *node.parents) if (p / 'idVendor').is_file() and (p / 'idProduct').is_file()), None)
    need(parent is not None, 'USB identity is incomplete')
    serial_path = parent / 'serial'
    serial = serial_path.read_text().strip() if serial_path.is_file() else ''
    interfaces = list(parent.glob(parent.name + ':*/bInterfaceClass')) + list(parent.parent.glob(parent.name + ':*/bInterfaceClass'))
    return {'vendor': (parent / 'idVendor').read_text().strip().lower(),
            'product': (parent / 'idProduct').read_text().strip().lower(),
            'serial_sha256': private_hash(serial) if serial else None,
            'disk_bytes': int((node / 'size').read_text().strip()) * 512,
            'mass_storage_interface': any(p.read_text().strip().lower() == '08' for p in interfaces),
            'sysfs_path': str(node), 'major_minor': (node / 'dev').read_text().strip()}


def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    need(result.returncode == 0, 'Required system command failed: ' + command[0])
    return result.stdout


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
        name = Path(disk.get('kname') or disk.get('name', '')).name
        if name.startswith(('loop', 'ram', 'zram', 'dm-')):
            continue
        usb = identity_reader(name)
        if usb['vendor'] != expected['usb']['vendor'] or usb['product'] != expected['usb']['product']:
            continue
        need(usb.get('mass_storage_interface') is True, 'Garmin USB device has no mass-storage interface')
        need(usb['serial_sha256'] == expected['usb']['serial_sha256'], 'A Garmin USB disk has a different serial identity')
        if int(disk.get('size', -1)) == 0 and usb['disk_bytes'] == 0:
            need(not disk.get('children') and not mountpoints(disk), 'Unexpected mounted/partitioned empty Garmin SD LUN')
            mount_checker(usb['major_minor'])
            continue
        need(int(disk.get('size', -1)) == expected['disk_bytes'] == usb['disk_bytes'], 'Garmin USB disk size mismatch')
        need(not disk.get('children'), 'Unexpected partitioned/multi-child disk layout')
        need(not mountpoints(disk), 'Target disk is already mounted')
        mount_checker(usb['major_minor'])
        path = disk.get('path') or disk.get('name')
        need(path == '/dev/' + name, 'Unexpected block-device path')
        need(disk.get('maj:min') == usb['major_minor'], 'Block major/minor changed')
        matches.append({'name': name, 'path': path, 'identity': usb})
    need(len(matches) <= 1, 'Multiple matching Garmin disks; ambiguous target refused')
    return matches[0] if matches else None


def reconfirm_disk(disk, expected):
    info = usb_sysfs(disk['name'])
    need(info == disk['identity'] and info['disk_bytes'] == expected['disk_bytes'], 'USB identity changed during operation')
    st = os.stat(disk['path'])
    need(stat.S_ISBLK(st.st_mode), 'Target is no longer a block device')
    need(str(os.major(st.st_rdev)) + ':' + str(os.minor(st.st_rdev)) == info['major_minor'], 'Block node identity changed')


@contextlib.contextmanager
def operation_lock():
    shared = Path('/root/garmin/evidence/usb-operation.lock')
    path = shared if shared.exists() else Path('/run/garmin-navigation-usb-operation.lock')
    with path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('Another USB operation holds the process lock') from None
        yield


def execute(bundle, mode):
    m, source, ranges, manifest_sha = load_manifest(bundle)
    result = {'started_at': timestamp(), 'mode': mode, 'state': 'waiting_for_usb',
              'manifest_sha256': manifest_sha, 'bundle_candidate_and_rollback_verified': True,
              'physical_device_present': False, 'device_files_written': False, 'image_committed': False,
              'device_search_verified': False, 'device_routing_verified': False,
              'candidate_device_verified': False, 'device_path': TARGET, 'unmounted': True}
    with operation_lock():
        disk = select_disk(disk_records(), m['device'])
        if disk is None:
            result['completed_at'] = timestamp()
            return result
        need(os.geteuid() == 0, 'Root privileges are required for exact physical USB operations')
        reconfirm_disk(disk, m['device'])
        result['physical_device_present'] = True
        mountpoint = Path(tempfile.mkdtemp(prefix='garmin-address-supplement-', dir='/run'))
        mounted = False
        try:
            run_command(['mount', '-t', 'vfat', '-o', 'ro,nosuid,nodev,noexec', disk['path'], str(mountpoint)])
            mounted, result['unmounted'] = True, False
            xml, preflight = device_preflight(mountpoint, m, mode)
            result['preflight'] = preflight
            result['state'] = 'device_readonly_preflight_passed'
            desired = 'original' if mode == 'rollback' else 'candidate'
            if mode in ('install', 'rollback') and preflight['image_state'] == desired:
                result['state'] = 'already_installed_verified' if mode == 'install' else 'already_original_verified'
            elif mode in ('install', 'rollback'):
                reconfirm_disk(disk, m['device'])
                run_command(['mount', '-o', 'remount,rw,nosuid,nodev,noexec', str(mountpoint)])

                def final_check():
                    need(safe_path(mountpoint, 'Garmin/GarminDevice.xml').read_bytes() == xml, 'Garmin XML changed during operation')
                    reconfirm_disk(disk, m['device'])

                result['device_files_written'] = True
                result['transaction'] = transaction(mountpoint, m, source, ranges, mode, final_check=final_check)
                result['image_committed'] = result['transaction']['committed']
                result['state'] = 'installed_readback_verified' if mode == 'install' else 'rolled_back_exact_original_verified'
        except BaseException as error:
            result.update(state='failed', error=str(error) if isinstance(error, Refusal) else type(error).__name__ + ': operation failed')
            if isinstance(error, TransactionFailure):
                result['image_committed'] = error.committed
                result['recovery_required'] = error.committed or error.cleanup_failed
        finally:
            if mounted:
                try:
                    os.sync()
                    run_command(['umount', str(mountpoint)])
                    check_mountinfo(disk['identity']['major_minor'])
                    mounted, result['unmounted'] = False, True
                except BaseException:
                    result.update(state='failed', unmounted=False, unmount_error='Unmount not confirmed; keep USB attached', recovery_mount=str(mountpoint))
            if not mounted:
                mountpoint.rmdir()
            result['completed_at'] = timestamp()
    return result


def interrupt(signum, frame):
    raise InterruptedError('Interrupted')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent, help='Directory containing manifest.json, candidate/ and rollback.json.gz')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--install', action='store_true', help='Atomically replace only the exact original Address Point IMG')
    modes.add_argument('--rollback', action='store_true', help='Restore the exact original hash using the packaged sparse ranges')
    args = parser.parse_args()
    mode = 'install' if args.install else 'rollback' if args.rollback else 'preflight'
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        result = execute(args.bundle, mode)
    except BaseException as error:
        result = {'started_at': timestamp(), 'completed_at': timestamp(), 'mode': mode, 'state': 'failed',
                  'error': str(error) if isinstance(error, Refusal) else type(error).__name__ + ': operation failed',
                  'physical_device_present': False, 'device_files_written': False,
                  'device_search_verified': False, 'device_routing_verified': False, 'candidate_device_verified': False}
    print(json.dumps(result, ensure_ascii=False))
    return 1 if result['state'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
