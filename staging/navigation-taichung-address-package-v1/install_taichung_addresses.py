#!/usr/bin/env python3
"""Default read-only preflight; explicit controlled install or stock rollback.

Only the exact authorized nüvi AP image is replaced. The larger Taichung
candidate may upgrade stock or the previously verified nine-house candidate.
Rollback streams an exact smaller stock image using one compact layout recipe;
it creates no second complete backup. No simulated-device CLI mode exists.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile

sys.dont_write_bytecode = True
import device_support as support
import native_address_layout_restore_v1 as restore
from device_support import (
    Refusal, TransactionFailure, need, timestamp, valid_sha, integer, safe_path,
    open_regular, digest, verify_file, read_json, verify_xml, verify_preserved,
    owned_inode, remove_owned, fsync_directory, operation_lock, select_disk,
    disk_records, reconfirm_disk, run_command, check_mountinfo, interrupt,
)

SCHEMA = 'garmin-native-taichung-address/v1'
TARGET = '.System/gmapprom1.img'
CANDIDATE = 'candidate/gmapprom1.img'
PARTIAL = TARGET + '.taichung-address.partial'
ROLLBACK = 'restore-layout.json.gz'
ORIGINAL_BYTES = 96739328
CANDIDATE_BYTES = 100945920
ORIGINAL_SHA = '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
PREVIOUS_SHA = '8e759a435482e945cf6a936a7f2374fdaf5c42dc8ee70a00bbe36e7eb5436287'
CANDIDATE_SHA = '3c03d0a09e24165f27b7ed275535552bfb3ea10defe0f492de6f51dfdaf9b00b'
MANIFEST_BYTES = 4466
MANIFEST_SHA = '636b9cd08b28d367f3484df1c05e18e42c50afaff7b39141bbc005973a278f9a'
RECIPE_BYTES = 864491
RECIPE_SHA = '0f93498372d4f7f6962ae138920afc3c345787a39b347aef0b16c85a15f5ccb4'
MAX_RECIPE_JSON = 8 * 1024 * 1024
RESERVE_BYTES = support.RESERVE_BYTES
CHUNK = support.CHUNK
OLD_PARTIAL = support.PARTIAL
EXPECTED_PREDECESSORS = [
    {'state': 'original', 'bytes': ORIGINAL_BYTES, 'sha256': ORIGINAL_SHA},
    {'state': 'previous_verified_nine', 'bytes': ORIGINAL_BYTES, 'sha256': PREVIOUS_SHA},
]


def validate_recipe(recipe, source, target):
    """Bound allocations and every reconstruction field before any mutation."""
    need(isinstance(recipe, dict) and recipe.get('schema') == 'garmin-native-layout-restore/v1', 'Unsupported layout recipe')
    for key, expected in (
        ('original_bytes', target['original_bytes']), ('original_sha256', target['original_sha256']),
        ('candidate_bytes', target['bytes']), ('candidate_sha256', target['candidate_sha256']),
    ):
        need(recipe.get(key) == expected, 'Layout recipe image identity mismatch')
    prefix_hex = recipe.get('original_prefix_hex')
    n = recipe.get('original_metadata_bytes')
    need(integer(n) and 4608 <= n <= 1024 * 1024 and n % 4096 == 0, 'Original metadata bound')
    need(isinstance(prefix_hex, str) and len(prefix_hex) == n * 2, 'Original metadata byte length')
    try:
        prefix = bytes.fromhex(prefix_hex)
        original = restore.layout(io.BytesIO(prefix), recipe['original_bytes'])
        with open_regular(source) as stream:
            actual = restore.layout(stream, recipe['candidate_bytes'])
    except (ValueError, KeyError, TypeError, OSError):
        raise Refusal('Malformed layout recipe or bound image allocation') from None
    need(original['components'] == recipe.get('original_components') and actual['components'] == recipe.get('candidate_components'), 'Recipe allocation tables differ from actual bound layouts')
    need(original['prefix'] == prefix, 'Original metadata prefix parse mismatch')
    tails = recipe.get('original_tail_hex')
    unused = recipe.get('original_unused_blocks_hex')
    need(isinstance(tails, dict) and set(tails) == restore.NAMES and isinstance(unused, dict), 'Recipe tail/unused inventory')
    need(set(unused) == {str(b) for b in original['unused_blocks']}, 'Recipe unused block coverage')
    try:
        for name, component in original['components'].items():
            expected = (-component['size']) % 4096
            need(isinstance(tails[name], str) and len(bytes.fromhex(tails[name])) == expected, 'Original component tail length')
            if name != '00004171.MDR':
                need(component['size'] == actual['components'][name]['size'], 'Unchanged component logical size mismatch')
        for value in unused.values():
            need(isinstance(value, str) and len(bytes.fromhex(value)) == 4096, 'Original unused block byte length')
        ranges = recipe.get('MDR_ranges')
        need(isinstance(ranges, list) and 1 <= len(ranges) <= 128, 'MDR reconstruction range count')
        size = 0
        for row in ranges:
            need(isinstance(row, dict) and integer(row.get('length')) and row['length'] > 0, 'MDR range positive integer length')
            size += row['length']
            has_original, has_candidate = 'original_hex' in row, 'candidate_offset' in row
            need(has_original != has_candidate, 'MDR range must select exactly one reconstruction source')
            if has_original:
                need(isinstance(row['original_hex'], str) and len(bytes.fromhex(row['original_hex'])) == row['length'], 'MDR stored range byte length')
            else:
                offset = row['candidate_offset']
                need(integer(offset) and 0 <= offset <= offset + row['length'] <= actual['components']['00004171.MDR']['size'], 'MDR candidate range bounds')
        need(size == original['components']['00004171.MDR']['size'], 'MDR recipe does not cover exact original logical length')
    except (ValueError, TypeError, KeyError):
        raise Refusal('Malformed layout recipe data') from None
    try:
        with open_regular(source) as stream:
            reconstructed = restore.reconstructed_hash(stream, recipe)
    except (ValueError, KeyError, TypeError, OSError):
        raise Refusal('Layout recipe cannot reconstruct original image') from None
    need(reconstructed == target['original_sha256'], 'Layout recipe original full hash mismatch')
    return recipe


def load_manifest(bundle):
    bundle = Path(bundle).resolve()
    manifest_path = safe_path(bundle, 'manifest.json')
    # Pin the sealed whole manifest so preservation hashes/device fields cannot be substituted.
    verify_file(manifest_path, MANIFEST_BYTES, MANIFEST_SHA, 'Sealed Taichung manifest')
    m = read_json(manifest_path, 1024 * 1024)
    need(m.get('schema') == SCHEMA, 'Unsupported Taichung manifest schema')
    t, d, rb = m.get('target', {}), m.get('device', {}), m.get('rollback', {})
    need(t.get('device_path') == TARGET and t.get('bundle_path') == CANDIDATE and
         t.get('bytes') == CANDIDATE_BYTES and t.get('candidate_sha256') == CANDIDATE_SHA and
         t.get('original_bytes') == ORIGINAL_BYTES and t.get('original_sha256') == ORIGINAL_SHA and
         t.get('accepted_predecessors') == EXPECTED_PREDECESSORS, 'Unexpected Taichung target/predecessor identity')
    need(d.get('part_number') == '006-B1352-00' and str(d.get('software_version')) == '800' and
         d.get('disk_bytes') == support.DISK_BYTES and d.get('unit_id_sha256') == support.UNIT_ID_SHA,
         'Unexpected authorized model/software/unit/disk')
    usb = d.get('usb', {})
    need(usb.get('vendor') == '091e' and usb.get('product') == '2548' and usb.get('serial_sha256') == support.USB_SERIAL_SHA, 'Unexpected authorized USB identity')
    need(rb == {'schema': 'garmin-native-layout-restore/v1', 'bundle_path': ROLLBACK, 'bytes': RECIPE_BYTES, 'sha256': RECIPE_SHA}, 'Unexpected compact rollback identity')
    seen = {TARGET.lower(), PARTIAL.lower(), OLD_PARTIAL.lower()}
    preserved = m.get('preserved_stock_files')
    required = m.get('required_files')
    need(isinstance(preserved, list) and isinstance(required, list), 'Missing protection inventories')
    for row in preserved + required:
        need(isinstance(row, dict), 'Invalid protected inventory entry')
        name = row.get('device_path')
        safe_path(bundle, name)
        need(name.lower() not in seen, 'Protected/target/recovery path collision')
        need(integer(row.get('bytes')) and row['bytes'] >= 0 and valid_sha(row.get('sha256')), 'Invalid protected size/hash')
        seen.add(name.lower())
    need(support.REQUIRED_PRESERVED <= {r['device_path'].lower() for r in preserved}, 'Required stock protection missing')
    source = safe_path(bundle, CANDIDATE)
    verify_file(source, CANDIDATE_BYTES, CANDIDATE_SHA, 'Bundled Taichung candidate')
    recipe_path = safe_path(bundle, ROLLBACK)
    verify_file(recipe_path, RECIPE_BYTES, RECIPE_SHA, 'Compact layout recipe')
    try:
        with open_regular(recipe_path) as raw, gzip.GzipFile(fileobj=raw) as stream:
            data = stream.read(MAX_RECIPE_JSON + 1)
        need(len(data) <= MAX_RECIPE_JSON, 'Oversized recipe JSON')
        recipe = json.loads(data)
    except (ValueError, UnicodeError, OSError):
        raise Refusal('Malformed compact layout recipe') from None
    validate_recipe(recipe, source, t)
    return m, source, recipe, MANIFEST_SHA


def image_state(root, m):
    target = safe_path(root, TARGET)
    for partial in (PARTIAL, OLD_PARTIAL):
        need(not safe_path(root, partial).exists(), 'Recovery/partial image exists; refusing to overwrite it')
    need(target.is_file() and not target.is_symlink(), 'Original Address Point image missing or not regular')
    t = m['target']
    states = t['accepted_predecessors'] + [{'state': 'candidate', 'bytes': t['bytes'], 'sha256': t['candidate_sha256']}]
    actual_size = target.stat().st_size
    need(actual_size in {s['bytes'] for s in states}, 'Address Point size is not a recognized exact state')
    actual_sha = digest(target)
    matches = [s for s in states if actual_size == s['bytes'] and actual_sha == s['sha256']]
    need(len(matches) == 1, 'Address Point hash is not the exact stock, previously verified nine, or this larger candidate')
    return matches[0]


def device_preflight(root, m, mode):
    need(mode in ('preflight', 'install', 'rollback'), 'Unknown operation mode')
    xml = safe_path(root, 'Garmin/GarminDevice.xml').read_bytes()
    verify_xml(xml, m['device'])
    verify_preserved(root, m)
    state = image_state(root, m)
    desired = 'original' if mode == 'rollback' else 'candidate'
    desired_size = m['target']['original_bytes'] if mode == 'rollback' else m['target']['bytes']
    space = os.statvfs(root)
    free = space.f_bavail * space.f_frsize
    required = desired_size + RESERVE_BYTES if state['state'] != desired else 0
    need(free >= required, 'Insufficient space for full atomic destination temporary image plus reserve')
    return xml, {'image_state': state['state'], 'image_bytes': state['bytes'], 'image_sha256': state['sha256'],
                 'free_bytes': free, 'required_free_bytes': required, 'xml_unit_verified': True,
                 'preserved_file_hashes_verified': True}


def image_blocks(source, recipe, mode):
    with open_regular(source) as stream:
        if mode == 'rollback':
            yield from restore.restored_blocks(stream, recipe)
        else:
            for block in iter(lambda: stream.read(CHUNK), b''):
                yield block


def transaction(root, m, source, recipe, mode, final_check=None, fault=None):
    """New size-changing transaction; old USB/XML/protection helpers remain exact.

    A failed precommit cleans only the owned inode. Errors after replacement
    retain the committed image and report that fact. Rollback writes a smaller
    new file and atomically replaces the larger image, never truncating live AP.
    """
    need(mode in ('install', 'rollback'), 'Unknown transaction mode')
    xml, preflight = device_preflight(root, m, mode)
    target, partial = safe_path(root, TARGET), safe_path(root, PARTIAL)
    t = m['target']
    desired = 'candidate' if mode == 'install' else 'original'
    desired_size = t['bytes'] if mode == 'install' else t['original_bytes']
    desired_sha = t['candidate_sha256'] if mode == 'install' else t['original_sha256']
    events, owned, committed = [], None, False

    def mark(event):
        events.append(event)
        if fault:
            fault(event)

    def fence_xml():
        need(safe_path(root, 'Garmin/GarminDevice.xml').read_bytes() == xml, 'Garmin XML changed during transaction')
        if final_check:
            final_check()

    if preflight['image_state'] == desired:
        fence_xml()
        return {'mode': mode, 'changed': False, 'committed': False, 'image_state': desired,
                'events': ['already_at_requested_image'], 'readback_verified': True}
    try:
        verify_file(source, t['bytes'], t['candidate_sha256'], 'Bundled Taichung candidate')
        validate_recipe(recipe, source, t)
        before_inode = owned_inode(target)
        prior_stat = target.stat()
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, prior_stat.st_mode & 0o777)
        owned = os.fstat(fd).st_dev, os.fstat(fd).st_ino
        written = 0
        with os.fdopen(fd, 'wb') as out:
            for block in image_blocks(source, recipe, mode):
                need(isinstance(block, bytes) and 0 < len(block) <= CHUNK, 'Invalid streamed image chunk')
                written += len(block)
                need(written <= desired_size, 'Streamed image exceeds destination size')
                need(out.write(block) == len(block), 'Short temporary image write')
            need(written == desired_size, 'Streamed image ended before destination size')
            out.flush(); os.fsync(out.fileno())
            os.utime(out.fileno(), ns=(prior_stat.st_atime_ns, prior_stat.st_mtime_ns))
            os.fsync(out.fileno())
        mark('temporary_image_written_and_synced')
        verify_file(partial, desired_size, desired_sha, 'Temporary destination full readback')
        mark('temporary_image_readback_verified')
        verify_preserved(root, m)
        need(owned_inode(target) == before_inode and owned_inode(partial) == owned, 'Target/temporary inode changed before commit')
        verify_file(target, preflight['image_bytes'], preflight['image_sha256'], 'Exact starting image before commit')
        verify_file(partial, desired_size, desired_sha, 'Temporary image immediately before commit')
        fence_xml()
        mark('precommit_identity_and_hashes_verified')
        # Observer/identity hooks can run Python code; recheck both bytes and metadata afterwards.
        need(owned_inode(target) == before_inode and owned_inode(partial) == owned, 'Target/temporary inode changed at replacement')
        verify_file(target, preflight['image_bytes'], preflight['image_sha256'], 'Exact starting image at replacement')
        verify_file(partial, desired_size, desired_sha, 'Temporary image at replacement')
        verify_preserved(root, m)
        fence_xml()
        os.replace(partial, target)
        committed = True
        mark('atomic_target_replacement_committed')
        fsync_directory(target.parent)
        verify_file(target, desired_size, desired_sha, 'Committed destination full readback')
        verify_preserved(root, m)
        fence_xml()
        mark('final_readback_preservation_and_identity_verified')
        return {'mode': mode, 'changed': True, 'committed': True, 'image_state': desired,
                'previous_image_state': preflight['image_state'], 'previous_image_bytes': preflight['image_bytes'],
                'destination_bytes': desired_size, 'events': events, 'readback_verified': True,
                'preserved_file_hashes_verified': True, 'original_full_backup_created': False}
    except BaseException as error:
        cleanup_failed = False
        if not committed and owned is not None and not partial.exists():
            try:
                committed = owned_inode(target) == owned
            except (OSError, Refusal):
                pass
        if not committed and owned is not None:
            try:
                if partial.exists() or partial.is_symlink():
                    remove_owned(partial, owned); fsync_directory(partial.parent)
            except BaseException:
                cleanup_failed = True
        message = 'Atomic image commit completed; verification failed, inspect target before further action' if committed else 'Transaction stopped before image commit'
        if isinstance(error, Refusal):
            message += ': ' + str(error)
        if cleanup_failed:
            message += '; owned temporary cleanup failed, recovery file retained'
        raise TransactionFailure(message, committed, cleanup_failed) from error


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


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--install', action='store_true', help='Install this larger Taichung candidate from a pinned accepted AP state')
    modes.add_argument('--rollback', action='store_true', help='Restore exact smaller stock AP using one compact recipe')
    args = parser.parse_args()
    mode = 'install' if args.install else 'rollback' if args.rollback else 'preflight'
    signal.signal(signal.SIGTERM, interrupt); signal.signal(signal.SIGINT, interrupt)
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
