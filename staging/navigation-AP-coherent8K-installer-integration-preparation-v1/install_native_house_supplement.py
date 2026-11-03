#!/usr/bin/env python3
"""Default read-only preflight; explicit controlled install or stock rollback.

Only the exact authorized nüvi AP image is replaced. The country house supplement
candidate may upgrade the exact stock, nine-house, Taichung or country-v1 states.
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
import native_8k_stock_restore as restore
import native_coherent8k_rollback as coherent_restore
import coherent_header_overlay as overlay
from device_support import (
    Refusal, TransactionFailure, need, timestamp, valid_sha, integer, safe_path,
    open_regular, digest, verify_file, read_json, verify_xml, verify_preserved,
    owned_inode, remove_owned, fsync_directory, operation_lock, select_disk,
    disk_records, reconfirm_disk, run_command, check_mountinfo, interrupt,
)

SCHEMA = 'garmin-AP-coherent8K-disabled-test-control/preparation-v1'
TARGET = '.System/gmapprom1.img'
CANDIDATE = 'candidate/coherent8K-end-mirror.img.disabled'
PARTIAL = TARGET + '.native-house-supplement.partial'
ROLLBACK = 'restore-layout.json.gz'
ORIGINAL_BYTES = 96739328
CANDIDATE_BYTES = 153346048
ORIGINAL_SHA = '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
PREVIOUS_SHA = '8e759a435482e945cf6a936a7f2374fdaf5c42dc8ee70a00bbe36e7eb5436287'
CANDIDATE_SHA = '9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'
MANIFEST_BYTES = 9188
MANIFEST_SHA = '8b5358655c79a9261af1ce69ade78c3a5c47d304a032f49452095768ab4e392a'
RECIPE_BYTES = 879499
RECIPE_SHA = '6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7'
MAX_RECIPE_JSON = 8 * 1024 * 1024
RESERVE_BYTES = support.RESERVE_BYTES
CHUNK = support.CHUNK
OLD_PARTIAL = support.PARTIAL
TAICHUNG_PARTIAL = TARGET + '.taichung-address.partial'
EXPECTED_PREDECESSORS = [{'state': 'original', 'bytes': 96739328, 'sha256': '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'}, {'state': 'previous_verified_nine', 'bytes': 96739328, 'sha256': '8e759a435482e945cf6a936a7f2374fdaf5c42dc8ee70a00bbe36e7eb5436287'}, {'state': 'previous_Taichung_candidate', 'bytes': 100945920, 'sha256': '3c03d0a09e24165f27b7ed275535552bfb3ea10defe0f492de6f51dfdaf9b00b'}, {'state': 'previous_country_v1_candidate', 'bytes': 121823232, 'sha256': 'a2e3d43ae33307e6e81bd6f724314a5e03af82082cf453d0aa20cdc4c81b12fa'}, {'state': 'previous_country_v2_candidate', 'bytes': 128356352, 'sha256': '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'}]

RESTORE_BINDING = 'virtual-old-v3-stock-restore-binding.json'
BINDING_BYTES = 292144
BINDING_SHA = '0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89'
RESTORE_HELPER = 'native_8k_stock_restore.py'
HELPER_BYTES = 26503
HELPER_SHA = '43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
SUPPORT_BYTES = 29351
SUPPORT_SHA = '8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411'
EXPECTED_ROLLBACK = {'schema': 'garmin-AP-coherent8K-inverse-overlay-stock-restore/v1', 'stock_recipe': {'schema': 'garmin-native-layout-restore/v1', 'bundle_path': 'restore-layout.json.gz', 'bytes': 879499, 'sha256': '6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7'}, 'virtual_old_v3_binding': {'schema': 'garmin-native-8k-stock-layout-restore/v1', 'bundle_path': 'virtual-old-v3-stock-restore-binding.json', 'bytes': 292144, 'sha256': '0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89', 'virtual_candidate_sha256': '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'}, 'coherent_control_binding': {'schema': 'garmin-AP-coherent8K-inverse-overlay-stock-restore/v1', 'bundle_path': 'coherent-control-restore-binding.json', 'bytes': 4255, 'sha256': 'f475233c965eec527ea333ddfac46b281f493d1467a87645f455f8218261d481'}}
EXPECTED_HELPERS = {'device_support.py': {'bytes': 29351, 'sha256': '8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411'}, 'native_8k_stock_restore.py': {'bytes': 26503, 'sha256': '43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'}, 'coherent_header_overlay.py': {'bytes': 13336, 'sha256': '284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc'}, 'native_coherent8k_rollback.py': {'bytes': 5380, 'sha256': '662b4aa570ca67d3cb0a1520dc1228730326fee9f6aea7c6912422a72c7b24df'}}

CONTROL_BINDING = 'coherent-control-restore-binding.json'
CONTROL_BYTES = 4255
CONTROL_SHA = 'f475233c965eec527ea333ddfac46b281f493d1467a87645f455f8218261d481'
ACTUAL_STOCK_PROOF = 'validation/actual-coherent8K-stock-verification.json'
ACTUAL_STOCK_PROOF_BYTES = 6062
ACTUAL_STOCK_PROOF_SHA = 'e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e'


def validate_recipe(recipe, source, target):
    """Fresh coherent fullSHA/inverse view, then unchanged strict exactstock."""
    need(isinstance(recipe, dict) and set(recipe) == {'stock', 'binding', 'control'}, 'Unsupported coherent portable restore objects')
    need(target.get('bytes') == CANDIDATE_BYTES and target.get('candidate_sha256') == CANDIDATE_SHA and
         target.get('original_bytes') == ORIGINAL_BYTES and target.get('original_sha256') == ORIGINAL_SHA,
         'Coherent8K target image identity mismatch')
    try:
        coherent_restore.prepare_objects(recipe)
        with open_regular(source) as stream:
            result = coherent_restore.reconstructed_stock_hash(stream, recipe)
    except (ValueError, KeyError, TypeError, OSError, OverflowError):
        raise Refusal('Coherent8K inverse view cannot reconstruct the exact stock image') from None
    need(result['bytes'] == target['original_bytes'] and result['sha256'] == target['original_sha256'],
         'Coherent8K exact stock full hash mismatch')
    return recipe


def load_manifest(bundle):
    bundle = Path(bundle).resolve()
    manifest_path = safe_path(bundle, 'manifest.json')
    # Pin the sealed whole manifest so preservation hashes/device fields cannot be substituted.
    verify_file(manifest_path, MANIFEST_BYTES, MANIFEST_SHA, 'Sealed country house supplement manifest')
    m = read_json(manifest_path, 1024 * 1024)
    need(m.get('schema') == SCHEMA, 'Unsupported country house supplement manifest schema')
    t, d, rb = m.get('target', {}), m.get('device', {}), m.get('rollback', {})
    need(m.get('integration_preparation_only') is False and m.get('integration_status') == 'independently_reviewed_test_control', 'Preparation-only coherent control; candidate/device work is disabled')
    need(t.get('device_path') == TARGET and t.get('bundle_path') == CANDIDATE and
         t.get('bytes') == CANDIDATE_BYTES and t.get('candidate_sha256') == CANDIDATE_SHA and
         t.get('original_bytes') == ORIGINAL_BYTES and t.get('original_sha256') == ORIGINAL_SHA and
         t.get('accepted_predecessors') == EXPECTED_PREDECESSORS, 'Unexpected country house supplement target/predecessor identity')
    need(d.get('part_number') == '006-B1352-00' and str(d.get('software_version')) == '800' and
         d.get('disk_bytes') == support.DISK_BYTES and d.get('unit_id_sha256') == support.UNIT_ID_SHA,
         'Unexpected authorized model/software/unit/disk')
    usb = d.get('usb', {})
    need(usb.get('vendor') == '091e' and usb.get('product') == '2548' and usb.get('serial_sha256') == support.USB_SERIAL_SHA, 'Unexpected authorized USB identity')
    need(rb == EXPECTED_ROLLBACK, 'Unexpected compactstock recipe/actual8K binding identities')
    need(m.get('portable_helpers') == EXPECTED_HELPERS, 'Unexpected portable helper identities')
    need(Path(restore.__file__).resolve() == safe_path(bundle, RESTORE_HELPER).resolve() and Path(support.__file__).resolve() == safe_path(bundle, 'device_support.py').resolve(), 'Portable helper modules are outside this exact bundle')
    verify_file(safe_path(bundle, RESTORE_HELPER), HELPER_BYTES, HELPER_SHA, 'Pinned portable8K stock restore helper')
    verify_file(safe_path(bundle, 'device_support.py'), SUPPORT_BYTES, SUPPORT_SHA, 'Unchanged device protection helper')
    need(Path(coherent_restore.__file__).resolve() == safe_path(bundle, 'native_coherent8k_rollback.py').resolve()
         and Path(overlay.__file__).resolve() == safe_path(bundle, 'coherent_header_overlay.py').resolve(), 'Coherent adapters are outside this exact bundle')
    for name in ('native_coherent8k_rollback.py', 'coherent_header_overlay.py'):
        row = EXPECTED_HELPERS[name]
        verify_file(safe_path(bundle, name), row['bytes'], row['sha256'], 'Pinned portable coherent adapter')
    seen = {TARGET.lower(), PARTIAL.lower(), OLD_PARTIAL.lower(), TAICHUNG_PARTIAL.lower()}
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
    recipe_path = safe_path(bundle, ROLLBACK)
    binding_path = safe_path(bundle, RESTORE_BINDING)
    verify_file(recipe_path, RECIPE_BYTES, RECIPE_SHA, 'Pinned compactstock recipe')
    verify_file(binding_path, BINDING_BYTES, BINDING_SHA, 'Pinned actual8K stock restore binding')
    control_path = safe_path(bundle, CONTROL_BINDING)
    verify_file(control_path, CONTROL_BYTES, CONTROL_SHA, 'Pinned actual coherent/inverse overlay binding')
    proof_path = safe_path(bundle, ACTUAL_STOCK_PROOF)
    verify_file(proof_path, ACTUAL_STOCK_PROOF_BYTES, ACTUAL_STOCK_PROOF_SHA, 'Closed actual coherent STOCK proof')
    actual = read_json(proof_path, 65536)
    need(actual.get('all_assigned_checks_passed') is True and actual.get('candidate_full_sha256') == CANDIDATE_SHA
         and actual.get('exact_stock_reconstruction_sha256') == ORIGINAL_SHA
         and actual.get('exact_stock_bytes') == ORIGINAL_BYTES and actual.get('all_handles_closed') is True,
         'Actual coherent exact-STOCK validation prerequisite missing')
    try:
        stock = restore.load_stock_recipe(recipe_path)
        binding = restore.load_restore_binding(binding_path, BINDING_SHA)
        need(binding == restore.prepare_restore_binding(stock, binding['candidate_layout']), 'Actual8K binding does not match portable pinned stock recipe')
        recipe = {'stock': stock, 'binding': binding, 'control': read_json(control_path, 65536)}
        coherent_restore.prepare_objects(recipe)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError):
        raise Refusal('Malformed portable compactstock recipe or actual8K binding') from None
    source = safe_path(bundle, CANDIDATE)
    verify_file(source, CANDIDATE_BYTES, CANDIDATE_SHA, 'Bundled country house supplement candidate')
    validate_recipe(recipe, source, t)
    return m, source, recipe, MANIFEST_SHA


def image_state(root, m):
    target = safe_path(root, TARGET)
    for partial in (PARTIAL, OLD_PARTIAL, TAICHUNG_PARTIAL):
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
    need(mode in ('install', 'rollback'), 'Unknown coherent image-stream mode')
    with open_regular(source) as stream:
        if mode == 'rollback':
            yield from coherent_restore.restored_stock_blocks(stream, recipe)
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
        verify_file(source, t['bytes'], t['candidate_sha256'], 'Bundled country house supplement candidate')
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
    modes.add_argument('--install', action='store_true', help='Install this larger country house supplement candidate from a pinned accepted AP state')
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
