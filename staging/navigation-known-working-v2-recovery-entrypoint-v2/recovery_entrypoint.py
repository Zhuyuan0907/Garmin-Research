#!/usr/bin/env python3
"""Portable MAP recovery: certified coherent8K -> stock -> working country v2.

Default: describe the fixed plan only. --verify-packet reads only small pinned
source/manifest/sidecar files, never IMG/ZIP. --execute is reserved for a later
explicit user instruction and checks the complete small-file inventory before
starting either unchanged phase entrypoint. It does not import an installer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys

# Set only after the activated owner's immutable handoff has been received.
APPROVED_BINDING_SHA = None
BINDING_NAME = 'recovery-source-binding.json'
SMALL_CAP = 3 * 1024 * 1024
FILE_CAP = 1024 * 1024
REPLY_CAP = 8192
TARGET = '.System/gmapprom1.img'
STOCK = {'bytes': 96739328, 'sha256': '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'}
WORKING_V2 = {'bytes': 128356352, 'sha256': '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'}
COHERENT_8K = {'bytes': 153346048, 'sha256': '9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'}
VIRTUAL_V3 = '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
SEARCH_V2 = {'device_path': 'Map/Taiwan_OSM_SearchRepair_v2.img', 'bytes': 131829760,
             'sha256': '664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117'}
V2_MANIFEST_SHA = '71258a290bce559b0f882282bf2ce3c6cd8e690d49fd5ef5756e454b3fde97f7'
V2_ENTRYPOINT_SHA = '663a40fb404e44598574035b0ea5d651342720864a41973459ef87f5affe5f5d'
PREPARATION_MANIFEST_SHA = '8b5358655c79a9261af1ce69ade78c3a5c47d304a032f49452095768ab4e392a'
PREPARATION_ENTRYPOINT_SHA = '8bd1a7046b3b91ffd5cde58bb8ea84cc118dce3b6c414a532dcd505e25edeec4'

class Refusal(ValueError):
    pass

def need(condition, message):
    if not condition:
        raise Refusal(message)

def no_duplicate_keys(pairs):
    d = {}
    for key, value in pairs:
        need(key not in d, 'Duplicate JSON key')
        d[key] = value
    return d

def decode_json(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        raise Refusal(label + ': invalid bounded JSON') from error
    need(type(value) is dict, label + ': object required')
    return value

def relative_small_path(value):
    need(type(value) is str and '\0' not in value, 'Small path required')
    p = PurePosixPath(value)
    need(not p.is_absolute() and p.parts and all(x not in ('', '.', '..') for x in p.parts),
         'Small path must remain inside packet')
    need('.img' not in value.lower() and not value.lower().endswith('.zip'),
         'IMG and ZIP are not part of small-file verification')
    need(str(p) == value, 'Canonical small path required')
    return p

def normalized_packet(value):
    # No resolve(): do not follow a packet symlink silently.
    return Path(os.path.abspath(os.fspath(value)))

def stat_key(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
            s.st_mode, s.st_nlink)

def read_small(root, relative, expected_bytes=None, expected_sha=None, retain=False):
    p = relative_small_path(relative)
    root = normalized_packet(root)
    s = root.lstat()
    need(stat.S_ISDIR(s.st_mode), 'Packet root must be a real directory')
    current = root
    for part in p.parts[:-1]:
        current = current / part
        s = current.lstat()
        need(stat.S_ISDIR(s.st_mode), 'Packet subdirectory must be a real directory')
    current = root.joinpath(*p.parts)
    before = current.lstat()
    need(stat.S_ISREG(before.st_mode), 'Pinned small file must be regular')
    need(0 < before.st_size <= FILE_CAP, 'Small file cap')
    if expected_bytes is not None:
        need(type(expected_bytes) is int and before.st_size == expected_bytes, 'Pinned small size mismatch')
    fd = os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    h = hashlib.sha256()
    chunks = []
    read_bytes = 0
    try:
        opened = os.fstat(fd)
        need(stat_key(opened) == stat_key(before), 'Pinned file changed at open')
        while True:
            b = os.read(fd, min(65536, FILE_CAP + 1 - read_bytes))
            if not b:
                break
            read_bytes += len(b)
            need(read_bytes <= FILE_CAP, 'Small read exceeds cap')
            h.update(b)
            if retain:
                chunks.append(b)
        after_fd = os.fstat(fd)
        after_path = current.lstat()
        need(stat_key(before) == stat_key(after_fd) == stat_key(after_path), 'Pinned small inode/stat changed')
        need(read_bytes == before.st_size, 'Small file short read or EOF mismatch')
    finally:
        os.close(fd)
    digest = h.hexdigest()
    if expected_sha is not None:
        need(type(expected_sha) is str and digest == expected_sha, 'Pinned small SHA mismatch')
    return {'path': relative, 'bytes': read_bytes, 'sha256': digest, 'stable': True,
            'stat': list(stat_key(before))}, b''.join(chunks)

def get_json_path(value, path):
    for key in path:
        need(type(value) is dict and key in value, 'Missing owner source-binding field')
        value = value[key]
    return value

def load_binding(root):
    need(type(APPROVED_BINDING_SHA) is str and len(APPROVED_BINDING_SHA) == 64,
         'Activated owner binding has not been closed')
    row, raw = read_small(root, BINDING_NAME, expected_sha=APPROVED_BINDING_SHA, retain=True)
    binding = decode_json(raw, 'Recovery source binding')
    need(binding.get('schema') == 'garmin-working-v2-recovery-source-binding/v2', 'Recovery binding schema')
    need(binding.get('phase1_activated') is True, 'Preparation-only binding is refused')
    need(binding.get('roles') == {'phase1_input': COHERENT_8K, 'phase1_output': STOCK,
                                 'phase2_input': STOCK, 'phase2_output': WORKING_V2}, 'Wrong SHA/image roles')
    need(binding['phase2_manifest']['sha256'] == V2_MANIFEST_SHA, 'Original working-v2 manifest required')
    need(binding['phase2_entrypoint']['sha256'] == V2_ENTRYPOINT_SHA, 'Unchanged working-v2 entrypoint required')
    need(binding['phase1_manifest']['sha256'] != PREPARATION_MANIFEST_SHA
         and binding['phase1_entrypoint']['sha256'] != PREPARATION_ENTRYPOINT_SHA,
         'Closed preparation sources cannot be activated by this wrapper')
    return binding, row

def validate_manifest_roles(m1, m2, owner, binding):
    need(m1.get('integration_preparation_only', False) is False
         and m1.get('allowed_operation') == 'controlled_physical_test',
         'Phase-one manifest remains preparation-only')
    need(m1.get('schema') == binding['phase1_manifest_schema']
         and m2.get('schema') == binding['phase2_manifest_schema'], 'Exact phase manifest schemas required')
    need(m1.get('device') == m2.get('device') and type(m1.get('device')) is dict,
         'Phase devices differ')
    d = m1['device']
    need(d.get('part_number') == '006-B1352-00' and str(d.get('software_version')) == '800',
         'Exact Taiwan HWID/software required')
    need(m1.get('preserved_stock_files') == m2.get('preserved_stock_files')
         and type(m1.get('preserved_stock_files')) is list and m1['preserved_stock_files'],
         'Protected original map/file roles differ')
    need(m1.get('required_files') == m2.get('required_files') == [SEARCH_V2],
         'Exact already-installed Search v2 preservation required')
    for m, candidate in ((m1, COHERENT_8K), (m2, WORKING_V2)):
        t = m.get('target', {})
        need(t.get('device_path') == TARGET and t.get('bytes') == candidate['bytes']
             and t.get('candidate_sha256') == candidate['sha256']
             and t.get('original_bytes') == STOCK['bytes'] and t.get('original_sha256') == STOCK['sha256'],
             'Wrong AP source/destination role')
        accepted = t.get('accepted_predecessors', [])
        need(any(type(x) is dict and x.get('state') == 'original' and x.get('bytes') == STOCK['bytes']
                 and x.get('sha256') == STOCK['sha256'] for x in accepted), 'Exact stock predecessor missing')
    need(m1['target'].get('bundle_path') == 'candidate/coherent8K-end-mirror.img.disabled'
         and m2['target'].get('bundle_path') == 'candidate/gmapprom1.img', 'Portable AP bundle roles')
    need(owner.get('schema') == binding['phase1_source_binding_schema'], 'Activated source-binding schema')
    for key, spec_key in (('entrypoint', 'phase1_entrypoint'), ('manifest', 'phase1_manifest')):
        spec = binding[spec_key]
        expected = {'bundle_path': str(PurePosixPath(spec['path']).relative_to('coherent8k')),
                    'bytes': spec['bytes'], 'sha256': spec['sha256']}
        need(owner.get(key) == expected, 'Owner source-binding source/manifest link mismatch')
    declared = owner.get('bundle_input_inventory')
    need(type(declared) is dict and m1.get('bundle_input_inventory') == declared,
         'Owner/manifest input inventories differ')
    indexed = {x['path']: x for x in binding['small_inventory']}
    expected_small = {binding['phase1_manifest']['path'], binding['phase1_entrypoint']['path'],
                      binding['phase1_source_binding_path']}
    for name, spec in declared.items():
        if '.img' in name.lower():
            expected = {'bytes': COHERENT_8K['bytes'], 'sha256': COHERENT_8K['sha256'], 'role': 'candidate'} \
                if name == 'candidate/coherent8K-end-mirror.img.disabled' else \
                {'bytes': SEARCH_V2['bytes'], 'sha256': SEARCH_V2['sha256'], 'role': 'road'} \
                if name == 'roadmap/Taiwan_OSM_SearchRepair_v2.img' else None
            need(expected is not None and spec == expected, 'Wrong declared candidate/road payload role')
            continue
        path = 'coherent8k/' + name
        expected_small.add(path)
        row = indexed.get(path, {})
        need(spec.get('bytes') == row.get('bytes') and spec.get('sha256') == row.get('sha256'),
             'Source-binding sidecar is not its pinned small inventory row')
    need({x for x in indexed if x.startswith('coherent8k/')} == expected_small,
         'Activated complete sidecar closure differs')
    need(m1.get('entrypoint_source_binding') == {'bundle_path': 'entrypoint-source-binding.json',
         'schema': binding['phase1_source_binding_schema']}, 'Portable owner source-binding declaration')
    need(m1.get('rollback', {}).get('stock_recipe') == m2.get('rollback')
         and m1.get('rollback', {}).get('virtual_old_v3_binding', {}).get('virtual_candidate_sha256') == VIRTUAL_V3,
         'Stock recipe and virtual-old-v3 SHA roles differ')
    for link in binding['phase1_source_binding_links']:
        need(get_json_path(owner, link['json_path']) == link['expected'], 'Owner source-binding role link mismatch')

def verify_packet(root):
    root = normalized_packet(root)
    binding, initial = load_binding(root)
    inventory = binding['small_inventory']
    need(type(inventory) is list and inventory, 'Complete small inventory required')
    need(len(inventory) <= 48 and len({x['path'] for x in inventory}) == len(inventory), 'Unique bounded inventory')
    required = set(binding['required_small_paths'])
    need(len(required) == len(binding['required_small_paths'])
         and {x['path'] for x in inventory} == required, 'Complete source/manifest/sidecar inventory mismatch')
    indexed = {x['path']: x for x in inventory}
    for name in ('phase1_manifest', 'phase2_manifest', 'phase1_entrypoint', 'phase2_entrypoint'):
        spec = binding[name]
        need(spec == indexed.get(spec['path']), 'Entry source/manifest pin is not its inventory row')
    rows = [initial]
    content = {}
    retained = {binding['phase1_manifest']['path'], binding['phase2_manifest']['path'],
                binding['phase1_source_binding_path']}
    total = initial['bytes']
    need(total + sum(x['bytes'] for x in inventory) <= SMALL_CAP, 'Complete small read budget')
    for spec in inventory:
        need(spec['path'].startswith(('coherent8k/', 'working-v2/')), 'Same-bundle phase path required')
        row, raw = read_small(root, spec['path'], spec['bytes'], spec['sha256'], spec['path'] in retained)
        rows.append(row)
        total += row['bytes']
        if spec['path'] in retained:
            content[spec['path']] = decode_json(raw, 'Pinned phase metadata')
    m1 = content[binding['phase1_manifest']['path']]
    m2 = content[binding['phase2_manifest']['path']]
    owner = content[binding['phase1_source_binding_path']]
    validate_manifest_roles(m1, m2, owner, binding)
    # Fence all helpers/metadata after the last small read, before a runner call.
    for row in rows:
        p = relative_small_path(row['path'])
        need(list(stat_key(root.joinpath(*p.parts).lstat())) == row['stat'],
             'Packet file changed during complete verification')
    return {'schema': 'verified-working-v2-recovery-packet/v2', 'binding': binding,
            'root': str(root), 'small_inventory_verified': True, 'read_bytes': total,
            'small_read_receipts': rows, 'payload_IMG_stat_open_read': 0,
            'payload_validation': 'performed by pinned installer only after explicit execution'}

def commands(root):
    p = normalized_packet(root)
    return [[sys.executable, '-B', str(p / 'coherent8k/install_native_house_supplement.py'),
             '--bundle', str(p / 'coherent8k'), '--rollback'],
            [sys.executable, '-B', str(p / 'working-v2/install_native_house_supplement.py'),
             '--bundle', str(p / 'working-v2'), '--install']]

def standard_runner(argv):
    # This source is prepared but never called by this offline scope. A timeout
    # may leave recovery work pending; the caller halts, never advances/retries.
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, encoding='utf-8', errors='strict', check=False, timeout=7200)
    return done.returncode, done.stdout

def checked_reply(code, stdout, phase, binding):
    need(type(code) is int and code == 0, 'Installer exit was not successful')
    need(type(stdout) is str and len(stdout.encode()) <= REPLY_CAP, 'Bounded installer JSON required')
    r = decode_json(stdout, 'Installer reply')
    rollback = phase == 1
    mode = 'rollback' if rollback else 'install'
    desired = 'original' if rollback else 'candidate'
    desired_size = STOCK['bytes'] if rollback else WORKING_V2['bytes']
    expected_sha = binding['phase1_manifest' if rollback else 'phase2_manifest']['sha256']
    changed = 'rolled_back_exact_original_verified' if rollback else 'installed_readback_verified'
    already = 'already_original_verified' if rollback else 'already_installed_verified'
    need(r.get('mode') == mode and r.get('manifest_sha256') == expected_sha, 'Wrong result mode/manifest role')
    need(r.get('state') in (changed, already), 'No verified final image state')
    need(r.get('physical_device_present') is True and r.get('unmounted') is True
         and r.get('bundle_candidate_and_rollback_verified') is True and r.get('device_path') == TARGET,
         'Physical verification and safe unmount required')
    need(r.get('recovery_required', False) is False, 'Recovery inspection is required')
    pre = r.get('preflight', {})
    need(type(pre) is dict and pre.get('preserved_file_hashes_verified') is True
         and pre.get('xml_unit_verified') is True, 'Device identity/preservation not verified')
    if r['state'] == changed:
        t = r.get('transaction', {})
        need(type(t) is dict and r.get('image_committed') is True and r.get('device_files_written') is True,
             'Committed transaction required')
        need(t.get('mode') == mode and t.get('changed') is True and t.get('committed') is True
             and t.get('image_state') == desired and t.get('destination_bytes') == desired_size
             and t.get('readback_verified') is True and t.get('preserved_file_hashes_verified') is True,
             'Wrong final image/readback/preservation role')
    else:
        need(r.get('image_committed') is False and r.get('device_files_written') is False
             and pre.get('image_state') == desired and pre.get('image_bytes') == desired_size
             and pre.get('image_sha256') == (STOCK['sha256'] if rollback else WORKING_V2['sha256']),
             'Already-at-target role mismatch')
    return r['state']

def execute(root, runner=None):
    runner = standard_runner if runner is None else runner
    phase = 0
    completed = []
    runner_calls = 0
    try:
        verified = verify_packet(root)
        binding = verified['binding']
        argv = commands(root)
        for phase in (1, 2):
            if phase == 2:
                # No retry or fallback: changed/missing packet files stop here.
                renewed = verify_packet(root)
                need(renewed['binding'] == binding, 'Recovery binding changed between phases')
            runner_calls += 1
            code, stdout = runner(argv[phase - 1])
            state = checked_reply(code, stdout, phase, binding)
            completed.append({'phase': phase, 'state': state})
        return {'state': 'working_v2_recovery_verified', 'completed_phases': completed,
                'payload_roles': {'stock': STOCK, 'working_v2': WORKING_V2},
                'installer_calls': runner_calls, 'Garmin_UI_renderer_verified': False}
    except (Exception, KeyboardInterrupt) as error:
        # No stdout/stderr/device identity dump and no automatic third action.
        return {'state': 'halted', 'failed_phase': phase, 'completed_phases': completed,
                'installer_calls': runner_calls, 'phase2_executed': runner_calls == 2,
                'no_automatic_retry_or_fallback': True, 'inspect_before_retry': runner_calls > 0,
                'stop_reason': str(error) if isinstance(error, Refusal) else type(error).__name__}

def describe(root):
    return {'schema': 'working-v2-recovery-plan/v2', 'commands': commands(root),
            'default_is_plan_only': True, 'IMG_stat_open_read': 0,
            'activated_binding_closed': APPROVED_BINDING_SHA is not None,
            'actual_execution_requires_explicit_execute': True,
            'remaining_local_packet_validation': 'Root complete-payload packet and positive load-only validation',
            'device_acceptance_or_full_goal_complete': False}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, default=Path(__file__).absolute().parent)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--execute', action='store_true')
    modes.add_argument('--verify-packet', action='store_true')
    args = parser.parse_args(argv)
    if args.execute:
        result = execute(args.packet)
        code = 0 if result['state'] == 'working_v2_recovery_verified' else 1
    elif args.verify_packet:
        try:
            verified = verify_packet(args.packet)
            result = {'state': 'small_packet_inventory_verified', 'small_bytes_read': verified['read_bytes'],
                      'small_files': len(verified['small_read_receipts']), 'IMG_operations': 0,
                      'installer_calls': 0, 'payload_IMG_validation_performed': False}
            code = 0
        except Exception:
            result = {'state': 'refused', 'reason': 'Complete approved small packet verification failed',
                      'IMG_operations': 0, 'installer_calls': 0}
            code = 1
    else:
        result, code = describe(args.packet), 0
    print(json.dumps(result))
    return code

if __name__ == '__main__':
    raise SystemExit(main())
