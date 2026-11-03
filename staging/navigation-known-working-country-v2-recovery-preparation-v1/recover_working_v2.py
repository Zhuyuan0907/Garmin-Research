#!/usr/bin/env python3
"""Portable two-step recovery preparation, deliberately not a deployable packet.

No installer imports, subprocess calls, payload file reads, mounts or device I/O.
The sequencing API consumes explicit runner replies for small host-only spies.
An executable packet needs a NEW reviewed phase-one activation binding; this
closed preparation manifest is immutable and remains preparation-only.
"""
import argparse
import json
from pathlib import Path
import sys

STOCK = {'bytes': 96739328, 'sha256': '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'}
WORKING_V2 = {'bytes': 128356352, 'sha256': '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'}
COHERENT_8K = {'bytes': 153346048, 'sha256': '9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'}
OLD_VIRTUAL_V3_SHA = '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
PHASE1_PREPARATION_MANIFEST_SHA = '8b5358655c79a9261af1ce69ade78c3a5c47d304a032f49452095768ab4e392a'
PHASE2_MANIFEST_SHA = '71258a290bce559b0f882282bf2ce3c6cd8e690d49fd5ef5756e454b3fde97f7'
TARGET = '.System/gmapprom1.img'

class Refusal(ValueError):
    pass

def need(ok, message):
    if not ok:
        raise Refusal(message)

def roles():
    return {'phase1_input': dict(COHERENT_8K), 'phase1_output': dict(STOCK),
            'phase2_input': dict(STOCK), 'phase2_output': dict(WORKING_V2)}

def validate_roles(value):
    need(type(value) is dict and value == roles(), 'Exact coherent8K -> stock -> working-v2 SHA roles required')

def commands(packet_root):
    """Pure pathname assembly; does not stat or open paths or payloads."""
    p = Path(packet_root)
    need(p.is_absolute(), 'Packet root must be absolute')
    return [
        [sys.executable, '-B', str(p / 'coherent8k' / 'install_native_house_supplement.py'),
         '--bundle', str(p / 'coherent8k'), '--rollback'],
        [sys.executable, '-B', str(p / 'working-v2' / 'install_native_house_supplement.py'),
         '--bundle', str(p / 'working-v2'), '--install'],
    ]

def no_duplicate_keys(pairs):
    d = {}
    for key, value in pairs:
        need(key not in d, 'Duplicate installer reply key')
        d[key] = value
    return d

def checked_reply(returncode, stdout, phase):
    """Validate the actual old/new installer result ABI, not exit code alone."""
    need(type(returncode) is int and returncode == 0, 'Installer did not exit successfully')
    need(type(stdout) is str and len(stdout.encode()) <= 8192, 'Bounded JSON installer reply required')
    try:
        r = json.loads(stdout, object_pairs_hook=no_duplicate_keys)
    except (TypeError, json.JSONDecodeError) as error:
        raise Refusal('Installer reply is not one JSON object') from error
    need(type(r) is dict, 'JSON object reply required')
    need(phase in (1, 2), 'Two fixed phases only')
    rollback = phase == 1
    mode = 'rollback' if rollback else 'install'
    desired = 'original' if rollback else 'candidate'
    desired_size = STOCK['bytes'] if rollback else WORKING_V2['bytes']
    manifest = PHASE1_PREPARATION_MANIFEST_SHA if rollback else PHASE2_MANIFEST_SHA
    changed_state = 'rolled_back_exact_original_verified' if rollback else 'installed_readback_verified'
    already_state = 'already_original_verified' if rollback else 'already_installed_verified'
    need(r.get('mode') == mode and r.get('manifest_sha256') == manifest, 'Wrong mode or manifest SHA role')
    need(r.get('state') in (changed_state, already_state), 'No verified final image state')
    need(r.get('physical_device_present') is True and r.get('unmounted') is True,
         'Physical operation and safe unmount must both be confirmed')
    need(r.get('bundle_candidate_and_rollback_verified') is True and r.get('device_path') == TARGET,
         'Exact AP bundle verification required')
    need(not r.get('recovery_required', False), 'Earlier operation requires recovery inspection')
    pre = r.get('preflight', {})
    need(type(pre) is dict and pre.get('preserved_file_hashes_verified') is True,
         'Preserved-file verification required')
    if r['state'] == changed_state:
        t = r.get('transaction', {})
        need(type(t) is dict and r.get('image_committed') is True and r.get('device_files_written') is True,
             'Expected image transaction missing')
        need(t.get('mode') == mode and t.get('changed') is True and t.get('committed') is True
             and t.get('image_state') == desired and t.get('destination_bytes') == desired_size
             and t.get('readback_verified') is True and t.get('preserved_file_hashes_verified') is True,
             'Final destination/readback/preservation role not verified')
    else:
        need(r.get('image_committed') is False and r.get('device_files_written') is False
             and pre.get('image_state') == desired and pre.get('image_bytes') == desired_size,
             'Already-at-target result has wrong image role')
    return r

def run_sequence(packet_root, runner, expected_roles):
    """Pure spy API only: no production runner is provided in this preparation.

    Synthetic success for the preparation SHA models the reply ABI. The real
    preparation-only phase-one installer cannot emit that success. A subsequent
    reviewed packet must replace this SHA with its exact activated source pin.
    """
    validate_roles(expected_roles)
    first, second = commands(packet_root)
    code, text = runner(first)
    r1 = checked_reply(code, text, 1)
    code, text = runner(second)
    r2 = checked_reply(code, text, 2)
    return {'phase1': r1['state'], 'phase2': r2['state'], 'working_v2_restored': True,
            'scope': 'runner reply validation; no hardware claim'}

def description(packet_root):
    return {'schema': 'garmin-working-v2-recovery-preparation/v1', 'commands': commands(packet_root),
            'roles': roles(), 'phase1_executable': False, 'installable': False,
            'dependency': 'NEW reviewed activated coherent8K manifest/source pin and complete payload packet',
            'actual_orchestration_executed': False, 'metadata_only': True}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, default=Path(__file__).absolute().parent)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    # The immutable phase-one manifest explicitly rejects all image/device work.
    # Do not edit it in place or treat a metadata plan as an executable packet.
    if args.execute:
        print(json.dumps({'state': 'refused', 'reason': 'Phase-one activation binding and complete recovery packet are not ready',
                          'installer_calls': 0, 'IMG_operations': 0, 'device_operations': 0}))
        return 2
    print(json.dumps(description(args.packet)))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
