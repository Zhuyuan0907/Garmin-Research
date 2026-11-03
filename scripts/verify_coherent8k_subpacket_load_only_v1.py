"""Positive complete same-bundle load and full stock EOF, with no device path."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-coherent8K-test-recovery-packet-v1'
BUNDLE = OUT / 'packet/coherent8k'
PROOF_SHA = 'ace3b55869d0b5c45ec397818878dfd9c0fe2e3892d0af16239c6ad86f84e0d5'
ENTRY_SHA = '10167906752df5e22985b79cae4af33600de55ea8823c869c4d0abf26f98973c'
MANIFEST_SHA = 'a491e77131a1c3a468865f98cc204984acf4fb81198fdb89049e5338f57a9e52'


def need(value, message):
    if not value:
        raise ValueError(message)


def snap(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink, s.st_mode]


def save(name, value):
    b = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    need(len(b) <= 65536, 'Small load-only result bound')
    p = OUT / name
    with p.open('xb') as f:
        f.write(b); f.flush(); os.fsync(f.fileno())
    p.chmod(0o444)
    return {'path': str(p.relative_to(ROOT)), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def memory():
    fields = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith(('VmRSS:', 'VmHWM:')):
            fields[line.split(':')[0]] = int(line.split()[1])
    need(max(fields.values()) <= 98304, 'Current process memory budget')
    return fields


def main():
    need(not (OUT / 'coherent8K-load-only-proof.json').exists(), 'Single positive load result')
    raw = (OUT / 'coherent8K-staging-proof.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == PROOF_SHA, 'Fixed actual staging proof')
    staged = json.loads(raw)
    need(staged['all_assigned_staging_checks_passed'] and len(staged['members']) == 15, 'All fifteen members staged')
    initial = {}; small_bytes = 0
    for row in staged['members']:
        p = BUNDLE / row['bundle_path']; s = p.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_size == row['bytes']
             and stat.S_IMODE(s.st_mode) == 0o444, 'Exact readonly regular bundle member')
        initial[row['bundle_path']] = snap(s)
        if row['role'] not in ('candidate', 'road'):
            b = p.read_bytes(); small_bytes += len(b)
            need(hashlib.sha256(b).hexdigest() == row['sha256']
                 and snap(p.lstat()) == snap(s), 'Fresh exact metadata and source pin')
    need(small_bytes <= 2 * 1024 * 1024, 'Bounded initial source/sidecar verification')
    source = BUNDLE / 'install_native_house_supplement.py'
    need(hashlib.sha256(source.read_bytes()).hexdigest() == ENTRY_SHA, 'External exact source binding')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(BUNDLE))
    old_cwd = Path.cwd()
    loading = True
    capture = {'stock_blocks_yielded': 0, 'stock_bytes_yielded': 0,
               'portable_complete_stock_return': None, 'forbidden_operation_attempts': 0}
    forbidden_functions = {'main', 'execute', 'device_preflight', 'image_state', 'transaction',
                           'disk_records', 'reconfirm_disk', 'select_disk', 'operation_lock', 'run_command'}

    def audit(event, args):
        if not loading:
            return
        bad = event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'socket.connect', 'socket.bind')
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            path = os.fsdecode(args[0])
            bad = bad or path.startswith(('/dev/', '/sys/'))
            bad = bad or (path.startswith('/proc/') and path != '/proc/self/status')
            if len(args) > 2 and isinstance(args[2], int):
                bad = bad or bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if bad:
            capture['forbidden_operation_attempts'] += 1
            raise RuntimeError('Load-only verification forbids writes, subprocess and device discovery')

    def observer(frame, event, value):
        filename = frame.f_code.co_filename
        if not filename.startswith(str(BUNDLE) + '/'):
            return
        name = frame.f_code.co_name
        if event == 'call' and name in forbidden_functions:
            capture['forbidden_operation_attempts'] += 1
            raise RuntimeError('Device execution function must not run during load validation')
        if event == 'return' and filename.endswith('/native_8k_stock_restore.py') \
                and name == 'restored_stock_blocks' and type(value) is bytes:
            need(len(value) == 4096, 'Actual original physical block length')
            capture['stock_blocks_yielded'] += 1
            capture['stock_bytes_yielded'] += len(value)
            if capture['stock_blocks_yielded'] % 2048 == 0:
                memory()
        if event == 'return' and filename.endswith('/native_coherent8k_rollback.py') \
                and name == 'reconstructed_stock_hash' and type(value) is dict:
            need(capture['portable_complete_stock_return'] is None, 'Only one complete portable stock validation')
            capture['portable_complete_stock_return'] = value

    sys.addaudithook(audit)
    try:
        os.chdir('/tmp')
        need(sys.getprofile() is None, 'No preexisting observer')
        sys.setprofile(observer)
        spec = importlib.util.spec_from_file_location('_root_activated_coherent8K_load_only', source)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        m, candidate, recipe, manifest_sha = installer.load_manifest(BUNDLE)
        need(manifest_sha == MANIFEST_SHA and candidate == BUNDLE / installer.CANDIDATE,
             'Actual complete same-bundle positive load')
        result = capture['portable_complete_stock_return']
        need(type(result) is dict and result['bytes'] == 96739328
             and result['sha256'] == '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2', 'Actual complete portable stock return')
        need(capture['stock_blocks_yielded'] == 23618 and capture['stock_bytes_yielded'] == 96739328,
             'Observed generator consumed through exact complete block stream')
        inverse = result['inverse_view_receipt']
        need(inverse['actual_corrected_full_sha256'] == installer.CANDIDATE_SHA
             and inverse['computed_inverse_full_sha256'] == '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
             and inverse['stock_hash_verified'], 'Fresh actual, inverse and complete stock roles verified')
    except BaseException as exc:
        loading = False; sys.setprofile(None); os.chdir(old_cwd)
        save('coherent8K-load-only-failure.json', {'error_type': type(exc).__name__, 'error': str(exc),
                                                'capture': capture, 'no_automatic_retry': True, 'device_IO': False})
        raise
    finally:
        loading = False; sys.setprofile(None); os.chdir(old_cwd)
    need(capture['forbidden_operation_attempts'] == 0, 'No device path or mutation attempted')
    for name, before in initial.items():
        need(snap((BUNDLE / name).lstat()) == before, 'Every source stable through full positive load')
    proof = {
        'schema': 'actual-complete-coherent8K-subpacket-load-only/v1', 'all_assigned_checks_passed': True,
        'completed_utc': datetime.now(timezone.utc).isoformat(), 'external_entrypoint_SHA256': ENTRY_SHA,
        'manifest_SHA256': manifest_sha, 'complete_15_member_same_directory_load_passed': True,
        'fresh_inventory_all12inputs_SHA_verified_by_unchanged_catalog': True,
        'actual_portable_stock_validation': capture, 'all_member_stats_unchanged': initial,
        'current_memory': memory(), 'invocation_cwd': '/tmp', 'all_handles_closed': True,
        'device_IO': False, 'execute_or_main_or_device_preflight_called': False,
        'native_guest': False, 'audio': False, 'service_changes': False,
        'recovery_entrypoint_assembled': False, 'complete_test_packet': False, 'installed': False,
        'Garmin_UI_renderer_verified': False, 'checksum_policy_verified': False,
        'road_loss_rootcause_proven': False, 'full_Taiwan_update_complete': False, 'full_goal_complete': False}
    saved = save('coherent8K-load-only-proof.json', proof)
    print(json.dumps({'all_passed': True, 'proof': saved, 'stock_blocks': capture['stock_blocks_yielded'],
                      'complete_same_bundle_load_passed': True, 'device_IO': False}))


if __name__ == '__main__':
    main()
