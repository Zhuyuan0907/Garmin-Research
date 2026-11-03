"""Fresh exact inventory and unchanged v2 load_manifest validation, no device."""
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
BUNDLE = OUT / 'packet/working-v2'
RESULT = OUT / 'working-v2-load-only-proof.json'
STAGING_PROOF_SHA = '8dc588afb3e6af2a7b6568861e34121c95eb01a8c7036ce5e6234e05c69642e3'


def need(value, message):
    if not value:
        raise ValueError(message)


def snap(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink, s.st_mode]


def save(value):
    b = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    need(len(b) <= 65536, 'Small result cap')
    with RESULT.open('xb') as f:
        f.write(b); f.flush(); os.fsync(f.fileno())
    RESULT.chmod(0o444)
    return {'path': str(RESULT.relative_to(ROOT)), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def main():
    need(not RESULT.exists(), 'One load-only verification result')
    raw = (OUT / 'working-v2-staging-proof.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == STAGING_PROOF_SHA, 'Pinned staged inventory')
    proof = json.loads(raw)
    need(proof['all_assigned_staging_checks_passed'] and len(proof['members']) == 20, 'All original members staged')
    checked = []; total = 0
    for row in proof['members']:
        p = OUT / 'packet' / row['packet_path']; before = p.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_size == row['bytes'], 'Exact regular member')
        h = hashlib.sha256(); count = 0
        with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
            need(snap(os.fstat(f.fileno())) == snap(before), 'Opened member stat')
            while True:
                b = f.read(1048576)
                if not b: break
                count += len(b); h.update(b)
                need(count <= row['bytes'], 'Bounded member stream')
            need(snap(os.fstat(f.fileno())) == snap(before), 'Member stable through full hash')
        need(count == row['bytes'] and h.hexdigest() == row['sha256']
             and snap(p.lstat()) == snap(before), 'All member fresh SHA and EOF')
        total += count
        checked.append({'packet_path': row['packet_path'], 'bytes': count,
                        'fresh_sha256': h.hexdigest(), 'stat_before_after': snap(before)})

    # Test actual same-bundle imports and positive recipe validation from an
    # unrelated cwd. Forbid process execution and device/system discovery.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(BUNDLE))
    old_cwd = Path.cwd()
    loading = True; audit_counts = {'forbidden_operation_attempts': 0}

    def audit(event, args):
        if not loading:
            return
        forbidden = event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'socket.connect', 'socket.bind')
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            path = os.fsdecode(args[0])
            forbidden = forbidden or path.startswith(('/dev/', '/sys/'))
            if len(args) > 2 and isinstance(args[2], int):
                forbidden = forbidden or bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        if forbidden:
            audit_counts['forbidden_operation_attempts'] += 1
            raise RuntimeError('Load-only validation forbids mutation, subprocess or device I/O')

    sys.addaudithook(audit)
    try:
        os.chdir('/tmp')
        source = BUNDLE / 'install_native_house_supplement.py'
        spec = importlib.util.spec_from_file_location('_root_working_v2_pinned_load_only', source)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        m, candidate, recipe, manifest_sha = installer.load_manifest(BUNDLE)
        need(manifest_sha == '71258a290bce559b0f882282bf2ce3c6cd8e690d49fd5ef5756e454b3fde97f7'
             and m['target']['candidate_sha256'] == '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
             'Exact unchanged known-working bundle returned')
        need(recipe['original_bytes'] == 96739328
             and recipe['original_sha256'] == '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',
             'Complete stock reconstruction passed within unchanged validator')
        need(candidate == BUNDLE / 'candidate/gmapprom1.img', 'Portable local candidate path')
    finally:
        loading = False
        os.chdir(old_cwd)
    need(audit_counts['forbidden_operation_attempts'] == 0, 'No forbidden I/O or execution attempted')
    value = {
        'schema': 'unchanged-working-v2-packet-load-only-proof/v1', 'all_assigned_checks_passed': True,
        'completed_utc': datetime.now(timezone.utc).isoformat(), 'original_members_freshly_verified': checked,
        'fresh_inventory_full_file_bytes': total, 'unchanged_installer_load_manifest_called': True,
        'complete_exact_stock_reconstruction_checked_by_unchanged_validator': True,
        'manifest_SHA256': manifest_sha, 'invocation_cwd': '/tmp',
        'same_bundle_imports_and_paths_verified': True, 'audited_forbidden_operation_attempts': 0,
        'device_IO': False, 'execute_or_main_called': False, 'native_guest': False, 'audio': False,
        'coherent8K_subbundle_complete': False, 'complete_test_packet': False,
        'known_working_v2_device_recovery_executed': False, 'Garmin_UI_new_candidate_verified': False,
        'full_Taiwan_update_complete': False, 'full_goal_complete': False,
    }
    saved = save(value)
    print(json.dumps({'all_passed': True, 'proof': saved, 'fresh_inventory_bytes': total,
                      'unchanged_load_manifest_passed': True, 'device_IO': False}))


if __name__ == '__main__':
    main()
