"""Add the fixed 15-member coherent8K local test subbundle, no device I/O."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-coherent8K-test-recovery-packet-v1'
BUNDLE = OUT / 'packet/coherent8k'
SOURCE = ROOT / 'staging/navigation-AP-coherent8K-activated-test-entrypoint-v1'
PLAN_SHA = 'a6a2a84e91bbbc2b515b13cd93b4c008f2a85c0394bae72f077c93dd496b2af1'
SOURCE_SEAL_SHA = '54bdfcd2aa434d99d2d141f23e405870958218fc6e9052f402b7015bcbbefb9d'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def snap(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink, s.st_mode]


def relative(value):
    p = PurePosixPath(value)
    need(not p.is_absolute() and str(p) == value and '\\' not in value
         and all(x not in ('', '.', '..') for x in value.split('/')), 'Canonical relative packet path')
    return value


def save(name, value):
    b = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    need(len(b) <= 65536, 'Small staging receipt cap')
    p = OUT / name
    with p.open('xb') as f:
        f.write(b); f.flush(); os.fsync(f.fileno())
    p.chmod(0o444)
    return {'path': str(p.relative_to(ROOT)), 'bytes': len(b), 'sha256': sha(b)}


def main():
    need(not BUNDLE.exists(), 'One new coherent8K packet subdirectory')
    need((OUT / 'working-v2-half-packet-closure.json').is_file(), 'Working-v2 half already verified')
    raw = (SOURCE / 'PACKAGING.json').read_bytes()
    seal_raw = (SOURCE / 'sealed-files.json').read_bytes()
    need(len(raw) == 5082 and sha(raw) == PLAN_SHA and sha(seal_raw) == SOURCE_SEAL_SHA,
         'Exact new activated source and copy-plan seals')
    rows = json.loads(raw)['files']
    need(len(rows) == 15 and len({r['bundle_path'] for r in rows}) == 15, 'Exact complete 15-member catalog')
    need(sum(r['bytes'] for r in rows if r['role'] not in ('candidate', 'road')) <= 2 * 1024 * 1024,
         'Compact copied-sidecar storage bound')
    large = {r['role']: r for r in rows if r['role'] in ('candidate', 'road')}
    need(set(large) == {'candidate', 'road'}
         and large['candidate']['bytes'] == 153346048
         and large['candidate']['sha256'] == '9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'
         and large['road']['bytes'] == 131829760
         and large['road']['sha256'] == '664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117',
         'One fixed actual control and unchanged road')
    for row in rows:
        relative(row['bundle_path']); relative(row['source_path'])
        p = ROOT / row['source_path']; s = p.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_size == row['bytes']
             and stat.S_IMODE(s.st_mode) == 0o444, 'Expected readonly regular source')
    BUNDLE.mkdir()
    results = []; copied = 0
    try:
        for row in rows:
            p = ROOT / row['source_path']; t = BUNDLE / row['bundle_path']
            t.parent.mkdir(parents=True, exist_ok=True)
            before = p.lstat()
            if row['role'] in ('candidate', 'road'):
                os.link(p, t, follow_symlinks=False)
                after = p.lstat()
                need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
                     == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
                     and after.st_nlink == before.st_nlink + 1 and snap(t.lstat()) == snap(after),
                     'Exact same inode; only intentional hardlink bookkeeping changes')
                results.append({**row, 'kind': 'same_inode_hardlink', 'source_stat_before': snap(before),
                                'source_stat_after': snap(after), 'fresh_payload_SHA_pending_load_gate': True})
            else:
                h = hashlib.sha256(); count = 0
                with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as inp, t.open('xb') as dest:
                    need(snap(os.fstat(inp.fileno())) == snap(before), 'Source opened stat pin')
                    while True:
                        b = inp.read(1048576)
                        if not b: break
                        count += len(b); h.update(b); dest.write(b)
                        need(count <= row['bytes'], 'Exact small copy length')
                    dest.flush(); os.fsync(dest.fileno())
                    need(snap(os.fstat(inp.fileno())) == snap(before), 'Source stable while copying')
                need(count == row['bytes'] and h.hexdigest() == row['sha256']
                     and snap(p.lstat()) == snap(before), 'Exact closed source bytes and stable stat')
                t.chmod(0o444)
                saved = t.read_bytes()
                need(len(saved) == count and sha(saved) == row['sha256'], 'Actual small saved-output readback')
                copied += count
                results.append({**row, 'kind': 'copy', 'saved_readback_sha256': sha(saved), 'source_unchanged': True})
        road = (BUNDLE / large['road']['bundle_path']).lstat()
        working_road = (OUT / 'packet/working-v2/roadmap/Taiwan_OSM_SearchRepair_v2.img').lstat()
        need((road.st_dev, road.st_ino) == (working_road.st_dev, working_road.st_ino), 'Both phases share exact road inode')
        proof = {'schema': 'activated-coherent8K-subpacket-staging/v1',
                 'completed_utc': datetime.now(timezone.utc).isoformat(), 'all_assigned_staging_checks_passed': True,
                 'copy_plan_SHA256': PLAN_SHA, 'activated_source_seal_SHA256': SOURCE_SEAL_SHA,
                 'members': results, 'metadata_bytes_copied_and_readback_verified': copied,
                 'large_payloads_hardlinked': 2, 'new_large_map_storage_allocated': 0,
                 'IMG_bytes_opened_read_written': 0, 'source_nlink_ctime_changes_expected_and_recorded': True,
                 'earlier_source_stat_proofs_preserved_as_prepackaging_history': True,
                 'same_directory_positive_production_load_verified': False, 'recovery_entrypoint_assembled': False,
                 'complete_test_packet': False, 'device_IO': False, 'native_guest': False, 'audio': False,
                 'installed': False, 'installable': False, 'Garmin_UI_renderer_verified': False, 'full_goal_complete': False}
        saved = save('coherent8K-staging-proof.json', proof)
        print(json.dumps({'all_passed': True, 'proof': saved, 'metadata_copied': copied,
                          'large_maps_hardlinked': 2, 'IMG_bytes_read': 0, 'device_IO': False}))
    except BaseException as exc:
        save('coherent8K-staging-failure.json', {'error_type': type(exc).__name__, 'error': str(exc),
                                               'completed_members': len(results), 'partial_packet_retained': True,
                                               'no_automatic_retry': True, 'device_IO': False})
        raise


if __name__ == '__main__':
    main()
