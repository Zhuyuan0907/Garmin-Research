"""Stage the unchanged known-working v2 bundle without copying large maps.

Pure host file packaging; no device discovery, firmware, guest or audio. The
candidate and road files are hardlinked, then verified in a later load-only gate.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-coherent8K-test-recovery-packet-v1'
PLAN = ROOT / 'staging/navigation-known-working-country-v2-recovery-preparation-v1/recovery-file-binding-plan.json'
PLAN_SHA = 'da6be5d3e2cc653db0eb47861593b1288e26c0c0d96807ad5c7e2723e4c1f8fe'
MAX_NON_IMG = 16 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def snap(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
            s.st_ctime_ns, s.st_nlink, s.st_mode]


def write_json(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    p = OUT / name
    with p.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    p.chmod(0o444)
    return {'path': str(p.relative_to(ROOT)), 'bytes': len(raw), 'sha256': digest(raw)}


def safe_relative(name):
    p = PurePosixPath(name)
    need(not p.is_absolute() and all(x not in ('', '.', '..') for x in p.parts), 'Safe relative bundle member')
    need(str(p) == name and '\\' not in name, 'Canonical POSIX bundle member')
    return p


def main():
    need(not OUT.exists(), 'Single-use staging packet namespace')
    raw = PLAN.read_bytes()
    need(len(raw) == 19103 and digest(raw) == PLAN_SHA, 'Pinned closed file plan')
    plan = json.loads(raw)
    rows = plan['phase2']['all_original_bundle_members']
    need(len(rows) == 20 and len({r['packet_path'] for r in rows}) == 20, 'All unchanged original 20 members')
    non_img = sum(r['bytes'] for r in rows if not r['packet_path'].lower().endswith('.img'))
    need(non_img <= MAX_NON_IMG, 'Bounded small metadata and historical validation copy')
    for row in rows:
        safe_relative(row['packet_path']); safe_relative(row['source_path'])
        need(row['packet_path'].startswith('working-v2/'), 'Fixed working-v2 subdirectory')
        p = ROOT / row['source_path']; s = p.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_size == row['bytes']
             and stat.S_IMODE(s.st_mode) == 0o444, 'Expected readonly source member')
    OUT.mkdir(mode=0o700)
    results = []; phase = 'staging_unchanged_working_v2'
    copied = readback = 0
    try:
        for row in rows:
            source = ROOT / row['source_path']
            target = OUT / 'packet' / row['packet_path']
            target.parent.mkdir(parents=True, exist_ok=True)
            before = source.lstat()
            if target.suffix.lower() == '.img':
                os.link(source, target, follow_symlinks=False)
                after = source.lstat(); actual = target.lstat()
                need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
                     == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode),
                     'Only hardlink bookkeeping may change')
                need(snap(after) == snap(actual) and after.st_nlink == before.st_nlink + 1,
                     'One new hardlink to the exact same inode')
                results.append({**row, 'kind': 'same_inode_hardlink', 'source_stat_before': snap(before),
                                'source_stat_after': snap(after), 'expected_SHA_not_freshly_rehashed_yet': True})
            else:
                h = hashlib.sha256(); count = 0
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, 'rb') as inp, target.open('xb') as dest:
                    need(snap(os.fstat(inp.fileno())) == snap(before), 'Copied source inode/stat')
                    while True:
                        b = inp.read(1048576)
                        if not b: break
                        h.update(b); count += len(b); dest.write(b)
                        need(count <= row['bytes'], 'Source length cap')
                    dest.flush(); os.fsync(dest.fileno())
                    need(snap(os.fstat(inp.fileno())) == snap(before), 'Source stat stable through copy')
                need(count == row['bytes'] and h.hexdigest() == row['sha256']
                     and snap(source.lstat()) == snap(before), 'Copied exact pinned bytes')
                target.chmod(0o444)
                rh = hashlib.sha256(); rc = 0
                with target.open('rb') as f:
                    while True:
                        b = f.read(1048576)
                        if not b: break
                        rh.update(b); rc += len(b)
                need(rc == count and rh.hexdigest() == row['sha256'], 'Actual metadata saved readback')
                copied += count; readback += rc
                results.append({**row, 'kind': 'copy', 'saved_readback_sha256': rh.hexdigest(),
                                'source_stat_unchanged': True})
        proof = {
            'schema': 'working-v2-test-packet-staging/v1', 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'all_assigned_staging_checks_passed': True, 'closed_plan_SHA256': PLAN_SHA,
            'original_v2_bundle_20_members_retained': True, 'members': results,
            'metadata_copy_bytes': copied, 'metadata_saved_readback_bytes': readback,
            'IMG_bytes_opened_read_written': 0, 'hardlinked_large_assets': 2,
            'known_working_v2_candidate_SHA_expected': '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
            'Search_v2_road_SHA_expected': '664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117',
            'fresh_large_asset_SHA_and_production_load_only_gate_passed': False,
            'coherent8K_subbundle_assembled': False, 'recovery_entrypoint_assembled': False,
            'complete_test_packet': False, 'device_IO': False, 'native_guest': False, 'audio': False,
            'service_changes': False, 'installable': False, 'full_goal_complete': False,
            'source_nlink_ctime_changes_expected_and_recorded': True,
            'closed_prior_proofs_and_seals_not_modified': True,
        }
        saved = write_json('working-v2-staging-proof.json', proof)
        print(json.dumps({'all_passed': True, 'proof': saved, 'hardlinked_maps': 2,
                          'metadata_bytes_copied': copied, 'IMG_bytes_read': 0, 'device_IO': False}))
    except BaseException as exc:
        write_json('failure.json', {'phase': phase, 'error_type': type(exc).__name__, 'error': str(exc),
                                   'completed_members': len(results), 'partial_packet_retained': True,
                                   'IMG_bytes_read': 0, 'device_IO': False, 'no_automatic_retry': True})
        raise


if __name__ == '__main__':
    main()
