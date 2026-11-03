#!/usr/bin/env python3
"""Bind a compact, exact stock rollback recipe to the local country candidate."""
import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from native_address_layout_restore_v1 import layout, logical_read, reconstructed_hash

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'staging/navigation-country-layout-restore-v1'
ORIGINAL = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
CANDIDATE = ROOT/'staging/navigation-country-native-candidate-v1/gmapprom1.img'
ORIGINAL_SHA = '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
SUPPORT_SHA = '1f9d85290426cf7d696dd6a79a5e152100fd8eec17a73a803f65f0c56ba54695'


def main():
    assert not OUT.exists()
    support = ROOT/'scripts/native_address_layout_restore_v1.py'
    assert hashlib.sha256(support.read_bytes()).hexdigest() == SUPPORT_SHA
    # Structural candidate proof owns the full candidate digest. This read-only
    # recipe check computes the exact restored stock image without writing it.
    proof = json.loads((CANDIDATE.parent/'proof.json').read_text())
    assert proof['all_assigned_checks_passed'] and proof['original_L6_L5_L4_full_byte_prefixes_preserved']
    plan = json.loads((CANDIDATE.parent/'mdr-plan.json').read_text())
    orig_stat = ORIGINAL.stat(); candidate_stat = CANDIDATE.stat()
    with ORIGINAL.open('rb') as original, CANDIDATE.open('rb') as current:
        old = layout(original, orig_stat.st_size); new = layout(current, candidate_stat.st_size)
        tails = {}; unused = {}
        for name, item in old['components'].items():
            rem = item['size'] % 4096
            if rem:
                original.seek(item['blocks'][-1]*4096+rem)
                tails[name] = original.read(4096-rem).hex()
        for block in old['unused_blocks']:
            original.seek(block*4096); unused[str(block)] = original.read(4096).hex()
        mdr = old['components']['00004171.MDR']
        old_tables = {n+1:t for n,t in enumerate(plan['original_tables'])}
        new_tables = {n+1:t for n,t in enumerate(plan['new_tables'])}
        ranges = [dict(original_hex=logical_read(original, mdr, 0, 772).hex(), length=772),
            dict(candidate_offset=772, length=old_tables[6]['start']-772)]
        # Each original table is an exact byte prefix of its own enlarged table;
        # a continuous old offset would wrongly cross the new append segments.
        for level in (6, 5, 4):
            ranges.append(dict(candidate_offset=new_tables[level]['start'], length=old_tables[level]['bytes']))
        ranges += [dict(original_hex=logical_read(original, mdr, old_tables[3]['start'], old_tables[3]['bytes']).hex(),
                length=old_tables[3]['bytes']),
            dict(candidate_offset=new_tables[2]['start'], length=plan['old_directory_start']-old_tables[2]['start']),
            dict(original_hex=logical_read(original, mdr, plan['old_directory_start'], 120).hex(), length=120)]
        assert sum(r['length'] for r in ranges) == mdr['size']
        recipe = dict(schema='garmin-native-layout-restore/v1', created_utc=datetime.now(timezone.utc).isoformat(),
            original_bytes=orig_stat.st_size, original_sha256=ORIGINAL_SHA,
            candidate_bytes=candidate_stat.st_size, candidate_sha256=proof['candidate_sha256'],
            original_metadata_bytes=len(old['prefix']), original_prefix_hex=old['prefix'].hex(),
            original_components=old['components'], candidate_components=new['components'], MDR_ranges=ranges,
            original_tail_hex=tails, original_unused_blocks_hex=unused)
        restored = reconstructed_hash(current, recipe)
        assert restored == ORIGINAL_SHA
    assert ORIGINAL.stat() == orig_stat and CANDIDATE.stat() == candidate_stat
    raw = (json.dumps(recipe, ensure_ascii=False, separators=(',',':'))+'\n').encode()
    compressed = gzip.compress(raw, mtime=0)
    OUT.mkdir()
    with (OUT/'restore-layout.json.gz').open('xb') as f:
        f.write(compressed); f.flush(); os.fsync(f.fileno())
    result = dict(schema='country-candidate-exact-layout-restore-proof/v1', all_assigned_checks_passed=True,
        exact_original_hash_reconstructed=restored, original_image_bytes=orig_stat.st_size,
        candidate_image_bytes=candidate_stat.st_size, candidate_sha256=proof['candidate_sha256'],
        recipe_bytes=len(compressed), recipe_sha256=hashlib.sha256(compressed).hexdigest(),
        recipe_uncompressed_bytes=len(raw), original_header_FAT_small_L3_and_padding_stored_only=True,
        unchanged_components_and_separate_old_L6_L5_L4_tables_streamed_from_candidate=True,
        original_unused_blocks=len(unused), source_stats_unchanged=True,
        duplicate_full_backup_created=False, full_restored_IMG_written=False, device_IO=False,
        dependencies=[str((CANDIDATE.parent/'proof.json').relative_to(ROOT)),
            'scripts/native_address_layout_restore_v1.py', str(Path(__file__).relative_to(ROOT))],
        limits=['Exact read-only rollback reconstruction, not an atomic transaction or physical rollback test.',
            'Only this bound stock and country candidate layout; no arbitrary map repair.'])
    with (OUT/'proof.json').open('x') as f:
        f.write(json.dumps(result, ensure_ascii=False, indent=2)+'\n'); f.flush(); os.fsync(f.fileno())
    for path in OUT.iterdir(): path.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True, recipe_bytes=len(compressed), original_sha256=restored)))


if __name__ == '__main__': main()
