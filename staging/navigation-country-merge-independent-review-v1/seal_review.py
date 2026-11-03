#!/usr/bin/env python3
"""Seal the completed review without rerunning or rehashing large inputs."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent


def signature(path):
    value = path.stat()
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert not (OUT / 'execution-receipt.json').exists()
    proof_path = OUT / 'proof.json'
    proof = json.loads(proof_path.read_text())
    assert proof['all_assigned_checks_passed']
    assert digest(OUT / 'review_country_merge.py') == proof['script_sha256']
    immutable = []
    for item in proof['fresh_inputs']:
        current = signature(ROOT / item['path'])
        assert current == item['stat_after'] == item['stat_before'], item['path']
        immutable.append({'path': item['path'], 'sha256_from_completed_content_pass': item['sha256'],
                          'bytes': item['bytes'], 'stat_at_seal': current,
                          'unchanged_from_completed_review': True})
    for name in ('bounded_original_image_receipt', 'bounded_candidate_image_receipt'):
        item = proof[name]
        current = signature(ROOT / item['path'])
        assert current == item['stat_after'] == item['stat_before'], item['path']
        immutable.append({'path': item['path'], 'bytes': current[2],
                          'stat_at_seal': current, 'unchanged_from_completed_review': True,
                          'content_read_scope': 'Only the bounded image ranges listed in proof.json.'})
    elapsed = (datetime.fromisoformat(proof['finished_utc']) -
               datetime.fromisoformat(proof['started_utc'])).total_seconds()
    receipt = {
        'schema': 'country-merge-independent-readonly-review-execution-receipt/v1',
        'sealed_utc': datetime.now(timezone.utc).isoformat(),
        'command': 'python3 staging/navigation-country-merge-independent-review-v1/review_country_merge.py',
        'initial_exec_chunk_id': '2d1934', 'session_id': 24160,
        'terminal_write_stdin_chunk_id': 'f7eb5e', 'actual_exit_code': 0,
        'review_started_utc': proof['started_utc'], 'review_finished_utc': proof['finished_utc'],
        'review_elapsed_seconds': elapsed, 'max_RSS_KiB': proof['max_RSS_KiB'],
        'proof_bytes': proof_path.stat().st_size, 'proof_sha256': digest(proof_path),
        'script_sha256': proof['script_sha256'],
        'new_rows_decoded_from_actual_candidate': proof['new_rows_all_independently_decoded'],
        'embedded_source_members': proof['all_new_rows_source_member_counts'],
        'positive_unique_OSM_source_ids': proof['positive_unique_OSM_source_ids'],
        'complete_city_geometries': proof['complete_source_city_geometries'],
        'actual_new_record_cities': proof['actual_new_record_cities_used'],
        'native_grid_city_outliers': proof['quantized_point_city_membership_outliers'],
        'original_groups_directly_reviewed': proof['original_group_bounded_review']['groups'],
        'original_records_directly_reviewed': proof['original_group_bounded_review']['old_records_directly_compared'],
        'actual_original_image_bytes_read': proof['bounded_original_image_receipt']['actual_bytes_read'],
        'actual_candidate_image_bytes_read': proof['bounded_candidate_image_receipt']['actual_bytes_read'],
        'fresh_assigned_non_image_bytes_read': sum(x['bytes'] for x in proof['fresh_inputs']),
        'input_immutability_at_seal': immutable,
        'producer_ready_source_EOF_SHA_evidence_used_by_reference_only': True,
        'full_candidate_SHA_used_from_root_readback_only': True,
        'large_inputs_reparsed_or_rehashed_at_seal': False,
        'temporary_DB_swap_or_native_image_created': False,
        'device_IO_native_CPU_or_closed_suites': False,
        'full_Taiwan_update_complete': False,
        'scope': 'All 111608 new payloads and embedded source members; all 15679 range metadata; 30 bounded original groups. Source city containment is distinct from native-grid city containment and does not prove district geography or address authenticity.'
    }
    (OUT / 'execution-receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    text = """Independent country merge review, completed read-only

111,608 new integer house records were decoded from actual candidate packed bytes:
L4 74,455; L5 35,183; L6 1,970. All payload positions, original GMP CP950
house refs, raw24 values with independently rounded source strings, exact native
city/district/street roster identities, and all 111,608 embedded source members
(352,541 positive unique OSM IDs) matched. The three appended tables match the
sealed producer binaries; L5 final padding is 2 zero high bits, L6 is 4.

The independent signed-winding check used 21 complete city geometries, with
16 cities actually receiving new records; Kaohsiung receives zero. Every source
coordinate lies within its expected complete city. One quantized native point
crosses the city boundary: Taoyuan nativeStreetID 6676, L4 new_lowID 2382209,
810號, source 24.9285209 / 121.058782, raw24 [1161753, 5641748]. This extra
native-grid check is explicitly separate from the producer source-point policy.

30 original street groups (10 per level), 5,242 old records were directly read:
their significant bits and relative order are unchanged, including 145 nonnumeric
labels, 128 nested branches, 101 raw flag8 and 16 raw flag13 records. These flag
values are preserved observations; this review does not establish their semantics.
The sample covers original/output bit shifts and checks its 30 actual L3 parents.
All selected range metadata matches the original decoded roster; complete L3 and
old-prefix preservation use the root's separately sealed full readback evidence.

Actual image reads: original 3,939,336 B (includes bounded 3,805,432 B label pool),
candidate 25,130,930 B; peak RSS 424,240 KiB. Review exited 0 in 19.650932 seconds.
No full IMG hash, PBF, full source groups/node ledger or ready ledgers were reread.
The ready inputs' complete EOF/SHA provenance and candidate complete SHA are
explicitly inherited from their sealed producer/root readback evidence.
No IMG, CPU, device, canonical source, report or ZIP was modified in this scope.
District geographic membership, source address authenticity and physical UI/route
acceptance are not proved here. The full Taiwan native update remains incomplete.

proof.json contains actual source hashes/stats, bounded physical read ranges and
SHA receipts; execution-receipt.json ties it to session 24160 / terminal f7eb5e.
"""
    (OUT / 'REVIEW.txt').write_text(text)
    records = []
    for filename in ('review_country_merge.py', 'seal_review.py', 'proof.json',
                     'execution-receipt.json', 'REVIEW.txt'):
        path = OUT / filename
        records.append({'path': filename, 'bytes': path.stat().st_size, 'sha256': digest(path)})
    seal = {'schema': 'country-merge-independent-review-file-seal/v1',
            'sealed_utc': receipt['sealed_utc'], 'actual_review_exit_code': 0,
            'all_assigned_checks_passed': True, 'files': records,
            'native_grid_city_outliers': 1, 'full_Taiwan_update_complete': False}
    (OUT / 'sealed-files.json').write_text(json.dumps(seal, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'review_exit_code': 0, 'scope_sealed': True,
                      'proof_sha256': receipt['proof_sha256'],
                      'receipt_sha256': digest(OUT / 'execution-receipt.json'),
                      'seal_sha256': digest(OUT / 'sealed-files.json'),
                      'all_input_stats_unchanged_at_seal': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
