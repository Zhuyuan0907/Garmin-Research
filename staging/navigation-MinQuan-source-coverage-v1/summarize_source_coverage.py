#!/usr/bin/env python3
"""Small readable projection of completed XML-only coverage proof."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-MinQuan-source-coverage-v1'
PROOF = OUT / 'MinQuan-source-coverage-proof-v1.json'


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'coverage-summary-v1.json'
    if target.exists():
        raise ValueError('Refusing to overwrite summary')
    if ref(PROOF)['sha256'] != '33dca7c855910795770932541393b6bf22ae302f0273dee3987c0c1f3407b75d':
        raise ValueError('Completed source comparison changed')
    proof = json.loads(PROOF.read_text())
    rows = proof['qualified_source_records_complete_tags']
    present = [g for g in proof['distinct_qualified_housenumber_labels'] if g['status'] == 'present_in_old84']
    absent = [g for g in proof['distinct_qualified_housenumber_labels'] if g['status'] == 'not_observed_in_old84']
    summary = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
        'complete_source_proof': ref(PROOF), 'source_snapshot_date': proof['source_XML']['source_snapshot_date'],
        'summary': proof['summary'], 'administrative_policy': proof['administrative_matching_policy'],
        'label_comparison_policy': proof['label_comparison_policy'],
        'all66_distinct_housenumber_labels': [{k: v for k, v in g.items() if k != 'source_objects'}
                                           for g in proof['distinct_qualified_housenumber_labels']],
        'nine_simple_house_source_candidates_complete_tags': proof['simple_single_house_source_candidates_not_observed_in_old84'],
        'existing56_label_source_example_each_complete_tags': [next(r for r in rows if r['comparison_label'] == g['comparison_label'])
                                                             for g in present],
        'multi_address_literal_not_new_single_house': [r for r in rows if r['comparison_label'] == '16,18'],
        'known_source184_complete_tags': proof['known_source184_records'],
        'uncertain_source_records': proof['administratively_uncertain_source_records_complete_tags'],
        'old_primary_labels_not_in_this_filtered_source': proof['old_primary_labels_not_seen_in_qualified_source_comparison_forms'],
        'all_source_object_IDs_full_tags_and_coordinates_preserved_in_complete_proof': True,
        'not_observed_in_old84_is_not_absent_from_entire_Garmin': True,
        'all84_original_labels_equated_with_complete_index': False,
        'source_date_or_edit_timestamp_proves_post2016_new_construction': False,
        'original_IMG_USB_or_native_codec_read_or_rerun': False,
        'new_source_candidate_record_or_MAP_written': False,
        'all_summary_projection_checks_passed': len(present) == 56 and len(absent) == 10}
    if not summary['all_summary_projection_checks_passed']:
        raise ValueError('Coverage counts differ')
    with target.open('x') as f:
        json.dump(summary, f, ensure_ascii=False, separators=(',', ':'))
        f.write('\n')
    if target.stat().st_size >= 150000:
        raise ValueError('Summary unexpectedly large')
    print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
        'sha256': ref(target)['sha256'], 'all_summary_projection_checks_passed': True}))


if __name__ == '__main__':
    main()
