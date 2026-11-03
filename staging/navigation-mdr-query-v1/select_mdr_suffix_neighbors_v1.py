#!/usr/bin/env python3
"""Read only finite neighborhoods selected by the frozen Han taxonomy.

The reported native-unit predictions require the peer's actual comparator;
no original address caller, VM, whole-table recheck or whole-IMG digest.
"""
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]


def kind(cp):
    if 0x3400 <= cp <= 0x4dbf:
        return 'ExtA'
    if 0x4e00 <= cp <= 0x9fbb:
        return 'Unified'
    if 0x20000 <= cp <= 0x2a6d6:
        return 'ExtB'
    return 'other'


def lead(cp):
    return ((0xfb40 if kind(cp) == 'Unified' else 0xfb80) + (cp >> 15))


def main():
    output = BASE / 'candidate-mdr-suffix-neighborhoods-v1.json'
    assert not output.exists()
    helper = BASE / 'query_candidate_mdr_v1.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == '38d879f8f668b097294c98c75d834b7225a30c9c711a7a4a99641a9fc2635b4b'
    spec = importlib.util.spec_from_file_location('frozen_MDR_FILE_classes_only', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proof = json.loads((BASE / 'candidate-mdr-query-proof-v1.json').read_text())
    taxonomy = json.loads((BASE / 'candidate-mdr-Han-taxonomy-v1.json').read_text())
    sections = {int(k):v for k,v in proof['sections'].items()}
    image = module.Image(ROOT / proof['candidate']['path'])
    labels = module.Labels(image)
    sort = module.Sort(image.read(next(n for n in image.components if n.endswith('.SRT'))))
    maps_data = image.read(proof['MDR_component'], sections[1]['position'], sections[1]['bytes'])
    maps = [module.uint(maps_data, i * 4, 4) for i in range(sections[1]['records'])]
    neighborhoods = {}
    pairs = []
    for number in [7, 5]:
        section = sections[number]
        chosen = set()
        for row in taxonomy['sections'][str(number)]['bounded_ExtA_ExtB_examples']:
            chosen.update(range(max(1, row['record'] - 1), min(section['records'], row['record'] + 1) + 1))
        if number == 7:
            chosen.add(next(row['record'] for row in proof['target_MDR7_records'] if row['name'] == '民權路'))
        rows = []
        for record in sorted(chosen):
            data = image.read(proof['MDR_component'], section['position'] + (record - 1) * section['item_size'], section['item_size'])
            mi = module.uint(data, 0, 1)
            raw = module.uint(data, 3 if number == 5 else 1, 3)
            name = labels.name(maps[mi - 1], raw & 0x7fffff)
            partial = module.partial(name, data[4]) if number == 7 else name
            rows.append(dict(MDR_section=number, record=record, tile=maps[mi - 1],
                label_offset=raw & 0x7fffff, name=name, partial=partial))
        neighborhoods[number] = rows
        for left, right in zip(rows, rows[1:]):
            if right['record'] != left['record'] + 1:
                continue
            a, b = left['partial'], right['partial']
            at = next((i for i, (x,y) in enumerate(zip(a,b)) if x != y), None)
            if at is None:
                continue
            x, y = ord(a[at]), ord(b[at])
            if kind(x) in ['ExtA', 'ExtB'] and kind(y) == 'Unified':
                pairs.append(dict(before=left, after=right, common_Unicode_prefix=a[:at],
                    first_difference_codepoints=[f'U+{x:X}', f'U+{y:X}'],
                    native_predicted_first_difference_units=[[lead(x), 0x8000 + (x & 0x7fff)],
                        [lead(y), 0x8000 + (y & 0x7fff)]],
                    actual_host_key_order_ascending=sort.key(a) < sort.key(b),
                    predicted_native_primary_order_descending=lead(x) > lead(y),
                    these_pair_strings_native_executed_here=False, native_address_caller_verified=False))
        if number == 7:
            before = next(row for row in rows if row['record'] == 55)
            after = next(row for row in rows if row['name'] == '民權路')
            x, y = ord(before['partial'][0]), ord(after['partial'][0])
            pairs.append(dict(before=before, after=after, adjacent=False, common_Unicode_prefix='',
                first_difference_codepoints=[f'U+{x:X}', f'U+{y:X}'],
                actual_host_key_order_ascending=sort.key(before['partial']) < sort.key(after['partial']),
                predicted_native_primary_order_descending=lead(x) > lead(y),
                these_pair_strings_native_executed_here=False, native_address_caller_verified=False))
    result = dict(all_passed=True, checked_utc=datetime.now(timezone.utc).isoformat(),
        scope='NEW finite +/-1 neighborhoods of32 frozen rare-label records and one named control; no global order/flags/joins rerun.',
        source_taxonomy='staging/navigation-mdr-query-v1/candidate-mdr-Han-taxonomy-v1.json',
        neighborhoods=neighborhoods, actual_candidate_pairs_for_native_comparator=pairs,
        native_predictions_are_peer_unit_arithmetic=True, original_native_code_executed_here=False,
        address_search_root_cause_or_UI_failure_proven=False, candidate_remains_held=True,
        whole_IMG_or_backup_hash_repeated=False, device_IO=False, canonical_edits=False)
    with output.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=True, finite_rows_read=sum(len(v) for v in neighborhoods.values()),
        pair_count=len(pairs), pairs=[dict(section=p['before']['MDR_section'],
            before_record=p['before']['record'], before=p['before']['partial'],
            after_record=p['after']['record'], after=p['after']['partial']) for p in pairs]), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
