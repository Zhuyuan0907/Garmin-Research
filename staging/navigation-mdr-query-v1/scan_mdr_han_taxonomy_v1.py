#!/usr/bin/env python3
"""NEW taxonomy-only scope; select real labels for a later native comparator check.

Does not rerun the completed record joins, global order or repeat-flag checks.
Native lead predictions are arithmetic from a peer's finite unit evidence,
not executions of an address/search caller and not a Garmin UI success claim.
"""
import hashlib
import importlib.util
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
HELPER = BASE / 'query_candidate_mdr_v1.py'


def category(cp):
    if 0x3400 <= cp <= 0x4dbf:
        return 'ExtA'
    if 0x4e00 <= cp <= 0x9fbb:
        return 'Unified'
    if 0x20000 <= cp <= 0x2a6d6:
        return 'ExtB'
    return 'other'


def lead(cp):
    kind = category(cp)
    if kind == 'Unified':
        return 0xfb40 + (cp >> 15)
    if kind in ['ExtA', 'ExtB']:
        return 0xfb80 + (cp >> 15)
    return None


def main():
    output = BASE / 'candidate-mdr-Han-taxonomy-v1.json'
    assert not output.exists()
    assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == '38d879f8f668b097294c98c75d834b7225a30c9c711a7a4a99641a9fc2635b4b'
    spec = importlib.util.spec_from_file_location('frozen_file_helpers_only', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # main is never called; no guest libraries exist.
    proof = json.loads((BASE / 'candidate-mdr-query-proof-v1.json').read_text())
    sec = {int(k):v for k,v in proof['sections'].items()}
    img = module.Image(ROOT / proof['candidate']['path'])
    labels = module.Labels(img)
    mdr_key = proof['MDR_component']
    maps_data = img.read(mdr_key, sec[1]['position'], sec[1]['bytes'])
    maps = [module.uint(maps_data, i * 4, 4) for i in range(sec[1]['records'])]
    results = {}
    for number in [7, 5]:
        s = sec[number]
        data = img.read(mdr_key, s['position'], s['bytes'])
        leading, containing = Counter(), Counter()
        examples, adjacent, previous = [], [], None
        all_ext_names = set()
        for i in range(s['records']):
            pos = i * s['item_size']
            mi = module.uint(data, pos, 1)
            label_pos = pos + (3 if number == 5 else 1)
            raw = module.uint(data, label_pos, 3)
            name = labels.name(maps[mi - 1], raw & 0x7fffff)
            display = module.partial(name, data[pos + 4]) if number == 7 else name
            kinds = {category(ord(ch)) for ch in display}
            for kind in kinds:
                containing[kind] += 1
            first = ord(display[0]) if display else 0
            kind = category(first)
            leading[kind] += 1
            row = dict(MDR_section=number, record=i + 1, tile=maps[mi - 1],
                label_offset=raw & 0x7fffff, name=name, partial=display,
                leading_class=kind, first_codepoint=f'U+{first:04X}')
            if 'ExtA' in kinds or 'ExtB' in kinds:
                all_ext_names.add(display)
                if len(examples) < 24:
                    examples.append(row)
            if previous and previous['leading_class'] in ['ExtA', 'ExtB'] and kind == 'Unified':
                before_cp = int(previous['first_codepoint'][2:], 16)
                if lead(before_cp) > lead(first) and len(adjacent) < 24:
                    adjacent.append(dict(before=previous, after=row,
                        predicted_native_primary_leads=[lead(before_cp), lead(first)],
                        native_lead_arithmetic_inverts_current_record_order=True,
                        this_pair_native_instructions_executed=False,
                        actual_address_caller_or_UI_executed=False))
            previous = row
        results[number] = dict(record_count=s['records'], leading_class_counts=dict(leading),
            containing_class_record_counts=dict(containing), distinct_ExtA_or_ExtB_partial_names=len(all_ext_names),
            bounded_ExtA_ExtB_examples=examples, bounded_real_adjacencies_for_native_probe=adjacent)
    result = dict(all_passed=True, checked_utc=datetime.now(timezone.utc).isoformat(),
        scope='NEW candidate MDR7/MDR5 label Han taxonomy and bounded real adjacency selection only.',
        completed_MDR_query_checks_repeated=False, candidate_hash_repeated=False,
        native_firmware_or_Garmin_UI_executed=False, candidate_installable_or_incompatible_proven=False,
        peer_native_flag1_ranges={'Unified':['4E00','9FBB'], 'ExtA':['3400','4DBF'], 'ExtB':['20000','2A6D6']},
        peer_native_unit_rule='Unified lead FB40+(cp>>15), ExtA/ExtB lead FB80+(cp>>15), trail8000+(cp&7FFF); peer finite-unit evidence, caller scope still unproven.',
        candidate=proof['candidate'], sections=results,
        next='Execute the selected actual strings through the peer native unit/comparison scope, then confirm the address caller uses that ordering; no repair/root-cause claim from arithmetic alone.',
        device_IO=False, canonical_edits=False)
    with output.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'sections'}, ensure_ascii=False), flush=True)
    print(json.dumps({k:{field:value for field,value in row.items() if not isinstance(value,list)}
        for k,row in results.items()}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
