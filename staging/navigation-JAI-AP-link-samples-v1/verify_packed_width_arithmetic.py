#!/usr/bin/env python3
"""Pure integer crosscheck of six previously captured AP descriptors."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-JAI-AP-link-samples-v1'
INPUT = OUT / 'JAI-AP-link-samples-evidence.json'


def main():
    output = OUT / 'packed-width-arithmetic.json'
    raw = INPUT.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == 'a3a5d041d53deadc418dfca52d518f8d7a84cf21eb116616c9e5fb790976998c'
    evidence = json.loads(raw)
    rows = []
    for item in evidence['AP_directory_numerical_projections']:
        total_widths = sum(item['word3_6bit_projections'].values()) + sum(item['word4_6bit_projections'].values())
        projected = total_widths + 24 * item['word3_bit30'] + 19 * item['word3_bit31']
        assert projected == item['scalar_value']
        rows.append({'ordinal': item['ordinal'], 'sum_eight_widths': total_widths,
                     'bit30': item['word3_bit30'], 'bit31': item['word3_bit31'],
                     'formula_result': projected, 'observed_scalar': item['scalar_value'], 'equal': True})
    result = {'created_utc': datetime.now(timezone.utc).isoformat(),
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'dependency': {'path': str(INPUT.relative_to(ROOT)), 'sha256': digest},
        'scope': 'Pure arithmetic on captured DWORDs; no DB/map/native/device reads or suite reruns.',
        'formula': 'sum(eight six-bit width values) + 24*bit30 + 19*bit31 == third directory DWORD',
        'rows': rows, 'all_six_equal': True,
        'constant_24_and_bit30x24_indistinguishable_in_observed_rows': all(r['bit30'] == 1 for r in rows),
        'native_field_order_semantics_or_flag_causality_verified': False,
        'does_not_prove_bit30_adds24_for_unseen_zero_flag': True,
        'new_DB_AP_or_device_IO': False}
    with output.open('x') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(output.relative_to(ROOT)), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                      'bytes': output.stat().st_size, 'all_six_equal': True}))


if __name__ == '__main__':
    main()
