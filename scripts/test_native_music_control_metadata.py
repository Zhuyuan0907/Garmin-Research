#!/usr/bin/env python3
"""Host-only controls for the metadata guard, with clearly synthetic JSON data."""
import copy
import gzip
import json
from pathlib import Path
import tempfile

from check_native_music_control_metadata import FUNCTIONS, TABLE, LIMIT, check, load_metadata


def run(contract, historical):
    cases = []
    fixture = copy.deepcopy(historical)
    for index, name in enumerate((*FUNCTIONS, TABLE)):
        fixture['symbols'][name] = {
            'name': name, 'value': fixture['module_base'] + 256 + index * 128,
            'size': 36 if name == TABLE else 64, 'type': 1 if name == TABLE else 2,
            'binding': 1, 'visibility': 0, 'section_index': 2,
        }
    result = check(fixture, contract)
    assert result['metadata_contract_satisfied'] and not result['device_install_candidate']
    assert not result['fresh_ELF_verified'] and not result['runtime_wiring_verified']
    cases.append('complete synthetic metadata passes declarations only')
    result = check(historical, contract)
    assert historical['all_passed'] is True and not result['metadata_contract_satisfied']
    assert set(result['missing_entries']) == {
        'umc_status_read', 'umc_source_started', 'umc_cleanup_returned', 'umc_kick', TABLE}
    cases.append('historical all_passed does not mask five missing declarations')

    mutations = [
        ('table is an object, not a getter function', lambda d: d['symbols'][TABLE].update(type=2)),
        ('old 40-byte table shape refused', lambda d: d['symbols'][TABLE].update(size=40)),
        ('undefined function refused', lambda d: d['symbols'][FUNCTIONS[0]].update(section_index=0)),
        ('stale source hash refused', lambda d: d['source_sha256'].update({next(iter(contract['source_sha256'])): '0'*64})),
        ('different hardware refused', lambda d: d.update(HWID=1371)),
        ('address outside declared image refused', lambda d: d['symbols'][FUNCTIONS[0]].update(value=1)),
        ('boolean is not a numeric address', lambda d: d['symbols'][FUNCTIONS[0]].update(value=True)),
        ('wrong dictionary-name identity refused', lambda d: d['symbols'][FUNCTIONS[0]].update(name='other')),
        ('unaligned public table refused', lambda d: d['symbols'][TABLE].update(value=d['module_base']+257)),
    ]
    for label, mutate in mutations:
        candidate = copy.deepcopy(fixture); mutate(candidate)
        assert not check(candidate, contract)['metadata_contract_satisfied'], label
        cases.append(label)
    relocated = copy.deepcopy(fixture)
    for entry in relocated['symbols'].values():
        if entry['name'] in (*FUNCTIONS, TABLE):
            entry['value'] += 1500
    assert check(relocated, contract)['metadata_contract_satisfied']
    cases.append('relocated declarations do not require stale absolute addresses')
    bad_contract = copy.deepcopy(contract); bad_contract['required_functions'].pop()
    try:
        check(fixture, bad_contract)
    except ValueError:
        cases.append('contract cannot silently omit required controls')
    else:
        raise AssertionError('weakened contract accepted')
    with tempfile.TemporaryDirectory(prefix='garmin-json-guard-') as temp:
        p = Path(temp)/'duplicate.json'; p.write_text('{"symbols":{},"symbols":{}}')
        try:
            load_metadata(p)
        except ValueError:
            cases.append('duplicate metadata keys refused')
        else:
            raise AssertionError('duplicate key accepted')
        p = Path(temp)/'oversize.json.gz'; p.write_bytes(gzip.compress(b' '*(LIMIT+1)))
        try:
            load_metadata(p)
        except ValueError:
            cases.append('compressed expansion remains bounded')
        else:
            raise AssertionError('oversize accepted')
        try:
            load_metadata(Path(temp)/'unopened-native-file.bin')
        except ValueError:
            cases.append('binary paths refused before opening')
        else:
            raise AssertionError('binary path accepted')
    return {'host_controls_passed': len(cases), 'cases': cases,
            'positive_case_is_synthetic_metadata_only': True,
            'native_execution': False, 'device_IO': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--contract', required=True)
    parser.add_argument('--historical', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    contract, _ = load_metadata(args.contract)
    historical, _ = load_metadata(args.historical)
    result = run(contract, historical)
    with Path(args.output).open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps(result))
