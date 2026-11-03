#!/usr/bin/env python3
"""Check declared controller entries in JSON only; never read or run native code.

A passing result establishes a metadata prerequisite. It does not verify an ELF,
relocations, executable mode, runtime wiring, ownership, or installation safety.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

LIMIT = 262144
FUNCTIONS = (
    'umc_init', 'umc_request_start', 'umc_request_stop', 'umc_service',
    'umc_status_read', 'umc_admission', 'umc_runtime_ready',
    'umc_callback_acquire', 'umc_callback_release', 'umc_source_started',
    'umc_cleanup_returned', 'umc_kick',
)
TABLE = 'ui_music_control_api'
SOURCE_PATHS = (
    'native/ui-music-control-prototype/ui_music_control.c',
    'native/ui-music-control-prototype/ui_music_control.h',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_metadata(path):
    path = Path(path)
    if path.name.endswith('.json.gz'):
        with gzip.open(path, 'rb') as stream:
            raw = stream.read(LIMIT + 1)
    elif path.suffix == '.json':
        with path.open('rb') as stream:
            raw = stream.read(LIMIT + 1)
    else:
        raise ValueError('only JSON metadata is accepted')
    if len(raw) > LIMIT:
        raise ValueError('metadata size limit exceeded')
    result = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(result, dict):
        raise ValueError('top-level metadata must be an object')
    return result, digest(raw)


def is_int(value):
    return type(value) is int


def pin(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def check(manifest, contract):
    pins = contract.get('source_sha256')
    if (contract.get('schema') != 'garmin-controller-metadata-contract-v1'
            or contract.get('required_functions') != list(FUNCTIONS)
            or contract.get('table') != {'name': TABLE, 'type': 1, 'bytes': 36}
            or contract.get('target') != {'HWID': 1352, 'software': '8.00'}
            or not is_int(contract.get('target', {}).get('HWID'))
            or not is_int(contract.get('table', {}).get('type'))
            or not is_int(contract.get('table', {}).get('bytes'))
            or not isinstance(pins, dict) or set(pins) != set(SOURCE_PATHS)
            or not all(pin(v) for v in pins.values())):
        raise ValueError('invalid reviewed controller contract')
    errors = []
    for key, expected in contract['target'].items():
        if manifest.get(key) != expected or (key == 'HWID' and not is_int(manifest.get(key))):
            errors.append({'entry': key, 'reason': 'target mismatch'})
    if not pin(manifest.get('ELF_sha256')):
        errors.append({'entry': 'ELF_sha256', 'reason': 'missing declared image hash'})
    declared_pins = manifest.get('source_sha256', {})
    if not isinstance(declared_pins, dict):
        declared_pins = {}
    for path, expected in contract['source_sha256'].items():
        if declared_pins.get(path) != expected:
            errors.append({'entry': path, 'reason': 'source hash mismatch'})
    base, length = manifest.get('module_base'), manifest.get('combined_ram_bytes')
    bounds_ok = (is_int(base) and is_int(length) and 0 <= base < 2**32
                 and length > 0 and base + length <= 2**32)
    if not bounds_ok:
        errors.append({'entry': 'image bounds', 'reason': 'invalid declared RAM range'})
    symbols = manifest.get('symbols', {})
    if not isinstance(symbols, dict):
        symbols = {}
    present, missing = [], []
    for name in (*FUNCTIONS, TABLE):
        entry = symbols.get(name)
        if not isinstance(entry, dict):
            missing.append(name)
            errors.append({'entry': name, 'reason': 'absent symbol declaration'})
            continue
        present.append(name)
        expected_type = 1 if name == TABLE else 2  # STT_OBJECT versus STT_FUNC
        for key, expected in (('name', name), ('type', expected_type),
                              ('binding', 1), ('visibility', 0)):
            if entry.get(key) != expected or (key != 'name' and not is_int(entry.get(key))):
                errors.append({'entry': name, 'reason': 'wrong declared ' + key})
        section = entry.get('section_index')
        if not is_int(section) or not 0 < section < 0xff00:
            errors.append({'entry': name, 'reason': 'undefined or reserved section'})
        size, value = entry.get('size'), entry.get('value')
        if not is_int(size) or size <= 0 or (name == TABLE and size != 36):
            errors.append({'entry': name, 'reason': 'invalid declared size'})
        address_ok = is_int(value) and 0 <= value < 2**32
        if name == TABLE:
            address_ok = address_ok and value % 4 == 0
        elif address_ok:
            value &= ~1  # Normalize an optional Thumb bit without inferring code mode.
        if (not address_ok or not bounds_ok or not is_int(size) or size <= 0
                or not base <= value < value + size <= base + length):
            errors.append({'entry': name, 'reason': 'outside declared image range or misaligned table'})
    return {
        'metadata_contract_satisfied': not errors,
        'required_function_count': len(FUNCTIONS), 'required_table_count': 1,
        'declared_required_entries': present, 'missing_entries': missing, 'errors': errors,
        'scope': 'JSON declarations only; no binary read, build, or native execution',
        'fresh_ELF_verified': False, 'runtime_wiring_verified': False,
        'device_install_candidate': False, 'device_IO': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--contract', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    manifest, manifest_sha = load_metadata(args.manifest)
    contract, contract_sha = load_metadata(args.contract)
    result = check(manifest, contract)
    result.update(manifest_metadata_sha256=manifest_sha, contract_sha256=contract_sha)
    with Path(args.output).open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'metadata_contract_satisfied': result['metadata_contract_satisfied'],
                      'missing_entries': result['missing_entries'], 'output': args.output}))
    raise SystemExit(0 if result['metadata_contract_satisfied'] else 1)


if __name__ == '__main__':
    main()
