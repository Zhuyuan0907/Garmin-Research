#!/usr/bin/env python3
"""FILE-only verification and seal of a new isolated184 prototype."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(ok, name):
    if not ok:
        raise ValueError(name)


def main():
    source = OUT / 'prepare_house184_point_prototype_v1.py'
    prototype = OUT / 'modern-source-native-house184-point-prototype-v1.json'
    payload = OUT / 'modern-source-native-house184-point-payload-v1.bin'
    receipt = OUT / 'house184-prototype-terminal-tool-receipt-v1.json'
    review = OUT / 'house184-prototype-FILE-readback-v1.json'
    ledger = OUT / 'house184-prototype-source-output-ledger-v1.json'
    seal = OUT / 'house184-prototype-file-seal-v1.json'
    need(not any(x.exists() for x in (receipt, review, ledger, seal)), 'new output only')
    need(sha(prototype) == 'dcb61e8798cf9562f6ecdb7d0da1441ff8c193d96db37df22ff2db4a8dde66fa' and
         sha(payload) == '9d660ff2c9770a446e0a342f9b0e87c52db60e1b9209680f5c20151c99fd0a49',
         'completed new producer files')
    p = json.loads(prototype.read_text())
    need(p['source_sha256'] == sha(source) and p['all_new_bounded_host_checks_passed'] and
         p['module_sha256'] == '8dfec0a03795e29fc223fbd06f0418536b6f3969024083b5023e25620319eb33',
         'frozen producer/module reference')
    raw, old = payload.read_bytes(), bytes.fromhex(p['one_new_original_source_crosscheck']['source_payload_hex'])
    need(len(raw) == len(old) == 16 and p['one_new_original_source_crosscheck']['serialized_original_payload_hex'] == old.hex(),
         'selected original184 exact source witness')
    value, oldvalue = int.from_bytes(raw, 'little'), int.from_bytes(old, 'little')
    mask = (1 << 80) - 1
    need(value & mask == oldvalue & mask, 'all first80 reference/map/child/flag bits unchanged')
    decoded, cursor = [], 0
    for width in (1, 19, 19, 22, 10, 9, 24, 24):
        decoded.append(value >> cursor & ((1 << width) - 1))
        cursor += width
    need(decoded == [1, (1 << 19) - 1, 808, 0, 0, 0, 1125125, 5623857] and cursor == 128,
         'independent FILE bit extraction of every fresh field')
    expected = struct.pack('<8I', 0, 0, 1, 0, 808, 1125125, 5623857, 0xFFFFFFFF)
    need(expected.hex() == p['expected_native_output_32bytes_hex'], 'explicit sentinel-normalized output coherence')
    need(p['raw24_delta_from_original'] == [3, 3] and
         (oldvalue >> 80 & 0xFFFFFF, oldvalue >> 104 & 0xFFFFFF) == (1125122, 5623854),
         'only the two point fields changed')
    need(p['original184_native_CPU_identity_verified_here'] is False and
         p['OSM_node_equated_with_stock_record_identity'] is False and p['installable'] is False,
         'explicit limited prototype scope')
    now = datetime.now(timezone.utc).isoformat()
    receipt.write_text(json.dumps({'schema': 'actual-terminal-tool-receipt/house184-prototype/v1',
        'created_utc': now, 'terminal': True, 'actual_exit_code': 0, 'actual_completion_chunk_id': 'c893d6',
        'session_id': None, 'command': 'python3 staging/navigation-native-record-house184-prototype-v1/prepare_house184_point_prototype_v1.py',
        'source': str(source.relative_to(ROOT)), 'source_sha256': sha(source),
        'prototype': str(prototype.relative_to(ROOT)), 'prototype_sha256': sha(prototype),
        'new_host_producer_only': True, 'old5cases_or12controls_or_VM_rerun': False},
        ensure_ascii=False, indent=2) + '\n')
    review.write_text(json.dumps({'schema': 'house184-prototype-FILE-readback/v1', 'created_utc': now,
        'all_selected_FILE_checks_passed': True, 'FILE_ONLY': True, 'independent_new_payload_field_checks': 8,
        'preserved_first80_bits': True, 'original_source128bit_exact_crosscheck_readback': True,
        'raw24_delta': [3, 3], 'sentinel_wire19bits': (1 << 19) - 1, 'sentinel_native_u32': 0xFFFFFFFF,
        'independent_native_new_payload_executed': False,
        'stock_record_equated_with_OSM_node_identity': False, 'whole2026stock_update': False,
        'native_CPU_or_old_suites_or_IMG_device_reads': False, 'canonical_or_stock_writes': False},
        ensure_ascii=False, indent=2) + '\n')
    files = [source, Path(__file__), prototype, payload, receipt, review]
    hashes = {str(x.relative_to(ROOT)): sha(x) for x in files}
    ledger.write_text(json.dumps({'schema': 'house184-prototype-source-output-ledger/v1', 'created_utc': now,
        'source_sha256': {k: v for k, v in hashes.items() if k.endswith('.py')},
        'output_sha256': {k: v for k, v in hashes.items() if not k.endswith('.py')},
        'inherited_frozen_writer_module': {'path': 'scripts/native_address_records.py', 'sha256': p['module_sha256']},
        'dependencies': p['dependencies'], 'old_large_sources_rehashed': False},
        ensure_ascii=False, indent=2) + '\n')
    seal.write_text(json.dumps({'schema': 'house184-prototype-file-seal/v1', 'created_utc': now,
        'all_selected_FILE_checks_passed': True, 'files': hashes,
        'ledger': str(ledger.relative_to(ROOT)), 'ledger_sha256': sha(ledger),
        'native_independent_new_payload_proof_pending': True, 'whole2026stock_update': False,
        'installable': False, 'old_proofs_or_stock_or_canonicals_modified': False},
        ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'seal': str(seal.relative_to(ROOT)), 'seal_sha256': sha(seal),
        'review_sha256': sha(review), 'ledger_sha256': sha(ledger), 'actual_producer_receipt_sha256': sha(receipt),
        'sealer_source_sha256': sha(Path(__file__))}, ensure_ascii=False))


if __name__ == '__main__':
    main()
