#!/usr/bin/env python3
"""FILE-only seal; no import or rerun of writer/producer or original CPU."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    proof = OUT / 'native-record-writer-source-crosscheck-proof-v1.json'
    prototype = OUT / 'modern-Minquan-street-point-prototype-v1.json'
    payload = OUT / 'modern-Minquan-street-point-payload-v1.bin'
    source = OUT / 'verify_native_record_writer_v1.py'
    module = ROOT / 'scripts/native_address_records.py'
    receipt = OUT / 'writer-source-check-terminal-tool-receipt-v1.json'
    review = OUT / 'native-record-writer-FILE-readback-v1.json'
    ledger = OUT / 'native-record-writer-source-output-ledger-v1.json'
    seal = OUT / 'native-record-writer-file-seal-v1.json'
    need(not any(p.exists() for p in (receipt, review, ledger, seal)), 'new seal outputs only')
    need(sha(proof) == 'cee21c16cc1722b06a9395a410aaedf400709f66c2a927f881b6edbb83e6c062' and
         sha(prototype) == '01b793bd8ea6268529c05bd1769f586458dcb93283888fe640369362e1bc4cb7' and
         sha(payload) == 'dc4a2d6402c65749491d4122143cbc89e3c1137dcfa5189c1a00b52e2f236915',
         'completed source-check outputs')
    p, t = json.loads(proof.read_text()), json.loads(prototype.read_text())
    need(p['all_bounded_host_checks_passed'] and p['source_sha256'] == sha(source) and
         p['module_sha256'] == sha(module) and t['producer_source_sha256'] == sha(source) and
         t['module_sha256'] == sha(module), 'source/producer/module frozen identities')
    for case in p['original_native_source_cases']:
        mask = int.from_bytes(bytes.fromhex(case['used_bit_mask_16bytes_hex']), 'little')
        native = int.from_bytes(bytes.fromhex(case['source_readonly_16bytes_hex']), 'little')
        serialized = int.from_bytes(bytes.fromhex(case['serialized_zero_padded_16bytes_hex']), 'little')
        need(mask == ((1 << case['used_bits']) - 1) << case['initial_bit_offset'] and
             native & mask == serialized & mask and serialized & ~mask == 0,
             'original source used-bit independent FILE readback')
    need([x['complete_child_level_and_flags_preserved'] for x in p['original_native_source_cases']] ==
         [10, 3, 4, 6, 0], 'complete original child flags retained')
    need(len(p['required_rejection_controls']) == 12 and all(x['rejected'] for x in p['required_rejection_controls']),
         'actual producer rejection records')
    raw = payload.read_bytes()
    need(len(raw) == t['payload_bytes'] == 16 and raw.hex() == t['payload_hex'] and sha(payload) == t['payload_sha256'],
         'actual modern payload hash/readback')
    stream, cursor, values = int.from_bytes(raw, 'little'), t['initial_bit_offset'], {}
    for field in t['field_plan']:
        if field['enabled']:
            value = stream >> cursor & ((1 << field['width']) - 1)
            need(value == field['wire_value'], 'fresh prototype field FILE bit extraction')
            cursor += field['width']
        else:
            value = 0xFFFFFFFF if field['field'].endswith('_ref') else 0
        values[field['output_offset']] = value
    expected = bytes.fromhex(t['expected_native_output_32bytes_hex'])
    need(len(expected) == 32 and all(struct.unpack_from('<I', expected, i)[0] == values['+' + format(i, '02x')]
                                   for i in range(0, 32, 4)), 'explicit expected native output agrees with frozen serialization')
    need(cursor - t['initial_bit_offset'] == t['used_bits'] == 111 and
         t['record']['primary_ref'] == 206 and t['record']['child_level_and_flags'] == 4 and
         t['actual_original_house184_record_identity'] is False,
         'fresh street prototype scope')
    now = datetime.now(timezone.utc).isoformat()
    receipt.write_text(json.dumps({'schema': 'actual-terminal-tool-receipt/native-record-writer/v1',
        'created_utc': now, 'terminal': True, 'actual_exit_code': 0, 'actual_completion_chunk_id': '5d4077',
        'session_id': None, 'command': 'python3 staging/navigation-native-record-writer-v1/verify_native_record_writer_v1.py',
        'source': str(source.relative_to(ROOT)), 'source_sha256': sha(source),
        'proof': str(proof.relative_to(ROOT)), 'proof_sha256': sha(proof),
        'pure_offline_host_writer_scope': True, 'native_original_CPU_execution': False},
        ensure_ascii=False, indent=2) + '\n')
    review.write_text(json.dumps({'schema': 'native-record-writer-FILE-readback/v1', 'created_utc': now,
        'all_selected_FILE_checks_passed': True, 'FILE_ONLY': True,
        'original_source_used_bit_cases': 5, 'original_source_used_bits': 611,
        'full_child_level_and_flags_values': [10, 3, 4, 6, 0],
        'rejection_receipts': 12, 'fresh_payload_field_checks': 8,
        'independent_native_new_payload_execution': False,
        'same_function_encoder_decoder_roundtrip': False, 'writer_or_old_VM_or_original_CPU_rerun': False,
        'whole_IMG_MDR_JAI_or2026stock_update': False, 'stock_MAP_USB_canonical_writes': False,
        'scope': 'Selected fresh file identities, original source used-bit mask equality and independent fresh payload bit extraction/explicit expected-output coherence only.'},
        ensure_ascii=False, indent=2) + '\n')
    files = [module, source, Path(__file__), proof, prototype, payload, receipt, review]
    hashes = {str(x.relative_to(ROOT)): sha(x) for x in files}
    ledger.write_text(json.dumps({'schema': 'native-record-writer-source-output-ledger/v1', 'created_utc': now,
        'source_sha256': {k: v for k, v in hashes.items() if k.endswith('.py')},
        'output_sha256': {k: v for k, v in hashes.items() if not k.endswith('.py')},
        'dependencies': p['dependencies'], 'full_MAP_MAIN_backup_old_suite_rehash': False},
        ensure_ascii=False, indent=2) + '\n')
    seal.write_text(json.dumps({'schema': 'native-record-writer-file-seal/v1', 'created_utc': now,
        'all_selected_FILE_checks_passed': True, 'files': hashes,
        'ledger': str(ledger.relative_to(ROOT)), 'ledger_sha256': sha(ledger),
        'host_source_crosschecks': p['totals'], 'native_independent_new_payload_proof_pending': True,
        'whole_original_format_or2026address_update': False, 'installation_candidate': False,
        'old_proof_or_stock_or_canonical_modified': False}, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'seal': str(seal.relative_to(ROOT)), 'seal_sha256': sha(seal),
        'review_sha256': sha(review), 'ledger_sha256': sha(ledger), 'producer_actual_receipt_sha256': sha(receipt),
        'sealer_source_sha256': sha(Path(__file__)), 'files_sealed': len(files)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
