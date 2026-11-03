#!/usr/bin/env python3
"""New FILE-only seal of the completed bounded JAI bridge; no CPU rerun."""
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(value, label):
    if not value:
        raise ValueError(label)


def main():
    source = OUT / 'analyze_jai_reader_bridge_v1.py'
    proof = OUT / 'original-JAI-record-to-packed-reader-bridge-proof-v1.json'
    fragments = OUT / 'original-JAI-record-to-reader-static-fragments-v1.json'
    receipt = OUT / 'JAI-reader-bridge-actual-terminal-tool-receipt-v1.json'
    seal = OUT / 'JAI-reader-bridge-file-seal-v1.json'
    ledger = OUT / 'JAI-reader-bridge-source-output-ledger-v1.json'
    need(not any(x.exists() for x in (receipt, seal, ledger)), 'new output only')
    j = json.loads(proof.read_text())
    need(j['all_bounded_checks_passed'], 'completed bounded proof')
    need(sha(source) == j['source_sha256'], 'completed source hash')
    need(sha(fragments) == j['static_fragments_sha256'], 'completed fragments hash')
    need(len(j['actual_partial_CPU_cases']) == 3 and j['totals']['full_function_returns'] == 0,
         'three partial CPU cases scope')
    for case in j['actual_partial_CPU_cases']:
        record = case['underlying_DB_scalar']['record']
        level, low_id, _ = case['actual_tuple_words']
        arguments = case['actual_original_reader_arguments']
        need(level == record >> 28 and low_id == record & 0x0FFFFFFF,
             'selected native split serialized readback')
        need(arguments['r1_one_based_lowID'] == low_id and arguments['r2_level'] == level,
             'selected actual native argument serialized readback')
        need(all(not p['full_function_return'] for p in case['phases']), 'no full-function claim')
        need(case['phases'][-1]['after']['GP16'][15] == 0x04421DD0,
             'actual endpoint before packed reader call')
        need(all(int(x['pc'], 16) != 0x044B10E4 for x in case['actual_instructions']),
             'old packed reader never executed')
        need(not case['native_SQL_result_stub'], 'no forced SQL success')
    now = datetime.now(timezone.utc).isoformat()
    receipt.write_text(json.dumps({
        'schema': 'actual-terminal-tool-receipt/JAI-reader-bridge/v1', 'created_utc': now,
        'actual_exit_code': 0, 'actual_completion_chunk_id': '2dabd9',
        'session_id': None, 'terminal': True,
        'command': 'python3 staging/navigation-stock-jai-reader-bridge-v1/analyze_jai_reader_bridge_v1.py',
        'source': str(source.relative_to(ROOT)), 'source_sha256': sha(source),
        'proof': str(proof.relative_to(ROOT)), 'proof_sha256': sha(proof),
        'original_partial_CPU_blocks': True, 'host_readonly_SQLite_scalars': 3,
        'native_full_SQL_query_or_UI': False, 'old_reader_rerun': False,
    }, ensure_ascii=False, indent=2) + '\n')
    files = [source, Path(__file__), proof, fragments, receipt]
    hashes = {str(x.relative_to(ROOT)): sha(x) for x in files}
    ledger.write_text(json.dumps({
        'schema': 'JAI-reader-bridge-source-output-ledger/v1', 'created_utc': now,
        'source_sha256': {k: v for k, v in hashes.items() if k.endswith('.py')},
        'output_sha256': {k: v for k, v in hashes.items() if not k.endswith('.py')},
        'file_bytes': {str(x.relative_to(ROOT)): x.stat().st_size for x in files},
        'old_full_MAIN_backup_or_suite_rehash': False,
    }, ensure_ascii=False, indent=2) + '\n')
    seal.write_text(json.dumps({
        'schema': 'JAI-reader-bridge-file-seal/v1', 'created_utc': now,
        'all_selected_new_file_checks_passed': True,
        'selected_new_sources_and_outputs': hashes,
        'ledger': str(ledger.relative_to(ROOT)), 'ledger_sha256': sha(ledger),
        'analysis_scope': j['totals'], 'sealer_FILE_ONLY': True,
        'sealer_original_CPU_execution': False, 'complete_native_query': False,
        'complete_constructor': False, 'bitreader_replayed': False,
        'physical_or_house184_update_proof': False,
        'canonical_MAP_or_DB_writes': False,
        'readback_scope': 'Selected new hashes, partial endpoint GP16, actual scalar-to-level/low28/reader arguments; not a complete instruction/store semantic verifier.',
    }, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'seal': str(seal.relative_to(ROOT)), 'seal_sha256': sha(seal),
                      'ledger_sha256': sha(ledger), 'receipt_sha256': sha(receipt),
                      'sealer_source_sha256': sha(Path(__file__)), 'files_sealed': len(files)},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
