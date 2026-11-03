#!/usr/bin/env python3
"""Seal only this new bounded FILE-only namespace; never rerun the analysis."""
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    receipt = OUT / 'stock-fts-codec-actual-terminal-tool-receipts-v1.json'
    seal = OUT / 'stock-fts-codec-file-seal-v1.json'
    ledger = OUT / 'stock-fts-codec-source-output-ledger-v1.json'
    if any(path.exists() for path in (receipt, seal, ledger)):
        raise ValueError('new seal outputs only')
    codec_source = OUT / 'analyze_stock_fts_codec_v1.py'
    family_source = OUT / 'inspect_taichung_family_links_v2.py'
    codec_proof = OUT / 'stock-fts-token-codec-proof-v1.json'
    family_proof = OUT / 'stock-taichung-FTS-family-links-v2.json'
    fragments = OUT / 'stock-fts-token-codec-static-fragments-v1.json'
    first = json.loads(codec_proof.read_text())
    second = json.loads(family_proof.read_text())
    if not first['all_bounded_checks_passed'] or not second['all_bounded_checks_passed']:
        raise ValueError('bounded proofs must be completed')
    if sha(codec_source) != first['inputs']['source_sha256']:
        raise ValueError('frozen codec source hash')
    if sha(fragments) != first['inputs']['static_fragments_sha256']:
        raise ValueError('frozen fragments hash')
    if sha(family_source) != second['source_sha256']:
        raise ValueError('frozen family source hash')
    if sha(codec_proof) != second['inputs']['completed_codec_proof_sha256']:
        raise ValueError('frozen prior proof dependency')
    now = datetime.now(timezone.utc).isoformat()
    receipt_payload = {
        'schema': 'actual-terminal-tool-receipts/stock-fts-codec/v1',
        'created_utc': now, 'receipt_kind': 'actual exec_command completion records',
        'FILE_ONLY': True, 'native_execution': False,
        'terminals': [
            {'source': str(codec_source.relative_to(ROOT)),
             'source_sha256': sha(codec_source),
             'command': 'python3 staging/navigation-stock-fts-codec-v1/analyze_stock_fts_codec_v1.py',
             'actual_exit_code': 0, 'actual_completion_chunk_id': 'b1e934',
             'session_id': None, 'terminal': True,
             'output': str(codec_proof.relative_to(ROOT)),
             'output_sha256': sha(codec_proof)},
            {'source': str(family_source.relative_to(ROOT)),
             'source_sha256': sha(family_source),
             'command': 'python3 staging/navigation-stock-fts-codec-v1/inspect_taichung_family_links_v2.py',
             'actual_exit_code': 0, 'actual_completion_chunk_id': '8f68a5',
             'session_id': None, 'terminal': True,
             'output': str(family_proof.relative_to(ROOT)),
             'output_sha256': sha(family_proof)}],
        'earlier_bounded_observations': [
            {'actual_exit_code': 0, 'actual_completion_chunk_id': 'f5fb78',
             'scope': 'four exact infoIDs and three FTS1 content rows, read-only SQLite'},
            {'actual_exit_code': 0, 'actual_completion_chunk_id': 'b86c2f',
             'scope': 'initial host codec reconstruction, 22 city witnesses, no native execution'},
            {'actual_exit_code': 0, 'actual_completion_chunk_id': '77baaf',
             'scope': 'selected six Minquan keys / predecessor family parameter controls, read-only'}],
        'sealer_terminal_receipt': 'created separately after actual sealer terminal; not guessed here'}
    receipt.write_text(json.dumps(receipt_payload, ensure_ascii=False, indent=2) + '\n')
    files = [codec_source, family_source, Path(__file__), codec_proof, family_proof,
             fragments, OUT / 'REVIEW.txt', receipt]
    hashes = {str(path.relative_to(ROOT)): sha(path) for path in files}
    ledger_payload = {
        'schema': 'stock-fts-codec-source-output-ledger/v1', 'created_utc': now,
        'source_sha256': {key: value for key, value in hashes.items() if key.endswith('.py')},
        'output_sha256': {key: value for key, value in hashes.items() if not key.endswith('.py')},
        'new_namespace_file_bytes': {str(path.relative_to(ROOT)): path.stat().st_size
                                    for path in files},
        'old_backup_MAIN_DB_full_hashes_recomputed': False,
        'old_suite_or_native_guest_rerun': False}
    ledger.write_text(json.dumps(ledger_payload, ensure_ascii=False, indent=2) + '\n')
    seal_payload = {
        'schema': 'stock-fts-codec-file-seal/v1', 'created_utc': now,
        'all_selected_file_hash_checks_passed': True,
        'selected_new_sources_and_outputs': hashes,
        'source_output_ledger': str(ledger.relative_to(ROOT)),
        'source_output_ledger_sha256': sha(ledger),
        'scope': {'FILE_ONLY': True, 'host_codec_reconstruction': True,
                  'bounded_sqlite_ro_immutable_queries': True,
                  'native_instruction_or_query_execution': False,
                  'native_query_codepage_confirmed': False,
                  'native_family_consumer_verified': False,
                  '184_AP_payload_decoded': False, 'stock_map_update_implemented': False,
                  'device_or_canonical_writes': False,
                  'whole_old_sources_rehashed': False},
        'key_results': {'city_records': 22, 'Taichung_districts': 29,
                        'selected_street_witnesses': 9,
                        'stock_city_name': '台中市', 'central_Minquan_record': '0x30004143'},
        'limitations': 'Seal authenticates selected new files and their actual FILE receipts; it does not turn a host model into native/hardware query proof.'}
    seal.write_text(json.dumps(seal_payload, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'seal': str(seal.relative_to(ROOT)), 'seal_sha256': sha(seal),
                      'ledger': str(ledger.relative_to(ROOT)), 'ledger_sha256': sha(ledger),
                      'receipts': str(receipt.relative_to(ROOT)), 'receipts_sha256': sha(receipt),
                      'sealer_source_sha256': sha(Path(__file__)),
                      'files_sealed': len(files)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
