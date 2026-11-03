#!/usr/bin/env python3
"""New file-only selected trace/readback seal; never rerun native helpers."""
import gzip
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
    seal = OUT / 'native-fts-codec-file-seal-v1.json'
    ledger = OUT / 'native-fts-codec-source-output-ledger-v1.json'
    receipt = OUT / 'native-fts-codec-v2-terminal-tool-receipt.json'
    contract = OUT / 'native-fts-codec-input-scope-contract-v1.json'
    need(not any(p.exists() for p in (seal, ledger, receipt, contract)), 'new outputs only')
    proof = OUT / 'native-fts-token-codec-proof-v2.json'
    source = OUT / 'probe_native_fts_codec_v2.py'
    trace = OUT / 'native-fts-token-codec-trace-v2.json.gz'
    j = json.loads(proof.read_text())
    need(j['all_passed'] and sha(source) == j['source_sha256'], 'frozen actual source')
    need(sha(trace) == j['trace_sha256'], 'frozen actual trace')
    with gzip.open(trace, 'rt', encoding='utf-8') as stream:
        t = json.load(stream)
    totals = j['totals']
    need(len(t['original_instructions']) == totals['original_instructions'] == 18329,
         'actual instruction serialization count')
    need(len(t['actual_CPU_stores']) == totals['CPU_stores'] == 3756,
         'actual store serialization count')
    full = [x for x in t['actual_terminal_snapshots'] if x['full_original_function_return']]
    need(len(full) == 47, 'actual full terminal snapshot count')
    for row in full:
        before = row['before']['gp16']
        after = row['after']['gp16']
        need(len(before) == len(after) == 16, 'GP16 serialized')
        need(before[4:12] == after[4:12] and before[13] == after[13],
             'selected original callee-saved/SP file readback')
        need(after[15] == int(row['end'], 16) == 0x08D00000, 'actual helper return PC')
        need(row['after']['CPSR'] & 0x20, 'actual helper Thumb return')
    need(t['actual_terminal_snapshots'] == j['terminal_snapshots'],
         'trace/proof terminal agreement')
    for case in j['cases']:
        need(case['all_passed'] and case['actual_generated_token'] == case['frozen_DB_token'],
             'selected original native bytes match actual stock token')
        for unit in case['units']:
            need(unit['actual_input_hex'] == unit['actual_decoded_hex'],
                 'selected original decoder/encoder readback')
            need(bytes.fromhex(unit['actual_input_hex']).decode('utf-8') == unit['character'],
                 'selected actual plaintext UTF-8')
    now = datetime.now(timezone.utc).isoformat()
    receipt.write_text(json.dumps({
        'schema': 'actual-terminal-tool-receipt/native-fts-codec/v2',
        'created_utc': now, 'actual_exit_code': 0,
        'actual_completion_chunk_id': '8e7e5c', 'session_id': None, 'terminal': True,
        'command': 'python3 staging/navigation-stock-fts-native-codec-v1/probe_native_fts_codec_v2.py',
        'source': str(source.relative_to(ROOT)), 'source_sha256': sha(source),
        'proof': str(proof.relative_to(ROOT)), 'proof_sha256': sha(proof),
        'trace': str(trace.relative_to(ROOT)), 'trace_sha256': sha(trace),
        'native_helper_cases_passed': 3, 'no_native_UI_query_claim': True,
    }, ensure_ascii=False, indent=2) + '\n')
    contract.write_text(json.dumps({
        'schema': 'native-fts-codec-input-scope-contract/v1', 'created_utc': now,
        'actual_selected_helper_execution': True,
        'entry_points': j['input_contract'],
        'fixture_status': {
            'original_init_suffix': 'Starts0x04425B64 with r0=0 successful earlier-helper status and r4=0x09015000 synthetic object storage. Original suffix writes object+0x60 then emits identity/key bytes; preceding SQLite object constructor not executed.',
            'actual_original_KSA': 'Called0x04425AE8 with original-loop key buffer and original-loop identity table; no host-built scheduled context injected.',
            'actual_original_context_copy': 'Byte encoder and decoder execute original ARM memcpy3732C8 through veneer0448FE78; scheduled shared258-byte context remains unchanged.',
            'UTF8_handoff': 'Original iterator/current/converter generate actual bytes; a declared test caller copies these bytes into mutable encoder buffer between full helper calls. Complete044254C0 function is not executed.',
            'module_RAM': 'Mapped storage and stack are synthetic caller inputs; file-backed conditional MAIN code/data mapping is explicit and not live boot evidence.',
        },
        'selected_names': [x['name'] for x in j['cases']],
        'actual_totals': totals,
        'failed_attempt': 'V1 missed r4 object storage at suffix STR[r4+0x60] before any completed case; source/error/actual EXIT1 receipt preserved. V2 only supplies that declared caller storage.',
        'proved': ['Exact native CP65001 iterator/helper path for the eight selected Chinese units.',
                   'Exact original token encoder bytes match the selected original DB token strings.',
                   'Exact original token decoder bytes recover the selected helper-converted bytes.',
                   '47 actual original helper full returns include serialized GP16/SP/CPSR endpoints.'],
        'remaining_false': ['Full text encoder044254C0 allocator return / full provider constructor.',
                            'Address caller, keyboard preprocessing, Latin/nonBMP/malformed UTF8 controls.',
                            'Native family consumer / AP house184 payload / stock update writer / hardware UI query.',
                            'Independent complete instruction and CPU-store EA/value semantics verifier.'],
        'sealer_FILE_checks': 'Counts, selected stored ABI snapshots, proof/trace agreement, selected token/byte equality and new-file hashes. No VM/probe rerun and no old suite rerun.',
    }, ensure_ascii=False, indent=2) + '\n')
    files = [OUT / 'probe_native_fts_codec_v1.py',
             OUT / 'native-fts-token-codec-error-v1.json',
             OUT / 'native-fts-token-codec-v1-terminal-failure-receipt.json',
             source, proof, trace, Path(__file__), receipt, contract]
    hashes = {str(path.relative_to(ROOT)): sha(path) for path in files}
    ledger.write_text(json.dumps({
        'schema': 'native-fts-codec-source-output-ledger/v1', 'created_utc': now,
        'source_sha256': {k: v for k, v in hashes.items() if k.endswith('.py')},
        'output_sha256': {k: v for k, v in hashes.items() if not k.endswith('.py')},
        'file_bytes': {str(p.relative_to(ROOT)): p.stat().st_size for p in files},
        'prior_sources_proofs_and_suites_preserved': True,
        'old_MAIN_or_backup_full_rehash': False,
    }, ensure_ascii=False, indent=2) + '\n')
    seal.write_text(json.dumps({
        'schema': 'native-fts-codec-file-seal/v1', 'created_utc': now,
        'all_selected_file_checks_passed': True,
        'selected_new_sources_and_outputs': hashes,
        'ledger': str(ledger.relative_to(ROOT)), 'ledger_sha256': sha(ledger),
        'actual_native_helper_scope': totals,
        'native_helper_execution_receipt': str(receipt.relative_to(ROOT)),
        'sealer_FILE_ONLY': True, 'sealer_native_execution': False,
        'complete_instruction_store_semantics_verification': False,
        'UI_or_house_query_or_stock_update_proof': False,
        'old_MAIN_backup_full_hash_or_suite_rerun': False,
    }, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'seal': str(seal.relative_to(ROOT)), 'seal_sha256': sha(seal),
                      'ledger_sha256': sha(ledger), 'receipt_sha256': sha(receipt),
                      'contract_sha256': sha(contract), 'sealer_source_sha256': sha(Path(__file__)),
                      'files_sealed': len(files), 'FILE_ONLY': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
