#!/usr/bin/env python3
"""Seal only NEW finite MDR FILE evidence; no candidate/backup/old-suite rehash."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]


def main():
    out = BASE / 'navigation-MDR-finite-file-seal-v1.json'
    ledger_path = BASE / 'navigation-MDR-source-output-ledger-v1.json'
    assert not out.exists() and not ledger_path.exists()
    names = ['candidate-mdr-query-proof-v1.json', 'candidate-MDR-prefix-layout-review-v1.json',
             'candidate-mdr-Han-taxonomy-v1.json', 'candidate-mdr-suffix-neighborhoods-v1.json']
    results = {name:json.loads((BASE / name).read_text()) for name in names}
    assert all(row['all_passed'] for row in results.values())
    proof = results[names[0]]
    suffix = results[names[3]]
    assert len(suffix['actual_candidate_pairs_for_native_comparator']) == 8
    assert proof['target_reachability'] == {
        '民權路':{'mdr7_count':31,'Taichung_mdr20_count':4,'country_mdr22_count':31},
        '民和路一段':{'mdr7_count':2,'Taichung_mdr20_count':2,'country_mdr22_count':2},
        '民和路二段':{'mdr7_count':1,'Taichung_mdr20_count':1,'country_mdr22_count':1}}
    receipts = sorted(BASE.glob('*terminal-tool-receipt.json'))
    for receipt in receipts:
        row = json.loads(receipt.read_text())
        if 'source' in row:
            assert hashlib.sha256((ROOT / row['source']).read_bytes()).hexdigest() == row['source_sha256']
        assert row['actual_terminal_exit_code'] == (1 if receipt.name.startswith('official-source-fetch-v1') else 0)
    selected = sorted(p for p in BASE.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    ledger = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in selected}
    record = dict(all_passed=True, checked_utc=datetime.now(timezone.utc).isoformat(),
        scope='NEW finite host MDR record query, static prefix-layout review, Han taxonomy and56-row neighborhood selection. Self FILE seal, not independent VM or physical proof.',
        source_and_outputs_sha256=ledger,
        old_protected_4909_registry_or_suites_rehashed=False, whole_candidate_IMG_rehashed=False,
        full_backup_rehashed=False, canonical_or_candidate_changed=False, guest_execution=False,
        device_IO=False, candidate_compatibility_status='held_pending_native_order_and_physical_search',
        physical_installation_address_UI_routing_verified=False,
        rare_actual_candidate_pairs_native_executed_by_this_FILE_source=False,
        prior_failed_source_fetch_receipt_preserved=True)
    with ledger_path.open('x') as stream:
        stream.write(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    seal = dict(all_passed=True, checked_utc=record['checked_utc'],
        source_output_ledger=str(ledger_path.relative_to(ROOT)),
        source_output_ledger_sha256=hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        proofs={str((BASE / name).relative_to(ROOT)):ledger[str((BASE / name).relative_to(ROOT))] for name in names},
        ROOT_sealed_candidate_sha256=proof['candidate']['ROOT_sealed_sha256'],
        candidate_SHA_repeated=False, completed_MDR_query_source_not_rerun=True,
        target_reachability=proof['target_reachability'], native_pair_followup_count=8,
        full_MDR_dump_written=False, physical_UI_or_repair_success=False,
        canonical_edits=False, no_installation_or_old_scope_reexecution=True)
    with out.open('x') as stream:
        stream.write(json.dumps(seal, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=True, seal=str(out.relative_to(ROOT)),
        seal_sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
        ledger_sha256=hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        source_output_count=len(ledger), proofs=seal['proofs']), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
