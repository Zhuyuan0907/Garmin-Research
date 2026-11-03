#!/usr/bin/env python3
"""FILE-only readback of the new plan. No prior analyzer/native source is imported."""
import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
INPUT = [
    'prepare_Minquan_append_plan_v1.py',
    'Minquan-append-only-record-plan-v1.json',
    'APPEND-PLAN-v1.txt',
    'append-plan-terminal-tool-receipt-v1.json',
]
OUTPUT = ['append-plan-FILE-readback-v1.json', 'append-plan-source-output-ledger-v1.json',
          'append-plan-file-seal-v1.json']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    assert not any((OUT / name).exists() for name in OUTPUT), 'Never overwrite/rerun a terminal sealer'
    raw = {name: (OUT / name).read_bytes() for name in INPUT}
    plan = json.loads(raw[INPUT[1]])
    receipt = json.loads(raw[INPUT[3]])
    checks = []

    def check(name, condition):
        checks.append({'check': name, 'passed': bool(condition)})
        assert condition, name

    tree = ast.parse(raw[INPUT[0]])
    imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imports |= {x.name for n in ast.walk(tree) if isinstance(n, ast.Import) for x in n.names}
    check('analyzer_does_not_import_VM_or_old_writer', imports <= {'__future__', 'hashlib', 'json', 're', 'struct', 'collections', 'datetime', 'decimal', 'pathlib'})
    check('actual_receipt_EXIT0', receipt['terminal'] and receipt['tool_result']['exit_code'] == 0
          and receipt['tool_result']['chunk_id'] == '2bdda4')
    check('source_hash_actual_receipt_match', sha(raw[INPUT[0]]) == receipt['source_sha256'] == plan['source']['sha256'])
    reported = json.loads(receipt['tool_result']['output'])
    check('proof_hash_actual_terminal_match', sha(raw[INPUT[1]]) == reported['proof_sha256'] and len(raw[INPUT[1]]) == reported['proof_bytes'])
    check('note_hash_actual_terminal_match', sha(raw[INPUT[2]]) == reported['note_sha256'])
    check('187_plan_checks_passed', len(plan['checks']) == reported['checks'] == 187
          and all(c['passed'] for c in plan['checks']) and plan['all_bounded_input_and_mathematical_checks_passed'])
    p = plan['record_ID_plan']
    check('new93_range_and1488bytes', p['new_street_range'] == [2133949, 2134041]
          and p['new_street_count'] == 93 and p['extra_records'] == 93 and p['extra_bytes'] == 93 * 16)
    check('street_actual_count12_vs_L4_count10', plan['street_patch_plan']['only_changed_fields']['+0C']['width'] == 12
          and plan['MDR_component_relocation_plan']['tables'][3]['widths'][5] == 10)
    tables = plan['MDR_component_relocation_plan']['tables']
    for t in tables:
        check('table_change_rule_level_' + str(t['level']), t['proposed_start'] == t['old_start'] + (1488 if t['level'] <= 3 else 0)
              and t['proposed_bytes'] == t['old_bytes'] + (1488 if t['level'] == 4 else 0)
              and not t['logical_IDs_of_existing_records_change'])
    ordered = sorted(tables, key=lambda t: t['proposed_start'])
    check('proposed_spans_remain_contiguous', all(a['proposed_start'] + a['proposed_bytes'] == b['proposed_start'] for a, b in zip(ordered, ordered[1:])))
    check('descriptor600_and_component_end', plan['MDR_component_relocation_plan']['header600_descriptor']['proposed_u32'] == [92654968, 120, 20, 1]
          and ordered[-1]['proposed_start'] + ordered[-1]['proposed_bytes'] == 92654968
          and plan['MDR_component_relocation_plan']['component_bytes']['proposed'] == 92655088)
    cap = plan['conditional_carrier_capacity']
    check('conditional_MDR_slack528', cap['MDR']['capacity'] - 92655088 == 528
          and not cap['spare_padding_contents_ownership_and_checksums_verified'])
    check('conditional_GMP_slack480', cap['GMP']['capacity'] - cap['GMP']['conditional_proposed_bytes'] == 480)
    lbl = plan['conditional_LBL_pool_plan']
    check('LBL_tail826_not_padding', lbl['move_unclassified_GMP_tail']['bytes'] == 826 and not lbl['tail826_bytes_are_proven_padding'])
    check('LBL72bytes_19bit_refs_only_provisional', lbl['pool_tail_insert_bytes'] == 72 and lbl['packed_reference_bits'] == 19
          and not lbl['provisional_references_assigned_to_actual_map']
          and not lbl['native_allocation_serializer_and_all_tail_pointer_fields_verified'])
    new = plan['nine_new_source_candidates']
    check('nine_explicit_candidates_only', [r['label'] for r in new] == ['6號', '8號', '138號', '140號', '142號', '144號', '146號', '148號', '150號']
          and all(r['explicit_source_city_district_street'] == ['臺中市', '中區', '民權路'] for r in new))
    check('literal_append_order_risk_explicit', plan['ordering_and_flags']['old84_then_new9_observed_numeric_inversions'] == [[216, 6]]
          and not plan['record_ID_plan']['mapping_or_order_finalized'])
    check('old84_descendants_and_flags_remain_exact', sum(plan['old84_preservation']['raw_flags_distribution'].values()) == 84
          and plan['old84_preservation']['raw_flags_distribution'] == {'0': 64, '5': 9, '6': 1, '8': 10}
          and len(plan['old84_preservation']['child_bearing_records']) == 10
          and not plan['old84_preservation']['level5_and_level6_spans_or_IDs_change'])
    check('JAI_same_name_and_identity_stays_scoped', not plan['JAI_index_assessment']['existing_city_district_street_FTS_and_family_rewrite_proposed']
          and not plan['JAI_index_assessment']['complete_native_house_query_or_hidden_auxiliary_index_requirements_verified'])
    check('no_original_IO_installation_or_whole_update_claim', not any(plan['scope_limits'].values())
          and not plan['answer']['ready_for_full_candidate_or_installation']
          and not plan['answer']['whole_Taiwan_2026_update_complete']
          and not plan['native_full_candidate_validation_passed'])
    review = {'schema': 'Minquan-append-plan-FILE-readback/v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
              'source': str(Path(__file__).relative_to(ROOT)), 'checks': checks,
              'all_FILE_readback_checks_passed': all(c['passed'] for c in checks),
              'original_metadata_inputs_fresh_rehashed_again': False,
              'original_IMG_DB_MAIN_or_native_guest_opened_or_rerun': False,
              'new_independent_native_verification_claimed': False,
              'candidate_or_whole_update_complete': False}
    ledger = {'schema': 'new-source-output-ledger/v1', 'source_sha256': {}, 'output_sha256': {},
              'new_analyzer_run_actual_chunk': receipt['tool_result']['chunk_id'],
              'frozen_input_hashes_once_by_new_analyzer': plan['dependencies'],
              'no_whole_backup_map_or_old_suite_rehash': True}
    for name in INPUT:
        target = 'source_sha256' if name.endswith('.py') else 'output_sha256'
        ledger[target][str((OUT / name).relative_to(ROOT))] = sha(raw[name])
    ledger['source_sha256'][str(Path(__file__).relative_to(ROOT))] = sha(Path(__file__).read_bytes())
    review_bytes = (json.dumps(review, ensure_ascii=False, indent=2) + '\n').encode()
    (OUT / OUTPUT[0]).write_bytes(review_bytes)
    ledger['output_sha256'][str((OUT / OUTPUT[0]).relative_to(ROOT))] = sha(review_bytes)
    ledger_bytes = (json.dumps(ledger, ensure_ascii=False, indent=2) + '\n').encode()
    (OUT / OUTPUT[1]).write_bytes(ledger_bytes)
    seal = {'schema': 'new-FILE-seal/v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
            'all_FILE_readback_checks_passed': True, 'scope': 'FILE readback of the new bounded metadata/arithmetic plan only.',
            'source_sha256': ledger['source_sha256'], 'output_sha256': {**ledger['output_sha256'],
                str((OUT / OUTPUT[1]).relative_to(ROOT)): sha(ledger_bytes)},
            'actual_sealer_terminal_receipt': 'separate post-seal receipt; this script cannot self-prove its terminal completion',
            'native_candidate_UI_or_physical_success': False}
    seal_bytes = (json.dumps(seal, ensure_ascii=False, indent=2) + '\n').encode()
    (OUT / OUTPUT[2]).write_bytes(seal_bytes)
    print(json.dumps({'all_FILE_readback_checks_passed': True, 'checks': len(checks), 'seal': str((OUT / OUTPUT[2]).relative_to(ROOT)),
                      'seal_sha256': sha(seal_bytes), 'review_sha256': sha(review_bytes), 'ledger_sha256': sha(ledger_bytes),
                      'candidate_or_whole_update_complete': False}))


if __name__ == '__main__':
    main()
