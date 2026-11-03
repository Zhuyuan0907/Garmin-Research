#!/usr/bin/env python3
"""New-output normal-file audit and held-frontier hash seal; no IMG/gzip I/O."""
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
BASE = ROOT / 'staging/navigation-v2-one-family-lane-delta-plan-v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(name, value):
    (BASE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    assert not (BASE / 'SEAL.json').exists()
    source = json.loads((BASE / 'proof.json').read_text())
    target = json.loads((BASE / 'selected-original-source.json').read_text())
    actual = json.loads((BASE / 'actual-profile-parent-proof.json').read_text())
    assert source['failed_gate_holds'] == ['floor_unit_absent']
    assert target['complete_original_prepared_group']['separate_floor_unit_nodes'] == 20
    assert target['complete_original_prepared_group']['source_node_count'] == len(target['source_node_IDs']) == 21
    assert target['complete_original_prepared_group']['raw_address'][0] == '臺中市'
    assert target['raw_parent'] + target['raw_lane_suffix'] + target['raw_alley_suffix'] == target['original_raw_address'][2]
    assert actual['actual_IMG_read_bytes'] == sum(x['bytes'] for x in actual['actual_read_journal']) == 143664
    assert actual['actual_IMG_read_bytes'] <= 2 * 1024 * 1024
    parent_views = {}
    for tag in ['v2', 'v3']:
        r = actual['results'][tag]
        raw = (BASE / (tag + '-actual120-directory.bin')).read_bytes()
        assert len(raw) == 120 and sha(raw) == r['DIR_SHA256'] and raw.hex() == r['DIR_hex']
        h = (BASE / (tag + '-actual512-header.bin')).read_bytes()
        assert len(h) == 512 and sha(h) == r['AP_header_SHA256'] and h.hex() == r['raw_AP_header_hex']
        l3 = r['actual_tables']['3']
        assert (l3['widths'][0], l3['stride']) == (23, 112)
        p = r['exact_parent_record']
        assert p['record'] == 805319491 and p['ID'] == 13123 and p['label'] == '昌平路二段'
        assert p['label_ref_actual'] == 24559 and p['child_count'] == 594 and p['next_level'] == 4
        parent_views[tag] = p
    v2, v3 = parent_views['v2'], parent_views['v3']
    first_offset, first_width = 20, 23
    mask = ((1 << first_width) - 1) << first_offset
    assert v2['raw_record_value'] & ~mask == v3['raw_record_value'] & ~mask
    assert (v2['raw_record_value'] >> first_offset & ((1 << first_width) - 1)) == v2['first_child']
    assert (v3['raw_record_value'] >> first_offset & ((1 << first_width) - 1)) == v3['first_child']
    assert (v2['first_child'], v3['first_child']) == (2553254, 4175477)
    old_dir = ROOT / 'staging/navigation-country-native-lane-independent-review-v3'
    old_seal_path = old_dir / 'sealed-files.json'
    old_seal_raw = old_seal_path.read_bytes()
    old_seal = json.loads(old_seal_raw)
    proof_path = old_dir / 'proof.json'
    old_pin = next(x for x in old_seal['files'] if x['path'] == str(proof_path.relative_to(ROOT)))
    old_raw = proof_path.read_bytes()
    assert len(old_raw) == old_pin['bytes'] and sha(old_raw) == old_pin['sha256']
    existing = json.loads(old_raw)
    assert existing['all_assigned_checks_passed'] and existing['counts']['actual_new_house_leaves'] == 58233
    inherited = {'ordinary_JSON_proof_path': str(proof_path.relative_to(ROOT)),
        'proof_bytes': len(old_raw), 'proof_SHA256': sha(old_raw),
        'seal_path': str(old_seal_path.relative_to(ROOT)), 'seal_bytes': len(old_seal_raw),
        'seal_SHA256': sha(old_seal_raw), 'existing_actual_v3_house_leaves': 58233,
        'existing_actual_complete_house_parent_paths': existing['counts']['actual_complete_house_parent_paths'],
        'old_reader_or_sweep_not_reexecuted': True, 'old_artifact_data_gzip_not_opened': True,
        'claim_scope': 'Existing completed ordinary v3 tree readback already demonstrates lane/alley format; this scope never claims that lossless sidecar is its missing replacement.'}
    write('existing-v3-format-proof-pin.json', inherited)
    receipts = [
        {'actual_tool': 'exec_command', 'terminal_chunk_id': '57b554', 'exit_code': 0,
         'wall_time_seconds': 0.000020241,
         'command': 'python3 staging/navigation-v2-one-family-lane-delta-plan-v1/check_source_gate_v2.py',
         'executed_source_SHA256': sha((BASE / 'check_source_gate_v2.py').read_bytes()),
         'observed_result': 'held_before_IMG_family_planning; separate_floor_unit_nodes20/21; IDs and coords ready',
         'saved_capture_compressed_bytes': 18867, 'IMG_bytes_in_this_command': 0},
        {'actual_tool': 'exec_command', 'terminal_chunk_id': 'b8c780', 'exit_code': 0,
         'wall_time_seconds': 0.000021926,
         'command': 'python3 staging/navigation-v2-one-family-lane-delta-plan-v1/read_exact_profile_parent_v1.py',
         'executed_source_SHA256': sha((BASE / 'read_exact_profile_parent_v1.py').read_bytes()),
         'observed_result': 'actual_DIR_and_exact_parent_checked_source_still_held',
         'actual_IMG_bytes': 143664, 'actual_physical_read_operations': 18,
         'both_L3_first_width': 23, 'both_L3_stride': 112,
         'actual_v2_DIR_SHA256': actual['results']['v2']['DIR_SHA256'],
         'actual_v3_DIR_SHA256': actual['results']['v3']['DIR_SHA256'],
         'target_house_lookup_or_subtree_traversal': False},
    ]
    write('actual-normal-file-receipts.json', {'receipts': receipts,
        'failed_first_source_command_receipt': 'failed-source-gate-v1-receipt.json',
        'first_guard_failure_later_identified': 'Original raw city literal is臺中市; the failed v1 assumed台中市. Original failed source and city literal remain unchanged.',
        'counter_scope': 'Named executed source/metadata commands. Preparatory normal-JSON/code inspections and new-output seal audit are separate normal-file operations.'})
    a2 = actual['results']['v2']
    counts = a2['actual_tables']
    root_only_arithmetic = {'hypothesis_not_a_completed_family_plan': 'If all594 actual v3 root L4 children were cloned under current v2.',
        'old_v2_L4_count': counts['4']['count'], 'hypothetical_new_L4_first': counts['4']['count'] + 1,
        'observed_root_L4_child_count': 594,
        'hypothetical_L4_count_only': counts['4']['count'] + 594,
        'hypothetical_L4_payload_bytes_only': 594 * 128 // 8,
        'L3_23bit_first_child_max': (1 << 23) - 1, 'L3_12bit_child_count_max': (1 << 12) - 1,
        'complete_L5_L6_counts_remap_and_payload': None,
        'actual_current_v2_physical_bytes': a2['physical_IMG_bytes'],
        'actual_current_v2_capacity_declaration_bytes': a2['capacity_declaration_bytes'],
        'current_declared_minus_physical_bytes_arithmetic': a2['capacity_declaration_bytes'] - a2['physical_IMG_bytes'],
        'future_IMG_bytes_FAT_metadata_growth_and_capacity_acceptance': None,
        'same_profile_and_pointer_arithmetic_are_not_a_road_fix_or_installable_result': True}
    frontier = {'schema': 'source-held-before-complete-family-clone-plan/v1',
        'source_gate': source['gates'], 'precise_hold': 'separate_floor_unit_nodes=20 of21 source nodes',
        'sourcepoint': source['sourcepoint'], 'native24': source['native24'],
        'exact_parent_stock_and_actual_L3_record': 805319491, 'L3_ID': 13123,
        'actual_parent_ranges': {tag: {'level': 4, 'first': p['first_child'], 'count': 594,
            'last': p['first_child'] + 593, 'primary_label_ref': 24559,
            'CP950_hex': p['label_CP950_hex'], 'raw_flags': p['raw_flags']} for tag,p in parent_views.items()},
        'actual_parent_record_outside_first_child_bits_identical': True,
        'first_child_proven_bit_offset_width': [first_offset, first_width],
        'actual_v3_same_coordinate39_house_match': None,
        'selected_L4_L5_L6_subtree_traversal': 0,
        'cloned_complete_family_payload_or_ID_remap': None,
        'new_actual_record_ID_or_labelref_allocations': 0,
        'rawbit_preservation_and_wholebit_splice_requirements': [
            'Later complete family clone must retain all raw flags/coordinates/labels and patch only proven first_child/count fields.',
            'Current lower table valid bits must be retained; L5 stride126 gives cross-byte/tail shifts, so padded-record concatenation is invalid.',
            'Current v2 L3 profile23/112 must remain; original stock22/111 is not the current profile.',
            'Whole4K original header/capacity134217728/CHS must remain for a future minimal writer, requiring exact metadata growth accounting before any full output.'],
        'root_capacity_arithmetic_only': root_only_arithmetic,
        'next_minimum_missing_evidence': 'Ready per-node house/floor policy and original metadata must resolve the20 floor/unit nodes without collapsing or choosing a guessed base node; then exact v3 house label plus same raw24 coordinate and complete594-root-child L4/L5/L6 subtree can be bounded-read. This scope does not request or perform that new source/tree work.',
        'actual_family_delta_plan_complete': False, 'v3_failure_cause_proved': False,
        'source_read_or_IMG_work_continued_after_hold_and_metadata_boundary': False}
    write('held-remap-frontier.json', frontier)
    closure = {'schema': 'ordinary-source-and-bounded-v2-v3-profile-held-scope/v1',
        'assigned_file_checks_completed': True, 'complete_family_delta_plan': False,
        'status': 'sealed_held_source_floor_unit_gate;actual_profile_and_parent_metadata_only',
        'source_group': 172188, 'source_complete_node_ID_count': 21,
        'separate_floor_unit_nodes': 20, 'source_coordinates_and_IDs_ready': True,
        'sourcepoint': source['sourcepoint'], 'native24': source['native24'],
        'exact_parent_L3_ID': 13123, 'exact_parent_record': 805319491,
        'actual_parent_labelref': 24559, 'actual_root_child_count_both': 594,
        'source_gate_proof': 'proof.json', 'actual_bounded_IMG_proof': 'actual-profile-parent-proof.json',
        'frontier': 'held-remap-frontier.json', 'existing_v3_format': inherited,
        'profile_errata': actual['errata'],
        'actual_IMG_bytes': 143664, 'actual_IMG_reads': 18, 'IMG_budget_bytes': 2097152,
        'saved_capture_read_attempts': 2, 'saved_capture_compressed_bytes_across_two_attempts': 37734,
        'saved_capture_decompressed_bytes_across_two_attempts': 767842,
        'source_single_pass_claimed': False, 'full_original_groups_gzip_PBF_or_ledger_bytes': 0,
        'source_floor_held_and_target_house_not_matched': True,
        'tree_records_traversed': 0, 'native_CPU_instructions': 0, 'compile_commands': 0,
        'audio_or_device_IO': 0, 'new_full_IMG_installer_or_public_bundle': False,
        'new_payloads_recordIDs_labelrefs': 0, 'old_seals_sources_or_device_modified': False,
        'all_claim_flags_false': source['flags'],
        'failed_first_guard_source_and_receipt_preserved': True,
        'raw_source_city_臺_not_replaced_by_normalized_key_台': True,
        'new_output_readback': {'directories_120bytes_each': True, 'headers_512bytes_each': True,
            'all_saved_SHA_bytes_and_raw_hex_exact': True,
            'actual_parent_full_rawbits_except_first_child_equal': True},
        'seal_kind': 'hash/size/actual-stat; no chmod', 'seal_then_stop': True}
    write('scope-proof.json', closure)
    handoff = f'''# navigation-v2-one-family-lane-delta-plan-v1 HANDOFF

結果為sealed held/frontier，不是complete family plan。Source172188的完整prepared metadata與21 node IDs已由18867B saved capture真讀出；原literal為臺中市／北屯區／昌平路二段50之6巷2弄／39號，rawpoint{source['sourcepoint']}、native24{source['native24']}。different_coordinate_nodes0、coordinate_selection_ready=true、embedded_floor_unit=false，但separate_floor_unit_nodes20，因此source floor gate未ready，不能挑一個node假當base39號。

Actual source check57b554 EXIT0。首次2dfd3c EXIT1只因我預設city台中市而原raw為臺中市，failedsource與receipt保存；新v2source保持臺原字，允許兩city寫法以核對literal，沒有替換street／house／city或nearest。Saved capture共兩次明示讀18867B，各解383921B；不是singlepass。原137MB source／PBF／fullnodeledger都0。

Actual普通FILE reader b8c780 EXIT0，共143664 IMG bytes／18 physical reads，小於2097152；無CPU／guest。每圖都真讀120B MDR DIR：v2 SHA{actual['results']['v2']['DIR_SHA256']}，v3 SHA{actual['results']['v3']['DIR_SHA256']}。MDR actual v2 {a2['MDR_bytes']}B／v3 {actual['results']['v3']['MDR_bytes']}B。完整six-level actual descriptors、120B raw與512B APheader保存，原stats在讀取前後一致，wholeIMG hash只繼承原seal不重算。

重要profile更正：current-v2與v3的L3都23-bit first-child／112-bit stride；原stock才22／111。舊parent任務誤把stock當current，已在新scope errata保存；沒有shrink或global width改動，也不把L4總數跨2^22當v3 bug原因。

原stock exact parent昌平路二段：info13188，record805319491／L3 ID13123。Actual v2/v3 labelref均24559、CP950 a9f7a5adb8f4a447ac71，raw flags均4；v2 L4 first2553254..2553847、v3 first4175477..4176070，count均594。整個112-bit parent record除first-child bits[20,43)外一致，沒有修改原bytes。

Source floor hold後，selected L4/L5/L6 traversal0，exact v3 same-coordinates39號house未查（unknown，不是absent），complete cloned subtree／remap／append bins／new IMG counts及整體容量均未完成。只給條件式root算術：若clone594 L4則新增9504B、L4 first3781595/count後3782188，23-bit ptr與12-bit count能表示；L5/L6 descendants及其wholebit shifts、FAT growth、finalIMG容量未知，不能由此放行。Currentv2 physical128356352B、whole4K declaration134217728B；原header／CHS／圖檔完全未寫。

原v3有58233巷弄house的complete native-tree普通FILE讀回證據已存在（existing-v3-format-proof-pin.json）；lossless sidecar不是尚無巷弄格式的證明或代替。後續writer若來源ready必clone完整family rawbits、保留labels/GMP、只patch已證first/count，current L5 stride126與2尾padding需wholebit splice／crossbyte，不能逐record padded串接。此scope沒有執行任何writer。

最小missing：需能保持per-node floor/house metadata的policy解除本group20 floor-unit nodes，不能lossy忽略之號／樓層或任選base節點；再查exact v3 full path／house label／raw24與完整594根child子樹，才可完成remap與容量。沒有擴來源或要求裝置。

所有source-release／family-plan／v3fix／install／App／backend-owner／STOP_DONE／phone／speaker／fullTaiwan flagsfalse。failed source、source proof／complete target、actual FILE journal／headers／DIR／parent proof、errata／frontier／receipts一併hash-size-stat封存；無chmod，不改oldseal。scope-proof.json是總結；proof.json只代表source-gate當時IMG0的phase，兩者不混淆。Seal後停止。
'''
    (BASE / 'HANDOFF.md').write_text(handoff)
    files = []
    for p in sorted(BASE.iterdir()):
        if p.name in ['SEAL.json', 'post-seal-tool-receipt.json']:
            continue
        assert p.is_file()
        s = p.stat()
        raw = p.read_bytes()
        files.append({'path': str(p.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw),
            'mode_octal': oct(s.st_mode & 0o777), 'device': s.st_dev, 'inode': s.st_ino,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns})
    seal = {'schema': 'hash-size-observed-stat-seal/v1', 'files': files,
        'self_and_post_terminal_receipt_excluded': True, 'old_sources_modified': False,
        'chmod_performed': False, 'source_held': True, 'family_plan_complete': False,
        'actual_IMG_byte_budget_respected': True, 'native_CPU_or_device_audio': False,
        'seal_then_stop': True}
    raw = (json.dumps(seal, ensure_ascii=False, indent=2) + '\n').encode()
    (BASE / 'SEAL.json').write_bytes(raw)
    print(json.dumps({'status': 'held_source_floor_gate_and_actual_profile_parent_sealed', 'files': len(files),
        'scope_proof_SHA256': sha((BASE / 'scope-proof.json').read_bytes()), 'seal_SHA256': sha(raw),
        'actual_IMG_bytes': 143664, 'family_plan_complete': False, 'source_released': False,
        'both_L3_first_width_stride': [23,112], 'stop_after_seal': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
