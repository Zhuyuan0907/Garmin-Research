#!/usr/bin/env python3
"""Ordinary JSON-only lossless name views; no source gzip, map or device I/O."""
import collections
import copy
import hashlib
import json
import re
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-beitun-lossless-name-branch-plan-v1'
CAP = 'staging/navigation-beitun-source-capture-corrected-v1'
INPUTS = {
    'mapping': (CAP + '/hold-mapping.json', '800f5e59076b45159c395b913e7303dc4b2dbc6564f20a3aa0570c5b6c18aca5'),
    'examples': (CAP + '/planning-examples.json', '738481f7020f9c1877a9cc96f34e772ff90b6d769f9a7a5ad0d67047947be68a'),
    'stock': ('staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json', '929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6'),
}
FLAT = re.compile(r'(?P<base>[\u3400-\u9fffA-Za-z0-9·．]+?[路街])(?P<section>[一二三四五六七八九十百0-9]+段)?\Z')
BRANCH = re.compile(r'(?P<parent>[\u3400-\u9fffA-Za-z0-9·．]+?[路街](?:[一二三四五六七八九十百0-9]+段)?)(?P<lane>[^\s巷弄]+巷)(?P<alley>[^\s巷弄]+弄)?\Z')
ALLEY = re.compile(r'(?P<parent>[\u3400-\u9fffA-Za-z0-9·．]+?[路街](?:[一二三四五六七八九十百0-9]+段)?)(?P<alley>[^\s巷弄]+弄)\Z')
SECTION = re.compile(r'(?P<base>.+[路街])(?P<digits>[1-9][0-9]*)段\Z')
DIGITS = '零一二三四五六七八九'


def stat_fields(p):
    s = p.stat()
    return {'device': s.st_dev, 'inode': s.st_ino, 'bytes': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns,
            'mode_octal': oct(s.st_mode & 0o777)}


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def chinese_section(n):
    # This finite writing rule is deliberately restricted to 1..99 sections.
    assert 1 <= n <= 99
    if n < 10:
        return DIGITS[n]
    tens, units = divmod(n, 10)
    return (DIGITS[tens] if tens != 1 else '') + '十' + (DIGITS[units] if units else '')


def encoded(s):
    try:
        b = s.encode('cp950')
        return {'CP950_roundtrip': b.decode('cp950') == s, 'bytes': len(b), 'hex': b.hex()}
    except UnicodeError:
        return {'CP950_roundtrip': False, 'bytes': None, 'hex': None}


def stock_ref(row):
    return {'stock_label': row['label'], 'stock_info_id': row['info_id'],
            'stock_record': row['record'], 'stock_index_token': row['index_record'],
            'existing_stock_reference_only': True, 'same_road_or_alias_verified': False}


def section_view(raw, stock):
    m = SECTION.fullmatch(raw)
    if not m:
        return None
    n = int(m['digits'])
    if not 1 <= n <= 99:
        return {'original_literal': raw, 'refusal': 'section_number_outside_declared_1_to_99_rule'}
    replacement = chinese_section(n)
    candidate = m['base'] + replacement + '段'
    return {'original_literal': raw, 'raw_base': m['base'], 'raw_section_digits': m['digits'],
            'raw_section_suffix': '段', 'writing_candidate': candidate,
            'chinese_section_candidate_token': replacement + '段',
            'exact_stock_match': stock_ref(stock[candidate]) if candidate in stock else None,
            'literal_reconstruction': m['base'] + m['digits'] + '段',
            'candidate_only': True, 'automatic_replacement_permitted': False,
            'same_road_or_alias_verified': False}


def name_view(raw, stock):
    # A locality prefix is a candidate only with an EXISTING EXACT entire suffix.
    admin = []
    for suffix, row in stock.items():
        if raw != suffix and raw.endswith(suffix):
            prefix = raw[:-len(suffix)]
            if re.fullmatch(r'[\u3400-\u9fff]+(?:區|里)', prefix):
                admin.append({'raw_prefix': prefix, 'unchanged_suffix': suffix,
                              'exact_stock_suffix': stock_ref(row),
                              'literal_reconstruction': prefix + suffix,
                              'official_locality_prefix_verified': False})
    if admin:
        return {'class': 'held_existing_exact_suffix_locality_prefix',
                'raw_literal': raw, 'locality_prefix_candidates': admin,
                'literal_reconstruction': raw,
                'classification_hold_reasons': ['locality_prefix_interpretation_unverified',
                                                'entire_prefixed_literal_not_a_confirmed_flat_street']}
    m = BRANCH.fullmatch(raw) or ALLEY.fullmatch(raw)
    if m:
        raw_parent = m['parent']
        lane = m.groupdict().get('lane') or ''
        alley = m.groupdict().get('alley') or ''
        suffix = lane + alley
        assert raw_parent + suffix == raw
        exact = stock_ref(stock[raw_parent]) if raw_parent in stock else None
        writing = section_view(raw_parent, stock)
        candidate_parent = writing and writing.get('exact_stock_match')
        if exact:
            kind = 'held_branch_existing_exact_parent'
            holds = ['branch_representation_not_validated']
        elif candidate_parent:
            kind = 'held_branch_section_writing_candidate_parent'
            holds = ['raw_parent_absent_from_stock', 'section_parent_same_road_unverified',
                     'branch_representation_not_validated']
        else:
            kind = 'held_branch_no_existing_exact_parent'
            holds = ['raw_parent_absent_from_stock', 'cannot_assign_section_or_strip_prefix']
        if '之' in suffix:
            holds.append('lane_or_alley_subnumber_representation_unverified')
        prefix_note = None
        pm = re.match(r'(?P<prefix>北屯區)(?P<suffix>.+)\Z', raw)
        if pm:
            prefix_note = {'raw_prefix_seen': pm['prefix'], 'entire_unchanged_suffix': pm['suffix'],
                           'entire_suffix_exact_stock_match': pm['suffix'] in stock,
                           'prefix_removal_candidate_admitted': False,
                           'reason': 'entire_suffix_has_no_existing_exact_stock_name'}
            assert pm['suffix'] not in stock
        return {'class': kind, 'raw_literal': raw, 'raw_parent_literal': raw_parent,
                'existing_exact_parent': exact, 'parent_section_writing_candidate': writing,
                'raw_lane_suffix': lane, 'raw_alley_suffix': alley,
                'raw_complete_branch_suffix': suffix,
                'lane_token': lane[:-1] if lane else None,
                'alley_token': alley[:-1] if alley else None,
                'literal_reconstruction': raw_parent + lane + alley,
                'prefix_exact_suffix_gate_note': prefix_note,
                'classification_hold_reasons': holds}
    m = FLAT.fullmatch(raw)
    if m:
        writing = section_view(raw, stock)
        return {'class': 'held_flat_section_writing_candidate' if writing else 'held_flat_literal',
                'raw_literal': raw, 'raw_base': m['base'], 'raw_section': m['section'],
                'section_writing_candidate': writing,
                'literal_reconstruction': m['base'] + (m['section'] or ''),
                'classification_hold_reasons': ['same_road_and_official_name_unverified']}
    return {'class': 'held_unresolved_whole_name_shape', 'raw_literal': raw,
            'literal_reconstruction': raw, 'classification_hold_reasons': ['whole_name_shape_unresolved']}


def house_view(raw):
    if re.fullmatch(r'[1-9][0-9]*', raw):
        return {'class': 'bare_positive_integer', 'raw_literal': raw, 'integer_token': raw,
                'raw_number_suffix': '', 'representation_holds': []}
    if re.fullmatch(r'[1-9][0-9]*號', raw):
        return {'class': 'positive_integer_with_original_號_suffix', 'raw_literal': raw,
                'integer_token': raw[:-1], 'raw_number_suffix': '號',
                'representation_holds': ['existing_strict_raw_integer_guard_remains_held']}
    if re.fullmatch(r'[1-9][0-9]*之[1-9][0-9]*號?', raw):
        return {'class': 'held_house_subnumber', 'raw_literal': raw,
                'integer_token': None, 'raw_number_suffix': None,
                'representation_holds': ['house_subnumber_requires_lossless_supported_format']}
    return {'class': 'held_other_house_shape', 'raw_literal': raw, 'integer_token': None,
            'raw_number_suffix': None, 'representation_holds': ['house_shape_or_floor_requires_review']}


def main():
    loaded, pins = {}, []
    for key, (rel, expect) in INPUTS.items():
        p = ROOT / rel
        before = stat_fields(p)
        data = p.read_bytes()
        after = stat_fields(p)
        digest = hashlib.sha256(data).hexdigest()
        assert before == after and digest == expect
        loaded[key] = json.loads(data)
        pins.append({'path': rel, 'sha256': digest, 'bytes_read': len(data),
                     'stat_before': before, 'stat_after': after})
    mapping, examples, snapshot = loaded['mapping'], loaded['examples'], loaded['stock']
    roster = mapping['roster']
    assert len(roster) == mapping['literal_count'] == 28
    assert mapping['captured_complete_groups'] == 102 and not mapping['names_or_reasons_truncated']
    stock = {x['label']: x for x in snapshot['old_info_rows']}
    assert len(stock) == snapshot['selected_named_info_rows'] == 441
    full_examples = {x['complete_original_prepared_group']['group_id']: x for x in examples}
    assert len(full_examples) == 2
    capture_ref = copy.deepcopy(mapping['source_capture'])
    capture_ref['path'] = CAP + '/' + capture_ref['path']
    capture_ref['opened_or_hashed_in_this_scope'] = False
    rows, all_groups, all_lines = [], [], []
    for r in roster:
        raw = r['candidate_literal']
        assert raw not in stock
        gids, lines, houses = r['group_ids'], r['source_group_capture_lines'], r['raw_house_literals']
        assert len(gids) == len(lines) == len(houses)
        all_groups.extend(gids)
        all_lines.extend(lines)
        witnesses = copy.deepcopy(r['stock_nearby_witnesses'])
        for category in witnesses.values():
            for witness in category:
                s = stock[witness['stock_label']]
                assert [witness['stock_info_id'], witness['stock_record'], witness['stock_index_token']] == [s['info_id'], s['record'], s['index_record']]
                assert witness['verified_alias'] is False
        nv = name_view(raw, stock)
        assert nv['literal_reconstruction'] == raw
        group_views = []
        for gid, line, house in zip(gids, lines, houses):
            hv = house_view(house)
            if hv['integer_token'] is not None:
                assert hv['integer_token'] + hv['raw_number_suffix'] == house
            inherited_metadata = {}
            for key, explanation in [('no_floor_unit_metadata', 'floor_or_unit_metadata_present'),
                                     ('coordinate_selection_metadata_ready', 'multiple_coordinate_or_unready_metadata')]:
                count = r['hold_reason_group_counts'].get(key, 0)
                inherited_metadata[key] = {'failed_groups_in_literal': count,
                    'this_group': ('failed' if count == len(gids) else 'passed' if count == 0 else 'cannot_assess_from_aggregate_JSON'),
                    'hold_if_failed_or_unknown': explanation}
            e = full_examples.get(gid)
            payload = None
            if e:
                p = copy.deepcopy(e['complete_original_prepared_group'])
                assert p['raw_address'][2:] == [raw, house]
                assert e['source_group_capture_line'] == line
                payload = {'complete_original_prepared_group': p,
                           'complete_source_node_IDs': copy.deepcopy(e['complete_source_node_IDs']),
                           'sourcepoint': copy.deepcopy(e['sourcepoint']),
                           'native24': copy.deepcopy(e['native24']),
                           'existing_membership_evidence_only': copy.deepcopy(e['district_membership'])}
            group_views.append({'group_id': gid, 'source_capture_line': line,
                'original_street_literal': raw, 'original_raw_house_literal': house,
                'street_reconstruction': nv['literal_reconstruction'], 'house_view': hv,
                'house_reconstruction': house, 'house_encoding': encoded(house),
                'inherited_floor_coordinate_holds': inherited_metadata,
                'source_reference': {'path': capture_ref['path'], 'compressed_SHA256_inherited': capture_ref['SHA256'],
                    'JSONL_line': line, 'group_id': gid, 'source_node_IDs_materialized_here': e is not None},
                'allowed_JSON_full_source_payload': payload,
                'source_node_IDs_for_other_groups': None if e else 'not_in_allowed_JSON; preserved_by_sealed_line_reference',
                'released_for_address_or_route': False})
        rows.append({'candidate_literal': raw, 'group_count': len(gids),
                     'lossless_name_view': nv, 'street_encoding': encoded(raw),
                     'original_name_shapes': copy.deepcopy(r['name_shapes']),
                     'original_technical_planning_group_count': r['technical_planning_group_count'],
                     'original_failed_guard_group_counts': copy.deepcopy(r['hold_reason_group_counts']),
                     'original_nearby_stock_witnesses': witnesses,
                     'group_views': group_views, 'same_road_or_alias_verified': False,
                     'planning_release': False})
    assert len(all_groups) == len(set(all_groups)) == 102
    assert sorted(all_lines) == list(range(1, 103))
    by_name = {x['candidate_literal']: x for x in rows}
    assert by_name['平田里文心路四段']['lossless_name_view']['class'] == 'held_existing_exact_suffix_locality_prefix'
    assert by_name['北屯區和祥街185巷']['lossless_name_view']['prefix_exact_suffix_gate_note']['prefix_removal_candidate_admitted'] is False
    for a, b in [('崇德路2段', '崇德路二段'), ('崇德路3段', '崇德路三段')]:
        sv = by_name[a]['lossless_name_view']['section_writing_candidate']
        assert sv['writing_candidate'] == b and sv['exact_stock_match']['stock_label'] == b
    assert by_name['昌平路二段50之6巷2弄']['lossless_name_view']['raw_complete_branch_suffix'] == '50之6巷2弄'
    counts = dict(collections.Counter(x['lossless_name_view']['class'] for x in rows))
    house_counts = dict(collections.Counter(g['house_view']['class'] for x in rows for g in x['group_views']))
    metadata_unresolved = sum(any(k['this_group'] == 'cannot_assess_from_aggregate_JSON' for k in g['inherited_floor_coordinate_holds'].values()) for x in rows for g in x['group_views'])
    proposals = [
        {'proposal': 'lossless_numeric_section_writing_sidecar',
         'example_originals': ['崇德路2段', '崇德路3段'],
         'example_writing_candidates': ['崇德路二段', '崇德路三段'],
         'required_fields': ['original_literal', 'raw_section_digits', 'writing_candidate', 'existing_exact_stock_reference', 'source_group_and_line', 'held_relationship'],
         'requires_before_use': ['same_road_primary_source_or_actual_road_evidence', 'original_literal_kept_reconstructible'],
         'data_format_only': True, 'new_record_or_label_reference_created': False},
        {'proposal': 'lossless_anchored_branch_house_sidecar',
         'example_original': '昌平路二段50之6巷2弄',
         'raw_parent': '昌平路二段', 'raw_lane': '50之6巷', 'raw_alley': '2弄',
         'example_original_house': '39號', 'source_group_id': 172188, 'source_capture_line': 87,
         'required_fields': ['original_street_literal', 'existing_exact_parent_reference', 'raw_lane_suffix', 'raw_alley_suffix', 'original_raw_house_literal', 'source_group_and_line', 'unmaterialized_node_ID_reference', 'floor_coordinate_and_subnumber_holds'],
         'requires_before_use': ['supported_original_branch_and_house_format', 'complete_per_group_metadata_review', 'official_and_same_road_relationship_review'],
         'data_format_only': True, 'house_integer_or_flat_street_assignment_created': False},
    ]
    proof = {'schema': 'cached_JSON_lossless_name_branch_plan/v1', 'assigned_file_analysis_passed': True,
        'literal_count': 28, 'group_reference_count': 102, 'literal_classes': counts,
        'house_representation_classes': house_counts, 'literal_and_house_reconstruction_checks': 102,
        'existing_nearby_witnesses_checked_against_snapshot': True,
        'source_node_IDs_materialized_from_allowed_JSON_groups': 2,
        'other_group_node_IDs_retained_as_sealed_capture_line_references': 100,
        'group_metadata_assignment_cannot_assess_count': metadata_unresolved,
        '平田里文心路四段_correction': {'previous_technical_shape_eligible_groups': 1,
            'current_class': 'held_existing_exact_suffix_locality_prefix',
            'exact_suffix': '文心路四段', 'prefix': '平田里',
            'previous_scope_or_seal_modified': False, 'released': False},
        'section_rule': 'Only anchored Arabic positive section number1..99 → Chinese numeral token; original token retained. Exact stock spelling is a lexical candidate, never alias proof.',
        'prefix_rule': 'Locality prefix view requires the entire remaining suffix to be an existing exact stock label; no generic prefix stripping.',
        'branch_rule': 'Anchored parent + complete raw巷/弄 suffix, retain original raw house and every available ID/reference; no deletion or integer coercion.',
        'hold_policy': 'Original failed guards persist. Floor/unit, house subnumber, conflicting/unready coordinates remain held; aggregate-only mixed-group metadata cannot be reassigned or cleared.',
        'source_capture_reference': capture_ref, 'input_pins': pins,
        'capacity_arithmetic_only': {'original_stock_literal_count': 441,
            'distinct_missing_literal_count': 28, 'hypothetical_441_plus_all28': 469,
            'hypothetical_441_plus_at_most2': 443, 'actual_new_records': 0,
            'actual_new_labelrefs': 0, 'original_L2_child_count_from_snapshot': 441,
            'wire_widths_and_allocation_capacity_not_tested': True},
        'representation_research_proposal_count': 2,
        'read_counters': {'allowed_normal_JSON_bytes': sum(x['bytes_read'] for x in pins),
            'normal_JSON_input_files': 3, 'gzip_bytes': 0, 'source_prefix_bytes': 0,
            'PBF_or_nodeledger_bytes': 0, 'IMG_or_DB_bytes': 0, 'new_polygon_tests': 0,
            'native_or_guest_instructions': 0, 'compile_commands': 0, 'device_IO': 0, 'audio_playback': 0},
        'flags': {k: False for k in ['new_street_or_alias_verified', 'formal_house_or_route_accepted',
            'IMG_JAI_or_install_package_created', 'record_ID_reserved', 'labelref_created',
            'navigation_install_or_fullTaiwan_complete', 'App_complete', 'native_backend_owner',
            'STOP_DONE', 'direct_phone_A2DP_complete', 'speaker_complete', 'installable']},
        'limitations': ['100 groups node IDs and per-group mixed metadata are not expanded in the allowed JSON. This scope preserves exact group/capture-line references and does not reopen captured or original gzip.',
            'Two previously captured points/native24 and membership records are copied as prior evidence only, with zero new containment tests.',
            'Near names, stock prefix, numeric spelling and exact suffix do not establish alias, official name, same road, address or route acceptance.',
            'A hash seal is not a readonly-mode claim; source mode remains as observed and is not changed.'],
        'seal_then_stop': True}
    write_json('name-branch-classification.json', {'schema': proof['schema'], 'roster': rows})
    write_json('representation-research.json', {'proposals': proposals})
    write_json('source-pins.json', {'inputs': pins, 'source_capture_reference_not_opened': capture_ref,
        'inherited_corrected_source_seal_SHA256_not_reread': '5ba09fac307f25d569cb46fd60a2f948659dc4bb04fcc1cbafeaa3296c24ae3e'})
    write_json('proof.json', proof)
    table = ['# 28個名稱的可逆分類', '',
        '原名、原門牌、group ID 與 capture line 全部保留。表內「原名對應」只表示文字候選；沒有 alias／正式道路／門牌或路由放行。詳細逐group參照和未知欄位見 name-branch-classification.json。', '',
        '|完整候選 literal|groups|分類／原名對應|原巷弄 suffix|原門牌 literals|保留 holds|',
        '|---|---:|---|---|---|---|']
    for x in rows:
        nv = x['lossless_name_view']
        relation = nv['class']
        if nv.get('existing_exact_parent'):
            relation += '：' + nv['existing_exact_parent']['stock_label']
        if nv.get('section_writing_candidate'):
            relation += '；写法候選→' + nv['section_writing_candidate']['writing_candidate']
        if nv.get('parent_section_writing_candidate'):
            relation += '；parent写法候選→' + nv['parent_section_writing_candidate'].get('writing_candidate', '?')
        if nv.get('locality_prefix_candidates'):
            relation += '：' + '／'.join(z['raw_prefix'] + '＋' + z['unchanged_suffix'] for z in nv['locality_prefix_candidates'])
        houses = '、'.join(g['original_raw_house_literal'] for g in x['group_views'])
        holds = ', '.join(nv['classification_hold_reasons']) + '; 原guard=' + ', '.join(x['original_failed_guard_group_counts'])
        table.append(f"|{x['candidate_literal']}|{x['group_count']}|{relation}|{nv.get('raw_complete_branch_suffix', '—')}|{houses}|{holds}|")
    table += ['', '所有102個街名及原門牌字串均可重建。兩個崇德 groups 可由允許的 planning JSON 展開完整 node IDs；其餘100 groups 保留 sealed capture SHA＋JSONL line＋group ID 參照，未讀gzip且不聲稱node IDs已展開。', '',
        '段、里等單字不作全域排除。平田里文心路四段新增待核對里prefix分類；北屯區和祥街185巷的完整suffix和祥街185巷不在原名冊，拒絕自動刪prefix。所有之號、樓層／單元及多座標既有holds保持；mixed aggregate metadata無法指派到個別group時明記cannot-assess。', '']
    (OUT / 'mapping-table.md').write_text('\n'.join(table))
    print(json.dumps({'status': 'ordinary_saved_JSON_analysis_passed', 'names': 28, 'groups': 102,
        'classes': counts, 'house_classes': house_counts, 'mixed_metadata_unknown_groups': metadata_unresolved,
        'normal_JSON_bytes': proof['read_counters']['allowed_normal_JSON_bytes'], 'gzip_bytes': 0,
        'full_node_ID_groups': 2, 'new_records': 0, 'released_names': 0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
