"""Independent small-output integer review; no scanner/imported producer code."""
from pathlib import Path
import hashlib,json
from capacity_math import plan,minimum_L4_row_savings,packed_bytes,ceildiv,CAPACITY

HERE=Path(__file__).resolve().parent
CAP=HERE/'captured-inputs'
def read(name):return json.loads((CAP/name).read_text())
def ikeys(values):return {int(k):v for k,v in values.items()}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(name,value):
    p=HERE/name;p.write_text(json.dumps(value,indent=2)+'\n');return sha(p.read_bytes())

def main():
    proof=read('proof.json');summary=read('feasibility-summary.json')
    receipt=read('actual-stream-read-receipts.json')
    source=read('prepared-source.json');terminal=read('actual-root-tool-receipts.json')
    composition=read('lane-v3-composition-proof.json');seal=read('sealed-files.json')
    components={r['name']:r['bytes'] for r in composition['complete_actual_component_checks']}
    assert len(components)==6 and composition['all_assigned_checks_passed']
    stream=receipt['stream'];segments=stream['segments']
    tables={r['level']:r for r in segments if r['segment']=='table'}
    assert set(tables)=={1,2,3,4,5,6}
    for row in tables.values():
        assert row['bytes']==packed_bytes(row['record_count'],row['stride_bits'])
        assert row['final_padding_bits']==(-row['record_count']*row['stride_bits'])%8
    assert [tables[i]['stride_bits'] for i in (4,5,6)]==[128,126,68]
    assert tables[3]['record_count']==47870 and tables[3]['stride_bits']==112
    cursor=0
    for row in segments:
        if 'start' in row:assert row['start']==cursor
        cursor+=row['bytes']
    assert cursor==stream['streamed_bytes']==components['00004171.MDR']==149220356
    assert segments[-1]['segment']=='DIR' and segments[-1]['bytes']==120
    old={i:tables[i]['bytes'] for i in (4,5,6)}
    current={i:tables[i]['record_count'] for i in (4,5,6)}
    assert current=={4:4896236,5:3077845,6:2062771}
    base=stream['streamed_bytes']-sum(old.values())
    assert base==segments[0]['bytes']+sum(tables[i]['bytes'] for i in (1,2,3))+120==4870967
    recomputed={}
    for name in ['stock_prefix_plus_active','current_v2_prefix_plus_active']:
        given=summary[name];counts=ikeys(given['retained_total_lower_counts'])
        assert ikeys(given['current_lower_counts'])==current
        arithmetic=plan(counts,old,stream['streamed_bytes'],components)
        arithmetic['same_field_width_capacity_valid']=(counts[4]<(1<<23) and counts[5]<(1<<22) and counts[6]<(1<<21))
        expected=dict(given['arithmetic'])
        expected['lower_table_bytes_after']=ikeys(expected['lower_table_bytes_after'])
        assert all(arithmetic[key]==value for key,value in expected.items())
        assert not arithmetic['fits_4K_capacity_arithmetic']
        assert given['unknown_raw_flag_counts']=={}
        assert given['invalid_or_unclassified_child_encoding_counts']=={}
        assert given['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention'] is False
        assert given['range_alias_analysis_complete'] is True
        assert all(row['contiguity_failures']==0 for row in given['range_alias_analysis'].values())
        recomputed[name]=arithmetic
    stock=recomputed['stock_prefix_plus_active'];v2=recomputed['current_v2_prefix_plus_active']
    assert stock['projected_conservative_4K_IMG_bytes']==137170944
    assert stock['capacity_margin_conservative']==-2953216
    assert v2['projected_conservative_4K_IMG_bytes']==153337856
    assert v2['capacity_margin_conservative']==-19120128
    counts=ikeys(summary['stock_prefix_plus_active']['retained_total_lower_counts'])
    savings=minimum_L4_row_savings(counts,old,stream['streamed_bytes'],components)
    fit=savings['fitting_plan'];prev=savings['previous_plan'];n=savings['exact_minimum_L4_rows_saved']
    nonmdr=sum(b for k,b in fit['component_4K_block_counts'].items() if k!='00004171.MDR')
    maxblocks=(CAPACITY-fit['conservative_4K_metadata_bytes'])//4096-nonmdr
    byte_limit=maxblocks*4096
    closed_form=ceildiv(stock['MDR_bytes_after']-byte_limit,16)
    assert n==closed_form==184273
    assert savings['metadata_saving_bytes']==4096 and savings['MDR_allocated_blocks_saved']==720
    assert prev['projected_conservative_4K_IMG_bytes']==134221824
    assert fit['projected_conservative_4K_IMG_bytes']==134217728
    assert prev['MDR_bytes_after']==130113548>byte_limit
    assert fit['MDR_bytes_after']==130113532<=byte_limit==130113536
    savings['independent_closed_form']=dict(non_MDR_blocks=nonmdr,
        threshold_metadata_bytes=fit['conservative_4K_metadata_bytes'],
        maximum_MDR_blocks=maxblocks,maximum_MDR_logical_bytes=byte_limit,
        ceil_required_logical_saving_over16=closed_form,
        metadata_FAT_rows=fit['root_plus_component_FAT_rows'],
        MDR_FAT_parts=fit['FAT_component_part_counts']['00004171.MDR'])
    assert terminal['terminal'] is True and terminal['actual_final_exit_code']==0
    ending=terminal['observations'][-1]
    assert ending['chunk_id']=='c4d30e' and ending['exit_code']==0
    outputs=[json.loads(line) for row in terminal['observations']
             for line in row['output'].splitlines() if line.strip()]
    last=outputs[-1]
    assert last['all_assigned_data_feasibility_checks_completed'] is True
    assert last['proof']['sha256']==sha((CAP/'proof.json').read_bytes())
    assert proof['all_assigned_data_feasibility_checks_completed'] is True
    assert proof['own_budget_exception_or_platform_interruption'] is False
    assert proof['actual_MDR_hash_matches_sealed_complete_readback'] is True
    mdrr=next(r for r in composition['complete_actual_component_checks'] if r['name']=='00004171.MDR')
    assert stream['actual_MDR_SHA256']==mdrr['sha256']=='b23a67f80ad4275b40faf15fd12ac02e32c34d359108489d51404c9791a657d1'
    assert proof['one_actual_MDR_stream_bytes']==stream['streamed_bytes']
    preflight=proof['extracted_global_dependency_preflight']
    assert set(preflight)=={'helpers','mapper'}
    for row in preflight.values():
        assert row['unresolved_global_names']==[] and row['image_bytes_read']==0
        assert row['checked_code_objects'] and row['required_global_names']
    assert 'sha' in preflight['helpers']['required_global_names']
    assert source['source_sha256']=='1e7888373c759b72c206f0fef11cf189cffa4ef98299f61ebe2c7bb948be1a6b'
    observed=next(r for r in seal['files'] if r['path'].endswith('/observed_analyzer.py'))
    assert observed['sha256']==source['source_sha256'] and observed['bytes']==source['source_bytes']==24314
    assert source['IMG_budget']==proof['actual_IMG_read_cap']==receipt['read_budget']['read_cap_bytes']==160000000
    assert source['RSS_guard_current_mm_KiB']==proof['actual_RSS_measurement']['cap_KiB']==393216
    assert proof['actual_IMG_read_bytes']==receipt['read_budget']['actual_IMG_bytes_read']==last['actual_IMG_bytes_read']==149290500
    assert sum(receipt['read_budget']['bytes_by_purpose'].values())==149290500
    assert 149290500-stream['streamed_bytes']==70144
    assert receipt['actual_input_handle_closed'] and proof['all_own_and_source_handles_closed']
    assert receipt['source_stat_before']==receipt['source_stat_after']
    assert proof['source_candidate']['stat_before']==proof['source_candidate']['stat_after']
    assert proof['whole_IMG_hash_not_repeated'] and receipt['actual_source_whole_IMG_SHA_not_repeated']
    inputs=json.loads((HERE/'input-read-receipts.json').read_text())
    assert inputs['external_artifact_bytes']==54518<=98304
    math_sha=save('math.json',dict(schema='garmin-compaction-capacity-independent-math/v1',
        current_component_logical_bytes=components,current_lower_table_bytes=old,
        current_lower_counts=current,MDR_nonlower_base_bytes=base,
        recomputed_plans=recomputed,minimum_additional_L4_savings=savings,
        all_reported_capacity_fields_equal=True,
        numeric_level_keys_normalized_from_JSON_strings=True))
    checklist_sha=save('checklist.json',dict(schema='garmin-compaction-numeric-checklist/v1',
        lower_and_upper_packed_bytes_and_padding_recomputed=True,
        MDR_prefix_tables_DIR_adjacency_sum_and_nonlower_base_recomputed=True,
        all_six_components_4K_block_ceil_FAT240parts_metadata_ceil_recomputed=True,
        max_old_metadata73728_and_capacity134217728_applied=True,
        stock_plan_and_whole_v2prefix_both_fail_fit=True,
        exact_L4_threshold_checked_by_monotonic_search_adjacent_cases_and_closed_form=True,
        supplied_actual_MDR_stream_digest_matches_pinned_composition_digest=True,
        supplied_actual_successful_return_c4d30e_proof_SHA_verified=True,
        supplied_preflight_unresolved_globals_empty_and_sha_required_resolved=True,
        v5_source_contents_or_AST_independently_read=False,
        v5_observer_AST_identity_is_inherited_preparation_statement=True,
        actual_MDR_fullhash_recomputed_here=False,
        full_graph_record_bits_or_transitive_external_ABIs_independently_proved=False,
        all_source_retention_and_field_width_criteria_unchanged=True,
        v5_reported_IMG_read_bytes=149290500,
        prior_failed_v4_reported_IMG_read_bytes=149290500,
        known_v4_plus_v5_reported_total_IMG_bytes=298581000,
        prior_v4_read_count_is_parent_provenance_not_newly_reopened_failure_receipt=True,
        total_research_source_read_is_not_one_pass=True,
        own_external_artifact_read_bytes=54518,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0))
    final=dict(schema='garmin-v3-compaction-capacity-independent-review/v1',
        all_assigned_checks_passed=True,scope='small NUMERIC DATA artifact review, not graph/scanner rerun',
        actual_v5_proof_sha256=sha((CAP/'proof.json').read_bytes()),
        actual_v5_seal_sha256=sha((CAP/'sealed-files.json').read_bytes()),
        actual_v5_success_terminal='c4d30e EXIT0',
        actual_MDR_EOF_stream_digest_guard_success_evidence_checked=True,
        preflight_unresolved_helpers_and_mapper_globals_empty=True,
        existing_sha_required_and_resolved=True,
        stock_active_plan_4K_bytes=137170944,stock_active_shortage_bytes=2953216,
        whole_v2prefix_plan_4K_bytes=153337856,whole_v2prefix_shortage_bytes=19120128,
        original_container_capacity_bytes=CAPACITY,
        exact_additional_L4_rows_needed_if_only128bit_L4_shrinks=184273,
        previous184272_rows_plan_bytes=134221824,exact184273_rows_plan_bytes=134217728,
        threshold_metadata_bytes=77824,initial_metadata_bytes=81920,
        threshold_MDR_bytes=130113532,threshold_MDR_block_count=31766,
        threshold_FAT_rows=142,threshold_MDR_FAT_parts=133,
        exact_MDR_nonlower_base_bytes=base,
        five_other_components_logical_bytes_preserved_in_arithmetic=True,
        graph_or_safely_deletable184273_rows_not_proved=True,
        actual_new_IMG_or_compaction_renderer_UI_route_install_v3_fix_ready=False,
        unknown_external_lower_ID_refs_and_native_ABIs_remain=True,
        producer_v5_source_read149290500_and_failed_v4_separate149290500=True,
        total_known_two_attempt_source_IMG_reads_bytes=298581000,
        own_artifact_bytes_read=54518,own_artifact_limit_bytes=98304,
        own_scanner_IMG_MAIN_PBF_CPU_guest_audio_device_reads_execution=0,
        shared_sealed_sources_outputs_report_canonical_mutated=False,
        all_handles_closed=True,
        artifacts=dict(math_sha256=math_sha,checklist_sha256=checklist_sha))
    proofsha=save('proof.json',final)
    print(json.dumps(dict(all_assigned_checks_passed=True,
        exact_additional_L4_rows=184273,previous_image=134221824,fitting_image=134217728,
        stock_image=137170944,stock_shortage=2953216,v2prefix_image=153337856,
        proof_sha256=proofsha,external_artifact_bytes=54518,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0)))

if __name__=='__main__':main()
