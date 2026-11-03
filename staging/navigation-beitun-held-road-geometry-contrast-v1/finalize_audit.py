#!/usr/bin/env python3
"""Output audit only: no geometry, Java, IMG, firmware, or old controls rerun."""
import sys
sys.dont_write_bytecode=True
import hashlib,json
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def load(n):return json.loads((HERE/n).read_text())
def save(n,d):
 assert not (HERE/n).exists()
 (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def main():
 assert not (HERE/'proof.json').exists()
 prepared=load('prepared-inputs.json');groups_doc=load('candidate-groups.json');groups=groups_doc['groups']
 process=load('reader-process.json');io=load('java-tile-read-receipt.json');results=load('contrast-results.json')
 analysis=load('analysis-input-read-receipts.json');controls=load('new-segment-controls.json')
 assert len(groups)==2 and [g['literal']for g in groups]==['景賢六街','榮興街']
 assert [g['source_group_full']['original_prepared_group']['group_id']for g in groups]==[36096,33650]
 assert [g['source_group_full']['original_prepared_group']['source_ids']for g in groups]==[[7867809101],[7170215615]]
 assert [g['eligible_for_readonly_road_contrast']for g in groups]==[True,False]
 selected=(HERE/'selected-capture-lines.jsonl').read_bytes().splitlines(keepends=True)
 assert len(selected)==2
 for line,g in zip(selected,groups):
  assert json.loads(line)==g['source_group_full']
  assert g['source_group_full']['original_prepared_group']['source_node_count']==1
  assert g['existing_holds_preserved'] and not g['official_alias_address_route_or_write_ready']
  assert {'held_alias_relation','official_name_and_historical_alias_unverified'}<=set(g['all_holds'])
 assert groups[1]['actual_source_membership']['eligible'] is False and groups[1]['actual_raw24_membership']['eligible'] is False
 assert process['exit_code']==0 and process['actual_invocations']==1 and process['maximum_tiles']==1
 assert io['successful_open_count']==io['successful_close_count']==1
 assert io['actual_read_syscall_count']==len(io['reads']) and io['actual_syscall_bytes_read']==sum(r['bytes']for r in io['reads'])
 assert not io['mmap_count']
 rows=load('road-geometry.json');assert len(rows)==2
 assert {tuple(r['labels']) for r in rows}=={('景賢六路',),('景賢北街',)}
 assert results['exact_label_decoded_NET_rows']=={'景賢六路':1,'景賢北街':1,'景賢六街':0}
 assert results['RGN_vertices_checked']==15 and results['complete_segment_pairs_checked']==13
 assert len(results['comparisons'])==2
 assert all(r['all_decoded_pairs_inside_Beitun'] for r in results['comparisons'])
 assert sum(len(r['complete_segment_district_checks'])for r in results['comparisons'])==13
 assert controls['all_passed'] and len(controls['cases'])==6 and not controls['old_point_controls_run']
 for r in controls['cases']:assert r['actual']==r['expected']
 assert all(not r['alias_renaming_formal_address_route_match']for r in results['comparisons'])
 assert not results['official_alias_address_route_write_install_ready']
 inherited_reads=prepared['input_read_receipts']+process['input_hash_read_receipts']+analysis['reads']
 for r in inherited_reads:assert stat(ROOT/r['path'])==r['stat'],r['path']
 tile_read=next(r for r in process['input_hash_read_receipts']if r['path']==prepared['selected_tile'])
 distances=[dict(label=r['road_NET_row']['labels'][0],NET_offset=r['road_NET_row']['netOffset'],
  sourcepoint_m=r['sourcepoint_minimum_on_proved_inside_segments']['distance_m'],
  raw24point_m=r['raw24point_minimum_on_proved_inside_segments']['distance_m'])for r in results['comparisons']]
 proof=dict(schema='bounded-held-source-road-geometry-contrast-proof/v1',all_assigned_checks_passed=True,
  source_capture=dict(path='staging/navigation-beitun-source-capture-corrected-v1/missing-source-groups.jsonl.gz',
   **groups_doc['complete_capture_input']),original_complete_groups=2,source_ID_count=2,
  full_prepared_group_objects_and_hold_mapping_preserved=True,
  unavailable_original_per_node_tags_versions_or_alternate_coordinates_not_invented=True,
  actual_new_geometry_point_cases=groups_doc['actual_new_membership_calls'],geometry_relation_id=2959946,
  geometry_sha256=groups[0]['actual_source_membership']['geometry_sha256'],
  eligible_readonly_contrast_group_ids=[36096],geometry_held_group_ids=[33650],
  held_Rongxing_no_road_candidate_or_NET_targets=True,exact_candidate_only_this_tile_not_found=True,
  inherited_near_name_witnesses_not_reinterpreted_as_aliases=True,road_distances=distances,
  same_native_city_district_stock_context_preserved=True,
  actual_NET_city_names='臺中市',every_compared_RGN_segment_within_complete_Beitun_polygon=True,
  actual_ordinary_Java_invocations=1,ordinary_Java_exit_code=0,actual_tiles_decoded=1,
  parsed_NET_rows=2,parsed_RGN_polylines=2,RGN_vertices_checked=15,exact_rational_segment_pairs_checked=13,
  new_synthetic_segment_controls=6,old368_or_Chongde_geometry_controls_rerun=False,
  selected_tile_host_hash_bytes=tile_read['bytes'],selected_tile_host_hash_sha256=tile_read['sha256'],
  selected_tile_Java_read_syscalls=io['actual_read_syscall_count'],selected_tile_Java_actual_read_bytes=io['actual_syscall_bytes_read'],
  selected_tile_Java_unique_bytes=io['unique_bytes_read'],Java_map_mmap_count=0,
  total_tile_host_hash_plus_Java_read_bytes=tile_read['bytes']+io['actual_syscall_bytes_read'],
  Java_Xmx_bytes=384*1024*1024,Java_actual_RSS_not_measured=True,
  Java_SIGSEGV_trace_events=io['JVM_signal_trace_lines'],
  Java_signal_runtime_cause_not_inferred=True,all_input_stats_unchanged=True,all_image_handles_closed=True,
  proof_limits=dict(whole_Search_IMG_read_or_hash=False,full_source_ledger_or_PBF_open=False,
   MAIN_or_original_CPU_reads=0,native_guest_cases=0,device_IO=False,new_IMG_DB_or_installer=False,
   nearest_auto_rename=False,cross_district_matching=False,formal_address_alias_or_route_verified=False,
   original_frontend_or_physical_road_acceptance=False,install_ready=False,full_update_complete=False),
  preserved_exploratory_capture_history=dict(initial_wrong_top_level_key_lookup_empty=True,
   corrected_host_nested_key_inspection=True,preparation_full_capture_passes=1,
   capture_read_passes_including_two_initial_host_inspections=3,
   full_137MB_planning_ledger_read_passes=0),
  output_only_audit=True,geometry_java_oldcases_or_distance_execution_repeated_by_audit=False)
 save('proof.json',proof)
 save('audit-result.json',dict(all_assigned_checks_passed=True,actual_group_count=2,geometry_held_group_count=1,
   compared_NET_rows=2,all_stats_stable=True,IMG_reads=0,CPU_cases=0,output_audit_only=True))
 print(json.dumps(dict(result='PASS output audit; no IMG/Java/geometry rerun',proof_sha256=sha((HERE/'proof.json').read_bytes()),
  original_groups=2,geometry_held=['榮興街'],distances=distances,all_handles_closed=True),ensure_ascii=False))
if __name__=='__main__':main()
