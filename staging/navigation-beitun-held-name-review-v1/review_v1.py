#!/usr/bin/env python3
"""Pure normal-file artifact review. Read prior namespace only; no sources.

Never imports or executes the prior ingestion script; no gzip/PBF/IMG,
native guest, compiler, device or audio. Missing fields stay cannot-assess.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
OLD=ROOT/'staging/navigation-beitun-new-street-bounded-source-v1'
PINS=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def sig(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(name,limit=24000):
 p=OLD/name;before=sig(p);assert before[2]<=limit
 raw=p.read_bytes();assert len(raw)==before[2] and sig(p)==before
 PINS.append({'path':str(p.relative_to(ROOT)),'bytes':len(raw),'SHA256':sha(raw),'stat_before':before,'stat_after':sig(p)})
 return raw
def save(name,value):
 with (OUT/name).open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
 assert not (OUT/'review.json').exists();started=datetime.now(timezone.utc).isoformat()
 seal_raw=read('SEAL.json');assert sha(seal_raw)=='3d7839c8972ed85d17923bb353397b4a59022c496bf35724d6a63bf97cb546ea'
 seal=json.loads(seal_raw);raw={}
 for name,identity in seal['files'].items():
  raw[name]=read(name);assert len(raw[name])==identity['bytes'] and sha(raw[name])==identity['SHA256']
 post=json.loads(read('post-seal-tool-receipt.json'))
 assert post['chunk_id']=='567067' and post['exit_code']==0
 source=raw['analyze_v1.py'].decode();lines=source.splitlines()
 proof=json.loads(raw['proof.json']);counts=json.loads(raw['prefix-read-counters.json']);samples=json.loads(raw['source-examples.json']);receipt=json.loads(raw['actual-data-tool-receipt.json']);old_pins=json.loads(raw['source-pins.json'])
 assert proof['ordinary_analysis_complete'] and receipt['terminal_chunk_id']=='1b4ead' and receipt['terminal_exit_code']==0
 assert samples==[] and counts['new_source_examples_saved']==0
 assert counts['missing_exact_stock_distinct_street_names']==28 and counts['missing_exact_stock_street_groups']==102
 assert counts['same_city_district_groups_in_prefix']==548
 assert counts['actual_sourcepoint_membership_calls']==counts['actual_raw24_membership_calls']==0
 assert proof['reused_capture_check']==[{'capture':'staging/navigation-native-new-street-source-example-v1/final-bounded-taichung-shortlist.json','group_id':37506,'street':'敦富六街','already_closed_six_street':True}]
 assert 'missing_names.add(street)' in source and "'missing_exact_stock_distinct_street_names':len(missing_names)" in source
 assert not any(k in counts for k in ['missing_names','missing_street_literals','per_street_hold_reasons','held_source_samples'])
 assert "near=[r for r in snapshot['old_info_rows'] if one_edit(r['label'],street)]" in source
 assert "prefixes=[r for r in snapshot['old_info_rows'] if street.startswith(r['label']) or r['label'].startswith(street)]" in source
 assert "if near or prefixes:reasons.append('possible_spelling_or_prefix_alias_relation')" in source
 assert "re.search(r'[巷弄之段村里鄰交叉口]',street)" in source
 interesting=[{'line':i,'source':s} for i,s in enumerate(lines,1) if any(x in s for x in ['def one_edit','if abs(len(a)-len(b))','sum(x!=y','if len(a)>len(b)','return any(a==b[:i]','missing_names.add','not_conservative_flat_road_or_street_literal','not_literal_positive_integer_house','incomplete_or_invalid_source_IDs','coordinate_conflict_or_unready','floor_unit_metadata_present','near=[','prefixes=[','if near or prefixes','CP950_roundtrip_failure','if reasons:','for reason in reasons','offset+=len(line);continue','selected.append','missing_exact_stock_distinct_street_names','save(\'source-examples'])]
 save('policy-source-excerpts.json',{'source':'staging/navigation-beitun-new-street-bounded-source-v1/analyze_v1.py','SHA256':sha(raw['analyze_v1.py']),'source_read_only_not_executed':True,'excerpts':interesting})
 reasons=counts['reject_reason_counts'];assert reasons['not_conservative_flat_road_or_street_literal']==97 and reasons['possible_spelling_or_prefix_alias_relation']==97 and reasons['not_literal_positive_integer_house']==83
 # Counts are overlapping group totals, not a missing-literal map or proof
 # of a specific intersection. No candidate/group is reconstructed here.
 aggregate={'same_admin_groups':548,'exact_stock_street_group_count':reasons['exact_stock_street_present'],'exact_missing_group_count':102,'distinct_missing_literal_count':28,'hold_reason_group_counts_overlapping':reasons,'derived_single_guard_pass_counts_only':{'name_shape_guard':102-reasons['not_conservative_flat_road_or_street_literal'],'plain_integer_house_guard':102-reasons['not_literal_positive_integer_house'],'CP950_street_and_house_combined_guard':102-reasons['CP950_roundtrip_failure'],'coordinate_selection_metadata_guard':102-reasons['coordinate_conflict_or_unready'],'no_floor_unit_metadata_guard':102-reasons['floor_unit_metadata_present'],'ID_metadata_guard':102-reasons.get('incomplete_or_invalid_source_IDs',0),'no_stock_edit_or_prefix_relation_guard':102-reasons['possible_spelling_or_prefix_alias_relation']},'per_group_intersections_not_saved':True,'coordinate_values_and_global_precision_not_validated_for_held_groups':True,'only_near_or_prefix_hold_count':'cannot-assess','do_not_infer_verified_aliases_from_near_or_prefix_count':True}
 mapping=[{'candidate_literal':'敦富六街','identification_basis':'Only preserved literal from reused_capture_check plus already_closed_six_street_excluded counter1.','stock_nearby_names':'not saved in this scope','hold_reasons':['already_closed_six_street_excluded'],'additional_per_group_hold_reasons':'cannot-assess; full row/reasons not retained here','saved_complete_source_in_this_scope':False,'saved_reference_only':{'group_id':37506,'prior_capture':'staging/navigation-native-new-street-source-example-v1/final-bounded-taichung-shortlist.json'},'usable_as_new_candidate':False},{'candidate_literal':None,'aggregate_unidentified_distinct_literals':27,'stock_nearby_names':'not saved','hold_reasons':'Only overlapping global counters available; individual mapping cannot-assess','saved_complete_source_in_this_scope':False,'usable_as_new_candidate':'cannot-assess'}]
 findings=[{'id':'missing_literal_roster_and_witnesses','conclusion':'The runtime missing-name set is persisted only as len=28. Per-name/group reasons and near/prefix stock witness lists were not serialized for rejected groups.','impact':'Cannot provide all28 real literal names or their hold mapping from the frozen outputs.'},{'id':'near_prefix_capture_gate','conclusion':'Any nonempty edit/prefix relation adds a rejection reason, then continue executes before selected.append. Held source rows are therefore not retained even when all other guards pass.','impact':'An empty source-examples list cannot establish zero otherwise-qualified near/prefix-only cases. Near/prefix relation remains pending review, never a proven alias.'},{'id':'sectioned_names','conclusion':'Names ending in a section marker fail the required 路/街 final suffix; any 段 character also fails the single-character blacklist.','impact':'This is a scope restriction for flat names, not evidence a sectioned road literal is false or invalid. Actual excluded section names were not retained, so individual misclassification cannot-assess.'},{'id':'single_character_blacklist_is_broad','conclusion':'The character class rejects every occurrence of 巷弄之段村里鄰交叉口 individually, including 交, 叉 and 口, rather than recognizing an entire intersection expression.','impact':'A name containing any such character can be held without evidence it is a lane/intersection or invalid name. No current actual literal witness was saved, so actual wrongly held names cannot-assess.'},{'id':'CJK_length_and_suffix_scope','conclusion':'The fullmatch requires2..14 CJK characters followed by路 or街, total3..15 characters. It excludes other character ranges, shorter/longer names and section suffixes regardless of official naming.','impact':'Conservative eligibility only; cannot infer legal/official authenticity or nonexistence.'},{'id':'aggregate_reasons_overlap','conclusion':'Reasons are counted independently;97 nonflat and97 near/prefix groups need not be the same groups. No per-row intersections are preserved.','impact':'Cannot derive which plain-integer/CP950/complete-ID/coordinate-ready group was held only for a stock relation.'}]
 review={'schema':'read-only held-name artifact review/v1','started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'normal_file_review_complete':True,'status':'cannot-assess_individual_held_names_due_missing_saved_fields','prior_scope_seal_verified':True,'prior_actual_data_terminal':'1b4ead EXIT0','prior_actual_seal_terminal':'567067 EXIT0','prior_artifacts_opened_only':list(raw)+['SEAL.json','post-seal-tool-receipt.json'],'source_dependency_paths_seen_in_old_manifest_only':len(old_pins['inputs']),'referenced_source_dependencies_not_opened':True,'large_source_or_compressed_files_read_bytes':0,'PBF_IMG_original_DB_or_stock_roster_reopened':False,'missing_name_retention':{'reported_distinct_missing_literals':28,'saved_complete_missing_literal_list':False,'identifiable_saved_literal_names':['敦富六街'],'unidentified_remaining_distinct_literals':27,'new_complete_source_samples':len(samples),'saved_group_IDs_coordinates_house_encoding_intersections_for_new_held_samples':False,'stock_nearby_name_witness_lists_for_held_samples':False},'aggregate_evidence':aggregate,'mapping':mapping,'static_findings':findings,'otherwise_qualified_only_stock_near_relation_cases':{'existence_in_original_scanned_data':'cannot-assess','available_saved_complete_cases':0,'max_requested':2,'cannot_assert_true_case_count_zero':True,'not_self_released':True},'next_real_road_contrast_candidates_from_saved_new_sources':[],'next_step_prerequisite':'No available complete new held source in this frozen namespace. Any later investigation needs separately supplied/captured actual complete groups; no reread or new map analysis is performed here.','source_pins':'input-artifact-pins.json','policy_source_excerpts':'policy-source-excerpts.json','native_CPU_execution':False,'guest_or_compile_execution':False,'device_IO':False,'audio_execution':False,'original_artifacts_modified':False,'new_IMG_JAI_bundle_created':False,'navigation_App_music_install_fullgoal_flags':False}
 save('review.json',review)
 table='| Candidate literal | Stock nearby name | Hold reasons | Saved source available |\n|---|---|---|---|\n| 敦富六街（既有closed來源） | 此scope未保存 | already_closed_six_street_excluded；其餘逐group原因cannot-assess | 只有group37506／prior-capture reference；不是新增示例 |\n| 其餘27個缺名literal未保存 | 未保存 | 僅有重疊彙總counts，逐名cannot-assess | 無完整新group／IDs／point |\n'
 (OUT/'mapping-table.md').write_text(table)
 save('input-artifact-pins.json',{'schema':'read-only prior-artifact input pins/v1','inputs':PINS,'no_referenced_large_or_original_source_opened':True})
 for item in PINS:
  path=ROOT/item['path'];assert sig(path)==item['stat_after'] and sha(path.read_bytes())==item['SHA256']
 print(json.dumps({'normal_file_review_complete':True,'prior_seal_verified':True,'reported_missing_literal_count':28,'identifiable_saved_literal_names':['敦富六街'],'unidentified_remaining_literals':27,'individual_held_name_mapping':'cannot-assess','available_new_complete_source_cases':0,'only_near_qualified_case_existence':'cannot-assess','broad_name_filter_and_capture_gate_findings':True,'large_source_read_bytes':0,'original_artifacts_modified':False,'native_guest_compile_device_audio':False},ensure_ascii=False),flush=True)
if __name__=='__main__':main()
