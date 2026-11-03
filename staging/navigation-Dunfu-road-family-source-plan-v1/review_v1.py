#!/usr/bin/env python3
"""Bounded ordinary cached data review; never reopens the large group source.

No address/image/database writer, original native code, firmware build, audio
or device operations. Absence within a prefix is not absence from Taiwan.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
PINS=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def sig(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(relative,maximum,expected=None):
 p=ROOT/relative;before=sig(p);assert before[2]<=maximum
 raw=p.read_bytes();assert sig(p)==before and len(raw)==before[2]
 if expected:assert sha(raw)==expected,(relative,'pin mismatch')
 PINS.append({'path':relative,'bytes':len(raw),'SHA256':sha(raw),'stat_before':before,'stat_after':sig(p),'full_small_file_read':True})
 return raw
def load(relative,maximum,expected=None):return json.loads(read(relative,maximum,expected))
def save(name,value):
 with (OUT/name).open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
 started=datetime.now(timezone.utc).isoformat();prefix='staging/navigation-Dunfu-road-family-source-plan-v1/'
 read(prefix+'capture_prefix_v1.py',13000);read(prefix+'review_v1.py',15000)
 receipt=load(prefix+'prefix-read-receipt.json',6000);examples=load(prefix+'source-examples-at-prefix.json',30000)
 assert receipt['compressed_bytes_actually_read']==3145728 and receipt['decompressed_bytes_produced']==25165824
 assert receipt['complete_JSONL_rows']==46470 and receipt['gzip_EOF'] is False
 assert not receipt['JSONL_parse_failures'] and receipt['new_distinct_street_examples_preserved']==len(examples)==0
 assert receipt['Dunfu_literal_group_counts_in_exact_admin_prefix']=={'敦富六街':1}
 snapshot_path='staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json'
 snapshot=load(snapshot_path,350000,'929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6')
 plan_path='staging/navigation-native-jai-new-street-plan-v1/one-family-new-street-plan.json'
 prior_plan=load(plan_path,72000)
 official_path='staging/navigation-Dunfu6-official-name-primary-source-v1/proof.json'
 official=load(official_path,2500,'d75272e96e06aa6ba490fb7f53dbd011a8a97cd35b179af59537ffac283dfef1')
 assert official['official_literal_name_announced']=='敦富六街' and official['historical_official_literal_road_name_confirmed']
 geometry=load('staging/navigation-beitun-district-geometry-v1/geometry.json',150000,'c4b4c2a842af2042ca4fff893fb9e5ccd33940ffe27e445aa3222121269d49b3')
 geometry_proof=load('staging/navigation-beitun-district-geometry-v1/proof.json',11000,'7000011d0cc84272d0ceb4a23b23e8dc2097cf414b9b0b4fea7dd0bbd82cd4e1')
 membership=load('staging/navigation-beitun-district-geometry-v1/source-membership.json',5000,'d624ec02eb3b79331cd4041a77a093b4dcf2bc14765578eca70196f88a9e0e84')
 read('staging/navigation-beitun-district-geometry-v1/beitun_membership.py',7000)
 read('staging/navigation-country-merge-independent-review-v1/review_country_merge.py',36000,'7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec')
 ingestion=load('staging/navigation-taiwan-address-ingestion-v1/ingestion-summary.json',65000)
 label_proof=load('staging/navigation-native-house-label-index-v1/proof.json',40000,'793ad2853b07ee3940d0e4f44b39809c612b4ed2de5632387b3a7c36123ed3b4')
 assert snapshot['all_assigned_checks_passed'] and snapshot['selected_original_physical_L3_count']==snapshot['selected_named_info_rows']==len(snapshot['old_info_rows'])==441
 assert snapshot['city']['label']=='台中市' and snapshot['city']['record']==0x10000008
 assert snapshot['district']['label']=='北屯區' and snapshot['district']['record']==0x2000004a
 native_fields=snapshot['actual_original_L2_fields'];assert (native_fields['one_based_ID'],native_fields['first_child'],native_fields['child_count'],native_fields['next_level'])==(74,12924,441,3)
 names=[r['label'] for r in snapshot['old_info_rows']];assert len(set(names))==441
 dunfu_exact=[r for r in snapshot['old_info_rows'] if r['label'].startswith('敦富')];assert dunfu_exact==[]
 dun_similar=[r for r in snapshot['old_info_rows'] if r['label'].startswith('敦')]
 assert len(dun_similar)==5
 assert geometry['type']=='MultiPolygon' and geometry_proof['all_assigned_geometry_preparation_checks_passed']
 assert geometry_proof['actual_source_parent_subarea_membership_verified'] and geometry_proof['source_district_relation_id']==membership['source_district_relation_id']==2959946
 assert membership['source_city_relation_id']==2921154 and membership['actual_source_parent_subarea_member']=={'type':'relation','ref':2959946,'role':'subarea'}
 patch=prior_plan['required_L2_patch'];assert patch['first_width']==16 and patch['count_width']==10
 assert prior_plan['old_physical_L3_count']==441 and prior_plan['new_physical_L3_count']==442 and prior_plan['final_L3_count']==48312
 assert snapshot['L3_count']==47870 and patch['first_child']==47871 and patch['child_count']==442
 hypothetical_extra=2;hypothetical_count=441+1+hypothetical_extra;max_count=(1<<patch['count_width'])-1;max_first=(1<<patch['first_width'])-1
 hypothetical_final=snapshot['L3_count']+hypothetical_count
 assert hypothetical_count==444<=max_count and patch['first_child']<=max_first and hypothetical_final<=max_first
 assert label_proof['all_assigned_checks_passed'] and label_proof['distinct_integer_or_subnumber_house_labels']==50567
 source=ROOT/receipt['source_path'];assert sig(source)==receipt['source_stat_after']
 save('source-pins.json',{'schema':'ordinary small-file source pins/v1','inputs':PINS,'large_groups_input_pin_scope':'Only separately recorded first3MiB compressed SHA256 and original file stat; no full source EOF/hash repeated.','large_groups_stat_unchanged_since_prefix':True})
 capacity={'schema':'held Dunfu source-family capacity preflight/v1','status':'arithmetic_only_no_new_source_no_package','actual_original_family_count':441,'stock_L3_count':47870,'stock_JAI_max_info_ID':snapshot['old_max_info_id'],'basis':{'original_snapshot':snapshot_path,'previous_six_street_plan':plan_path,'L2_first_child_bits':16,'L2_child_count_bits':10},'numeric_child_count_field_max':max_count,'original_family_numeric_headroom':max_count-441,'hypothetical_with_previously_prototyped_six_and_at_most_two_extra_streets':{'new_streets_vs_stock':3,'family_count':hypothetical_count,'family_count_numeric_headroom':max_count-hypothetical_count,'proposed_first_low_ID_from_old_plan':patch['first_child'],'prospective_last_low_ID':hypothetical_final,'first_and_last_fit_declared_16bit_numeric_range':True,'global_L3_count_arithmetic':hypothetical_final,'prospective_JAI_max_info_ID':snapshot['old_max_info_id']+3,'IDs_reserved_or_records_generated':False},'actual_new_source_examples':0,'actual_new_street_or_house_rows_generated':0,'CP950_street_or_house_encoding_for_new_sources':'not_assessed_no_new_source_literal','new_house_integer_classification':'not_assessed_no_new_source_group','existing_house_label_ref_for_new_sources':'not_assessed_no_new_house_label','existing_small_label_index_available':{'distinct_integer_or_subnumber_labels':50567,'codepage':label_proof['codepage'],'pool_bytes':label_proof['pool_bytes'],'ledger_path':'staging/navigation-native-house-label-index-v1/house-labels.jsonl.gz','ledger_not_opened_here':True},'label_bytes_and_alignment_for_new_streets':'unknown_without_new_literal_name_and_verified_payload_policy','L4_payload_budget':'unknown_without_new_complete_source_groups','JAI_FTS_prefix_and_renderer_acceptance':'not_proved_by_numeric_capacity','installable':False}
 save('capacity-preflight.json',capacity)
 proof={'schema':'Dunfu family bounded source/index/capacity plan/v1','started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'ordinary_file_analysis_complete':True,'status':'held_no_additional_Dunfu_source_in_authorized_prefix','new_source_examples':examples,'new_distinct_street_example_count':0,'maximum_new_examples':2,'normal_data_ingestion':{'prefix_receipt':prefix+'prefix-read-receipt.json','new_compressed_read_bytes':3145728,'new_decompressed_bytes':25165824,'complete_rows':46470,'partial_final_row_not_parsed':435,'gzip_EOF':False,'parse_failures':[],'Dunfu_literal_counts_in_same_city_district':{'敦富六街':1},'large_groups_file_reopened_by_this_review':False,'not_whole_dataset_existence_or_absence':True},'source_origin_inherited':ingestion['source'],'stock_JAI_name_classification':{'basis':'Cached complete441 selected original JAI street-family snapshot, originally captured from the full immutable stock DB; original DB not reopened here.','same_stock_city':snapshot['city'],'same_stock_district':snapshot['district'],'complete_original_named_L3_rows':441,'literal_Dunfu_prefix_rows':dunfu_exact,'other_Dun_prefix_stock_names_not_verified_aliases':dun_similar,'new_candidate_exact_stock_absence_and_conservative_alias_screen':'not_assessed_no_new_source','historical_alias_exclusion_proved':False,'stock_JAI_full_file_rehashed_or_modified':False},'official_naming':{'reused_proof':official_path,'confirmed_literal':'敦富六街','effective_date':official['naming_effective_date'],'scope':'historical official literal only; source368 address/current alias completeness not established','other_Dunfu_street_names':'unknown_no_inference_from_item_numbers','other_names_officially_verified':False,'fresh_web_fetch':False},'district_geometry':{'complete_source_polygon_verified_and_pinned':True,'source_city_relation_ID':2921154,'source_district_relation_ID':2959946,'same_city_subarea_relation_verified_in_saved_evidence':True,'source_and_raw24_new_point_tests':[],'source_point_test_count':0,'raw24_point_test_count':0,'new_point_contains_result':'not_executed_no_new_source_coordinates','old_368_point_or_seven_controls_rerun':False,'geometry_source':'staging/navigation-beitun-district-geometry-v1/geometry.json','pure_API_available_but_not_invoked':'staging/navigation-beitun-district-geometry-v1/beitun_membership.py'},'capacity_preflight':'capacity-preflight.json','source_pins':'source-pins.json','failure_classification':{'data_parse_failures':[],'no_more_examples_is_not_a_parser_failure':True,'missing_new_source_data':'held_at_authorized_prefix_boundary'},'limits':['Prefix-only zero additional examples does not establish absence from the remaining4.58million groups or real geography.','No inferred Dunfu1..5 names, official aliases, formal house addresses or routes.','No new coordinates exist to run district containment; no true containment success is claimed.','Arithmetic field headroom is not a JAI/MDR/LBL/image integration, route or renderer acceptance.','No whole Taiwan scan, PBF, full source-node ledger, IMG parse/hash, original DB rescan, old guest/control suite or firmware work.'],'IMG_JAI_or_install_bundle_created':False,'device_IO':False,'audio_execution':False,'native_CPU_execution':False,'App_music_direct_phone_speaker_install_fullTaiwan_flags':False}
 save('proof.json',proof)
 print(json.dumps({'ordinary_data_review_complete':True,'status':proof['status'],'new_source_examples':0,'stock_family_rows':441,'stock_Dunfu_prefix_names':0,'new_source_and_raw24_tests':0,'hypothetical_family_count_with_six_plus_two':hypothetical_count,'numeric_10bit_child_count_headroom':max_count-hypothetical_count,'official_other_names_verified':False,'IMG_JAI_bundle_created':False,'native_CPU_execution':False,'device_IO':False},ensure_ascii=False),flush=True)
if __name__=='__main__':main()
