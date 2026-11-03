#!/usr/bin/env python3
"""A newly authorized bounded ordinary data prefix, explicitly a reread.

No full source EOF/hash, PBF/node ledger, native CPU, database/image writer,
firmware, device or audio. Save at most two conservative source examples.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib,zlib,re,importlib.util,traceback
from pathlib import Path
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_UP

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
GROUPS=ROOT/'staging/navigation-taiwan-address-ingestion-v1/address-planning-groups.jsonl.gz'
REPEAT_C=3*1024*1024;REPEAT_D=24*1024*1024;NEW_C=9*1024*1024;NEW_D=72*1024*1024
INPUTS=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def sig(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(relative,limit,expected=None):
 p=ROOT/relative;before=sig(p);assert before[2]<=limit,(relative,'small-file bound')
 raw=p.read_bytes();assert len(raw)==before[2] and sig(p)==before
 if expected:assert sha(raw)==expected,(relative,'pin mismatch')
 INPUTS.append({'path':relative,'bytes':len(raw),'SHA256':sha(raw),'stat_before':before,'stat_after':sig(p)})
 return raw
def load(relative,limit,expected=None):return json.loads(read(relative,limit,expected))
def save(name,data):
 with (OUT/name).open('x') as f:json.dump(data,f,ensure_ascii=False,indent=2);f.write('\n')
def one_edit(a,b):
 if abs(len(a)-len(b))>1:return False
 if len(a)==len(b):return sum(x!=y for x,y in zip(a,b))<=1
 if len(a)>len(b):a,b=b,a
 return any(a==b[:i]+b[i+1:] for i in range(len(b)))
def main():
 started=datetime.now(timezone.utc).isoformat();phase='existing small captures';state={'compressed_bytes_actually_read':0,'decompressed_bytes_produced':0}
 assert not (OUT/'proof.json').exists()
 try:
  read(str(Path(__file__).relative_to(ROOT)),22000)
  snapshot=load('staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json',350000,'929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6')
  assert snapshot['all_assigned_checks_passed'] and len(snapshot['old_info_rows'])==snapshot['selected_named_info_rows']==snapshot['selected_original_physical_L3_count']==441
  assert snapshot['city']['record']==0x10000008 and snapshot['district']['record']==0x2000004a
  stock={r['label'] for r in snapshot['old_info_rows']}
  captures=['staging/navigation-native-new-street-source-example-v1/final-bounded-taichung-shortlist.json','staging/navigation-native-new-street-source-example-v1/bounded-prefix-qualifying-groups.json','staging/navigation-native-new-street-source-example-v1/bounded-taichung-relaxed-screen-groups.json','staging/navigation-Dunfu-road-family-source-plan-v1/source-examples-at-prefix.json']
  reused=[]
  for path in captures:
   rows=load(path,6500)
   for row in rows:
    groups=row.get('groups',[row.get('group',row)])
    for group in groups:
     key=group.get('normalized_planning_key',[])
     if len(key)==4 and key[:2]==['台中市','北屯區']:
      reused.append({'capture':path,'group_id':group['group_id'],'street':key[2],'already_closed_six_street':key[2]=='敦富六街'})
  assert reused and all(r['already_closed_six_street'] for r in reused)
  prior=load('staging/navigation-Dunfu-road-family-source-plan-v1/prefix-read-receipt.json',6000)
  source_manifest=load('staging/navigation-taiwan-address-ingestion-v1/ingestion-summary.json',65000)
  hp=load('staging/navigation-native-house-label-index-v1/proof.json',40000,'793ad2853b07ee3940d0e4f44b39809c612b4ed2de5632387b3a7c36123ed3b4')
  labels_raw=read('staging/navigation-native-house-label-index-v1/house-labels.jsonl.gz',270000,hp['ledger_sha256'])
  label_inflater=zlib.decompressobj(16+zlib.MAX_WBITS);labels_plain=label_inflater.decompress(labels_raw,8*1024*1024)
  assert label_inflater.eof and not label_inflater.unconsumed_tail and not label_inflater.unused_data and len(labels_plain)<8*1024*1024
  labels={}
  for line in labels_plain.splitlines():
   row=json.loads(line);assert row['label'] not in labels;labels[row['label']]=row
  assert len(labels)==hp['distinct_integer_or_subnumber_house_labels']==50567
  api_path='staging/navigation-beitun-district-geometry-v1/beitun_membership.py';read(api_path,7000)
  for path,limit,pin in [('staging/navigation-beitun-district-geometry-v1/geometry.json',150000,'c4b4c2a842af2042ca4fff893fb9e5ccd33940ffe27e445aa3222121269d49b3'),('staging/navigation-beitun-district-geometry-v1/proof.json',11000,'7000011d0cc84272d0ceb4a23b23e8dc2097cf414b9b0b4fea7dd0bbd82cd4e1'),('staging/navigation-beitun-district-geometry-v1/source-membership.json',5000,'d624ec02eb3b79331cd4041a77a093b4dcf2bc14765578eca70196f88a9e0e84'),('staging/navigation-country-merge-independent-review-v1/review_country_merge.py',36000,'7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec')]:read(path,limit,pin)
  spec=importlib.util.spec_from_file_location('beitun_membership_new_data_scope',ROOT/api_path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);membership=module.BeitunMembership()
  phase='explicit new 12MiB compressed prefix read'
  before=sig(GROUPS);assert before==prior['source_stat_after'] and before[2]==137633122
  with GROUPS.open('rb') as f:
   repeat_compressed=f.read(REPEAT_C);state['compressed_bytes_actually_read']+=len(repeat_compressed)
   assert len(repeat_compressed)==REPEAT_C and f.tell()==REPEAT_C
   extra_compressed=f.read(NEW_C);state['compressed_bytes_actually_read']+=len(extra_compressed)
   assert len(extra_compressed)==NEW_C and f.tell()==REPEAT_C+NEW_C
  assert sha(repeat_compressed)==prior['compressed_prefix_SHA256']
  phase='separate repeated24MiB and additional72MiB decompression'
  inflater=zlib.decompressobj(16+zlib.MAX_WBITS);repeat_plain=inflater.decompress(repeat_compressed,REPEAT_D);state['decompressed_bytes_produced']+=len(repeat_plain)
  assert len(repeat_plain)==REPEAT_D and sha(repeat_plain)==prior['decompressed_prefix_SHA256'] and not inflater.eof
  repeated_compressed_tail=inflater.unconsumed_tail
  assert len(repeated_compressed_tail)==prior['decompressor_unconsumed_compressed_bytes']==740947
  extra_plain=inflater.decompress(repeated_compressed_tail+extra_compressed,NEW_D);state['decompressed_bytes_produced']+=len(extra_plain)
  assert len(extra_plain)==NEW_D and not inflater.eof
  assert sig(GROUPS)==before
  plain=repeat_plain+extra_plain;newline=plain.rfind(b'\n');complete=plain[:newline+1];partial=plain[newline+1:]
  repeated_rows=repeat_plain.count(b'\n');assert repeated_rows==46470
  phase='bounded complete JSONL conservative source screening'
  rows=0;offset=0;selected=[];chosen_names=set();same_admin=0;missing_groups=0;missing_names=set();reason_counts={};parse_failures=[];geometry_calls={'source':0,'raw24':0};geometry_rejections=[];conservative_names={}
  for line in complete.splitlines(keepends=True):
   rows+=1
   try:group=json.loads(line)
   except Exception as error:
    parse_failures.append({'line':rows,'offset':offset,'SHA256':sha(line),'error':str(error)});offset+=len(line);continue
   key=group.get('normalized_planning_key',[]);raw=group.get('raw_address',[])
   if len(key)!=4 or len(raw)!=4 or key[:2]!=['台中市','北屯區']:
    offset+=len(line);continue
   same_admin+=1;city,district,street,label=key
   if street in stock:
    reason_counts['exact_stock_street_present']=reason_counts.get('exact_stock_street_present',0)+1;offset+=len(line);continue
   missing_groups+=1;missing_names.add(street);reasons=[]
   if street=='敦富六街':reasons.append('already_closed_six_street_excluded')
   if raw[0] not in ['台中市','臺中市'] or raw[1]!='北屯區' or raw[2]!=street:reasons.append('nonliteral_raw_admin_or_street_normalization')
   if not isinstance(street,str) or not re.fullmatch(r'[\u3400-\u9fff]{2,14}[路街]',street) or re.search(r'[巷弄之段村里鄰交叉口]',street):reasons.append('not_conservative_flat_road_or_street_literal')
   if not isinstance(raw[3],str) or not re.fullmatch(r'[1-9][0-9]*',raw[3]) or label!=raw[3]+'號':reasons.append('not_literal_positive_integer_house')
   ids=group.get('source_ids')
   if not isinstance(ids,list) or not ids or len(ids)!=group.get('source_node_count') or len(set(ids))!=len(ids) or any(type(n)is not int or n<=0 for n in ids):reasons.append('incomplete_or_invalid_source_IDs')
   if group.get('different_coordinate_nodes')!=0 or group.get('coordinate_selection_ready') is not True or group.get('needs_coordinate_review') is not False:reasons.append('coordinate_conflict_or_unready')
   if group.get('embedded_floor_unit') or group.get('separate_floor_unit_nodes')!=0:reasons.append('floor_unit_metadata_present')
   near=[r for r in snapshot['old_info_rows'] if one_edit(r['label'],street)]
   prefixes=[r for r in snapshot['old_info_rows'] if street.startswith(r['label']) or r['label'].startswith(street)]
   if near or prefixes:reasons.append('possible_spelling_or_prefix_alias_relation')
   try:street_bytes=street.encode('cp950');house_bytes=label.encode('cp950');assert street_bytes.decode('cp950')==street and house_bytes.decode('cp950')==label
   except (UnicodeEncodeError,UnicodeDecodeError,AssertionError):reasons.append('CP950_roundtrip_failure')
   if reasons:
    for reason in reasons:reason_counts[reason]=reason_counts.get(reason,0)+1
    offset+=len(line);continue
   conservative_names[street]=conservative_names.get(street,0)+1
   if street in chosen_names or len(selected)>=2:
    offset+=len(line);continue
   point=group.get('first_coordinate');assert isinstance(point,list) and len(point)==2
   decimals=[Decimal(v) for v in point];assert all(v.is_finite() for v in decimals)
   native=[int((v*Decimal(1<<24)/Decimal(360)).to_integral_value(rounding=ROUND_HALF_UP))&0xffffff for v in decimals]
   source_result=membership.assess_source_point(city,district,*point);geometry_calls['source']+=1
   native_result=membership.assess_raw24(city,district,*native);geometry_calls['raw24']+=1
   if not source_result['eligible'] or not native_result['eligible']:
    geometry_rejections.append({'street':street,'group_id':group['group_id'],'source_status':source_result['status'],'raw24_status':native_result['status']});offset+=len(line);continue
   existing=labels.get(label)
   if existing:assert type(existing['primary_ref'])is int and 0<=existing['primary_ref']<((1<<19)-1)
   selected.append({'schema':'conservative source-backed new street data example/v1','status':'held_official_name_and_historical_alias_unknown','group':group,'group_id':group['group_id'],'complete_source_node_IDs':ids,'sourcepoint_decimal_strings':point,'native24':native,'native24_degrees':[str(Decimal(n)*Decimal(360)/Decimal(1<<24)) for n in native],'quantization_policy':'Nearest grid Decimal ROUND_HALF_UP; stock rounding unknown.','raw_complete_JSONL_line_SHA256':sha(line),'raw_complete_JSONL_line_bytes':len(line),'complete_line_number':rows,'decompressed_prefix_offset':offset,'within_repeated_first24MiB':offset+len(line)<=REPEAT_D,'source_origin':'Complete prepared OSM-node planning group; all member IDs retained, different_coordinate_nodes0; version/timestamp not in group, full node ledger not opened.','original_city_district_relation':{'stock_city':snapshot['city'],'stock_district':snapshot['district'],'source_raw_city':raw[0],'source_raw_district':raw[1],'normalization':'Explicit 臺中市→台中市 city spelling only; district/street literals unchanged.'},'stock_JAI_name_classification':{'exact_absent_in_complete441_original_family':True,'basis':'Frozen complete original JAI selected-family snapshot, full stock DB not reopened here.','one_character_edit_candidates':near,'either_direction_prefix_candidates':prefixes,'conservative_possible_alias_matches':False,'historical_alias_exclusion_proved':False},'encoding':{'codepage':950,'street_roundtrip':True,'street_hex':street_bytes.hex(),'house_label_roundtrip':True,'house_label_hex':house_bytes.hex(),'street_bytes_with_NUL':len(street_bytes)+1},'house':{'raw_literal':raw[3],'class':'positive_integer','integer':int(raw[3]),'label':label,'existing_label_ref':existing,'existing_label_ref_scope':'Original numeric label text only; no existing-address or route overlap proved.'},'district_membership':{'sourcepoint':source_result,'exact_native24':native_result},'official_street_name_verified':False,'formal_house_address_or_route_verified':False,'record_ID_reserved':False,'IMG_JAI_bundle_created':False})
   chosen_names.add(street);offset+=len(line)
  assert not parse_failures and sig(GROUPS)==before
  counters={'schema':'new explicit repeated/extended bounded source counters/v1','started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'source_path':str(GROUPS.relative_to(ROOT)),'source_file_bytes':before[2],'source_stat_before':before,'source_stat_after':sig(GROUPS),'source_stat_unchanged':True,'source_single_pass_claim':False,'source_prefix_previously_read_in_other_scopes':True,'repeated_part':{'physical_compressed_bytes_read_again':len(repeat_compressed),'compressed_SHA256':sha(repeat_compressed),'decompressed_bytes_produced_again':len(repeat_plain),'decompressed_SHA256':sha(repeat_plain),'complete_rows_wholly_repeated_prefix':repeated_rows,'unconsumed_compressed_tail_passed_to_extension':len(repeated_compressed_tail),'matches_prior3MiB_24MiB_prefix':True},'extension_part':{'new_physical_compressed_bytes_after_first3MiB':len(extra_compressed),'compressed_new_range_start':REPEAT_C,'compressed_new_range_end_exclusive':REPEAT_C+NEW_C,'compressed_new_range_SHA256':sha(extra_compressed),'new_decompressed_output_after_first24MiB':len(extra_plain),'decompressed_extension_SHA256':sha(extra_plain),'complete_rows_finished_after24MiB_including_boundary_crossing':rows-repeated_rows,'uses_previous740947B_unconsumed_tail_plus_new_physical_range':True},'total_this_scope':{'physical_compressed_bytes_read':state['compressed_bytes_actually_read'],'decompressed_bytes_produced':state['decompressed_bytes_produced'],'compressed_budget':REPEAT_C+NEW_C,'decompressed_budget':REPEAT_D+NEW_D,'compressed12MiB_prefix_SHA256':sha(repeat_compressed+extra_compressed),'decompressed96MiB_prefix_SHA256':sha(plain),'complete_JSONL_rows':rows,'complete_JSONL_bytes':len(complete),'partial_final_row_bytes_not_parsed':len(partial),'gzip_EOF':inflater.eof,'gzip_footer_CRC_not_validated':True,'unconsumed_compressed_bytes_after96MiB':len(inflater.unconsumed_tail),'JSONL_parse_failures':parse_failures},'same_city_district_groups_in_prefix':same_admin,'missing_exact_stock_street_groups':missing_groups,'missing_exact_stock_distinct_street_names':len(missing_names),'conservative_ready_group_counts_by_street':conservative_names,'reject_reason_counts':reason_counts,'actual_sourcepoint_membership_calls':geometry_calls['source'],'actual_raw24_membership_calls':geometry_calls['raw24'],'geometry_rejection_statuses':geometry_rejections,'new_source_examples_saved':len(selected),'max_new_examples':2,'old_368_point_or_seven_controls_rerun':False,'no_full_source_EOF_hash_PBF_or_node_ledger':True}
  save('prefix-read-counters.json',counters);save('source-examples.json',selected)
  save('source-pins.json',{'schema':'bounded normal analysis source pins/v1','inputs':INPUTS,'groups_pin_scope':'Separately recorded prefix ranges and unchanged full source stat; no full groups EOF/hash','small_house_label_index':{'compressed_bytes':len(labels_raw),'decompressed_bytes':len(labels_plain),'gzip_EOF':True,'label_rows':len(labels),'historical_AP_label_pool_not_opened':True}})
  proof={'schema':'Beitun new-street bounded ordinary source plan/v1','ordinary_analysis_complete':True,'status':'held_official_and_historical_alias_unknown' if selected else 'held_no_conservative_new_source_in_authorized_prefix','reused_capture_check':reused,'new_prefix_read_explicitly_declared':True,'source_single_pass_claim':False,'source_origin_inherited':source_manifest['source'],'source_examples':'source-examples.json','new_source_example_count':len(selected),'sourcepins':'source-pins.json','read_counters':'prefix-read-counters.json','stock_JAI_family':{'rows':441,'same_stock_city':snapshot['city'],'same_stock_district':snapshot['district'],'actual_original_L2':snapshot['actual_original_L2_fields'],'cached_complete_family_SHA256':'929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6','full_original_DB_not_reopened':True},'actual_new_point_tests':geometry_calls,'saved_examples_both_inside_same_full_source_Beitun_polygon':bool(selected) and all(x['district_membership']['sourcepoint']['eligible'] and x['district_membership']['exact_native24']['eligible'] for x in selected),'old_368_controls_rerun':False,'no_record_ID_reserved_or_bundle_created':True,'official_names_or_historical_aliases_verified':False,'formal_house_or_route_device_acceptance':False,'CP950_encoding_and_integer_house_and_label_refs_in_each_example':True if selected else 'not_assessed_no_example','limits':['Prefix-only source examples, not full Taiwan coverage.','Every chosen name/house/point is from an actual complete prepared group; no names guessed or centroids/nearest roads assigned.','All original source node IDs retained; group lacks original node version/timestamp and the full node ledger is not opened.','Zero conservative edit/prefix matches does not establish absence of historical aliases; official/alias verification held.','Original label ref is text reuse only, not a preexisting address or route.','Source district polygon inclusion is OSM-data geometry evidence, not official territory/address/entrance/routing acceptance.','No IMG/JAI/firmware/device write, native guest, audio or closed suite.'],'App_music_direct_phone_speaker_install_fullTaiwan_flags':False,'native_CPU_execution':False,'device_IO':False,'audio_execution':False,'IMG_JAI_bundle_created':False}
  save('proof.json',proof)
  print(json.dumps({'ordinary_analysis_complete':True,'status':proof['status'],'read_repeat_compressed':len(repeat_compressed),'read_new_compressed':len(extra_compressed),'repeat_decompressed':len(repeat_plain),'new_decompressed':len(extra_plain),'complete_rows':rows,'gzip_EOF':False,'source_single_pass_claim':False,'examples':[{'street':x['group']['raw_address'][2],'house':x['group']['raw_address'][3],'group_id':x['group_id'],'source_ids':x['complete_source_node_IDs'],'native24':x['native24'],'existing_house_label_ref':None if not x['house']['existing_label_ref'] else x['house']['existing_label_ref']['primary_ref'],'both_points_inside_Beitun':True} for x in selected],'sourcepoint_calls':geometry_calls['source'],'raw24_calls':geometry_calls['raw24'],'official_alias_verified':False,'IMG_JAI_bundle_created':False,'device_IO':False},ensure_ascii=False),flush=True)
 except Exception as error:
  save('actual-failure.json',{'schema':'bounded normal data analysis actual failure/v1','phase':phase,'error_type':type(error).__name__,'error':str(error),'observed_read_counters_before_failure':state,'source_single_pass_claim':False,'no_native_guest_device_or_audio':True})
  traceback.print_exc();raise
if __name__=='__main__':main()
