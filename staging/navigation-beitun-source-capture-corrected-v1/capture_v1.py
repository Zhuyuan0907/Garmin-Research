#!/usr/bin/env python3
"""Corrected ordinary data capture, explicitly rereading a bounded prefix.

Keep every exact-missing prepared group and each hold/witness before example
selection. No full source EOF/hash, PBF/node ledger, IMG/JAI, native guest,
firmware/device/audio. At most two held planning examples; never installable.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib,zlib,re,difflib,importlib.util,traceback
from pathlib import Path
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_UP,InvalidOperation

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
GROUPS=ROOT/'staging/navigation-taiwan-address-ingestion-v1/address-planning-groups.jsonl.gz'
OLD='staging/navigation-beitun-new-street-bounded-source-v1/'
CBUDGET=12*1024*1024;DBUDGET=96*1024*1024;OUTPUT_BUDGET=4*1024*1024
INPUTS=[];WRITTEN=0
def sha(raw):return hashlib.sha256(raw).hexdigest()
def sig(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(relative,limit,expected=None):
 p=ROOT/relative;before=sig(p);assert before[2]<=limit
 raw=p.read_bytes();assert len(raw)==before[2] and sig(p)==before
 if expected:assert sha(raw)==expected,(relative,'pin mismatch')
 INPUTS.append({'path':relative,'bytes':len(raw),'SHA256':sha(raw),'stat_before':before,'stat_after':sig(p)})
 return raw
def load(relative,limit,expected=None):return json.loads(read(relative,limit,expected))
def raw_write(name,raw):
 global WRITTEN
 if WRITTEN+len(raw)>OUTPUT_BUDGET:raise RuntimeError('Output budget exceeded; stop without dropping fields')
 with (OUT/name).open('xb') as f:f.write(raw)
 WRITTEN+=len(raw)
def save(name,data):raw_write(name,(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode())
def one_edit(a,b):
 if abs(len(a)-len(b))>1:return False
 if len(a)==len(b):return sum(x!=y for x,y in zip(a,b))<=1
 if len(a)>len(b):a,b=b,a
 return any(a==b[:i]+b[i+1:] for i in range(len(b)))
def name_shape(street):
 if any(phrase in street for phrase in ['交叉口','交會處','交會口']) or re.search(r'[&/／×+]',street):
  return {'kind':'intersection_expression_held','flat_eligible':False,'basis':'Complete intersection phrase or separator, not isolated交/叉/口.'}
 if street.endswith(('巷','弄')):
  return {'kind':'lane_alley_existing_branch','flat_eligible':False,'basis':'Full name terminates in巷/弄; retain for existing branch pipeline.'}
 match=re.fullmatch(r'(?P<base>[\u3400-\u9fffA-Za-z0-9·．]+[路街])(?P<section>[一二三四五六七八九十百0-9]+段)?',street)
 if match:
  return {'kind':'sectioned_flat_road_or_street' if match.group('section') else 'flat_road_or_street','flat_eligible':True,'base':match.group('base'),'section':match.group('section'),'basis':'Whole name ending路/街 with optional numbered段; no individual-character blacklist.'}
 return {'kind':'other_full_name_shape_held','flat_eligible':False,'basis':'Does not fit this whole road/street or numbered section shape; not a statement of name invalidity.'}
def codec(text):
 try:
  raw=text.encode('cp950');return {'roundtrip':raw.decode('cp950')==text,'hex':raw.hex(),'bytes':len(raw)}
 except (UnicodeEncodeError,UnicodeDecodeError,AttributeError) as error:
  return {'roundtrip':False,'error_type':type(error).__name__,'error':str(error)}
def point_info(value):
 result={'original_first_coordinate':value,'valid_global_and_OSM_precision':False,'native24':None,'native24_degrees':None}
 try:
  if not isinstance(value,list) or len(value)!=2 or any(not isinstance(v,str) for v in value):return result
  lat,lon=[Decimal(v) for v in value]
  if not lat.is_finite() or not lon.is_finite() or not -90<=lat<=90 or not -180<=lon<180:return result
  if any(v*10_000_000!=(v*10_000_000).to_integral_value() for v in [lat,lon]):return result
  signed=[int((v*Decimal(1<<24)/Decimal(360)).to_integral_value(rounding=ROUND_HALF_UP)) for v in [lat,lon]]
  native=[n&0xffffff for n in signed]
  result.update(valid_global_and_OSM_precision=True,native24=native,signed24=signed,native24_degrees=[str(Decimal(n)*Decimal(360)/Decimal(1<<24)) for n in signed],quantization_policy='Nearest Decimal ROUND_HALF_UP; stock rounding unknown.')
 except (InvalidOperation,ValueError,TypeError):pass
 return result
class BoundedCapture:
 def __init__(self,limit):
  self.limit=limit;self.encoder=zlib.compressobj(level=9,wbits=31);self.chunks=[];self.bytes=0;self.rows=0;self.plain_bytes=0;self.digest=hashlib.sha256();self.truncated=False;self.closed=False
 def add(self,row):
  line=(json.dumps(row,ensure_ascii=False,separators=(',',':'),sort_keys=True)+'\n').encode()
  preview=self.encoder.copy();complete_tail=preview.compress(line)+preview.flush()
  if self.bytes+len(complete_tail)>self.limit:
   self.truncated=True;return False
  chunk=self.encoder.compress(line);self.chunks.append(chunk);self.bytes+=len(chunk);self.rows+=1;self.plain_bytes+=len(line);self.digest.update(line);return True
 def finish(self):
  if self.closed:return None
  tail=self.encoder.flush();self.chunks.append(tail);self.bytes+=len(tail);assert self.bytes<=self.limit;self.closed=True
  data=b''.join(self.chunks);raw_write('missing-source-groups.jsonl.gz',data)
  return {'path':'missing-source-groups.jsonl.gz','compressed_bytes':len(data),'SHA256':sha(data),'decompressed_bytes':self.plain_bytes,'decompressed_SHA256':self.digest.hexdigest(),'complete_rows':self.rows,'gzip_closed':True,'capture_limit_bytes':self.limit,'truncated':self.truncated,'no_record_fields_silently_dropped':True}
def witnesses(street,stock_rows):
 near=[];prefix=[]
 for row in stock_rows:
  base={'stock_label':row['label'],'stock_info_id':row['info_id'],'stock_record':row['record'],'stock_index_token':row['index_record'],'verified_alias':False}
  if one_edit(row['label'],street):near.append(dict(base,relation='single_character_edit_candidate'))
  relation=[]
  if street.startswith(row['label']):relation.append('candidate_starts_stock_name')
  if row['label'].startswith(street):relation.append('stock_starts_candidate_name')
  if relation:prefix.append(dict(base,relation=relation))
 return near,prefix
def classify(group,stock_rows):
 raw=group['raw_address'];city,district,street,label=group['normalized_planning_key'];ids=group.get('source_ids')
 shape=name_shape(street);encoding={'codepage':950,'street':codec(street),'house_label':codec(label)};point=point_info(group.get('first_coordinate'));near,prefix=witnesses(street,stock_rows)
 plain=bool(isinstance(raw[3],str) and re.fullmatch(r'[1-9][0-9]*',raw[3]) and label==raw[3]+'號')
 prior368=street=='敦富六街' and raw[3]=='368' and ids==[8280986017]
 flags={'literal_admin_and_street_unchanged':raw[0] in ['臺中市','台中市'] and raw[1]=='北屯區' and raw[2]==street,'source_ID_metadata_complete':isinstance(ids,list) and bool(ids) and len(ids)==group.get('source_node_count') and len(set(ids))==len(ids) and all(type(n)is int and n>0 for n in ids),'coordinate_selection_metadata_ready':group.get('different_coordinate_nodes')==0 and group.get('coordinate_selection_ready') is True and group.get('needs_coordinate_review') is False,'first_coordinate_valid_global_and_OSM_precision':point['valid_global_and_OSM_precision'],'plain_integer_house_and_label_agree':plain,'no_floor_unit_metadata':not group.get('embedded_floor_unit') and group.get('separate_floor_unit_nodes')==0,'CP950_street_and_house_roundtrip':encoding['street']['roundtrip'] and encoding['house_label']['roundtrip'],'whole_flat_road_or_street_shape':shape['flat_eligible'],'not_prior_closed_source368':not prior368}
 hard_holds=[name for name,passed in flags.items() if not passed]
 relation_holds=['held_alias_relation'] if near or prefix else []
 holds=hard_holds+relation_holds+['official_name_and_historical_alias_unverified']
 old_holds=[]
 if street=='敦富六街':old_holds.append('already_closed_six_street_excluded')
 if not flags['literal_admin_and_street_unchanged']:old_holds.append('nonliteral_raw_admin_or_street_normalization')
 if not re.fullmatch(r'[\u3400-\u9fff]{2,14}[路街]',street) or re.search(r'[巷弄之段村里鄰交叉口]',street):old_holds.append('not_conservative_flat_road_or_street_literal')
 if not plain:old_holds.append('not_literal_positive_integer_house')
 if not flags['source_ID_metadata_complete']:old_holds.append('incomplete_or_invalid_source_IDs')
 if not flags['coordinate_selection_metadata_ready']:old_holds.append('coordinate_conflict_or_unready')
 if not flags['no_floor_unit_metadata']:old_holds.append('floor_unit_metadata_present')
 if near or prefix:old_holds.append('possible_spelling_or_prefix_alias_relation')
 if not flags['CP950_street_and_house_roundtrip']:old_holds.append('CP950_roundtrip_failure')
 return {'name_shape':shape,'data_flags':flags,'hard_data_holds':hard_holds,'relationship_holds':relation_holds,'all_hold_reasons':holds,'technical_planning_eligible':not hard_holds,'official_alias_or_formal_address_verified':False,'old_rule_reasons_recomputed_for_same_group':old_holds,'near_stock_witnesses':near,'prefix_stock_witnesses':prefix,'encoding':encoding,'house_class':'plain_positive_integer' if plain else 'non_plain_integer_existing_or_review_branch','point':point}
def main():
 global WRITTEN
 assert not (OUT/'proof.json').exists();WRITTEN=sum(p.stat().st_size for p in OUT.iterdir() if p.is_file())
 started=datetime.now(timezone.utc).isoformat();phase='small pinned dependencies';state={'source_compressed_bytes_actually_read':0,'source_decompressed_bytes_produced':0};capture=None;capture_identity=None
 try:
  source_code=read(str(Path(__file__).relative_to(ROOT)),38000)
  old_source=read(OLD+'analyze_v1.py',22000,'25b98dbaab0978ca54f689a209f85aba0bc38e2de45c4bda74df6654095cb052')
  diff=''.join(difflib.unified_diff(old_source.decode().splitlines(keepends=True),source_code.decode().splitlines(keepends=True),fromfile=OLD+'analyze_v1.py',tofile=str(Path(__file__).relative_to(ROOT))))
  raw_write('corrected-source.diff',diff.encode())
  snapshot=load('staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json',350000,'929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6');stock_rows=snapshot['old_info_rows'];stock={r['label'] for r in stock_rows}
  assert snapshot['all_assigned_checks_passed'] and len(stock_rows)==441 and snapshot['city']['record']==0x10000008 and snapshot['district']['record']==0x2000004a
  old=load(OLD+'prefix-read-counters.json',6000);load(OLD+'source-examples.json',1000)
  ingestion=load('staging/navigation-taiwan-address-ingestion-v1/ingestion-summary.json',65000)
  ingestion_source=read('staging/navigation-taiwan-address-ingestion-v1/prepare_taiwan_address_ingestion.py',40000)
  assert "city, district, street, house = [tags.get('addr:' + k, '') for k in ('city', 'district', 'street', 'housenumber')]" in ingestion_source.decode()
  hp=load('staging/navigation-native-house-label-index-v1/proof.json',40000,'793ad2853b07ee3940d0e4f44b39809c612b4ed2de5632387b3a7c36123ed3b4')
  labels_raw=read('staging/navigation-native-house-label-index-v1/house-labels.jsonl.gz',270000,hp['ledger_sha256']);li=zlib.decompressobj(31);labels_plain=li.decompress(labels_raw,8*1024*1024)
  assert li.eof and not li.unconsumed_tail and not li.unused_data
  labels={}
  for line in labels_plain.splitlines():
   row=json.loads(line);assert row['label'] not in labels;labels[row['label']]=row
  assert len(labels)==hp['distinct_integer_or_subnumber_house_labels']==50567
  api='staging/navigation-beitun-district-geometry-v1/beitun_membership.py';read(api,7000)
  for path,limit,pin in [('staging/navigation-beitun-district-geometry-v1/geometry.json',150000,'c4b4c2a842af2042ca4fff893fb9e5ccd33940ffe27e445aa3222121269d49b3'),('staging/navigation-beitun-district-geometry-v1/proof.json',11000,'7000011d0cc84272d0ceb4a23b23e8dc2097cf414b9b0b4fea7dd0bbd82cd4e1'),('staging/navigation-beitun-district-geometry-v1/source-membership.json',5000,'d624ec02eb3b79331cd4041a77a093b4dcf2bc14765578eca70196f88a9e0e84'),('staging/navigation-country-merge-independent-review-v1/review_country_merge.py',36000,'7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec')]:read(path,limit,pin)
  spec=importlib.util.spec_from_file_location('beitun_corrected_capture_geometry',ROOT/api);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);membership=module.BeitunMembership()
  phase='new explicitly declared bounded reread12MiB/96MiB'
  before=sig(GROUPS);assert before==old['source_stat_after'] and before[2]==137633122
  with GROUPS.open('rb') as f:
   first=f.read(3*1024*1024);rest=f.read(9*1024*1024);state['source_compressed_bytes_actually_read']=len(first)+len(rest);assert f.tell()==CBUDGET
  assert len(first)==3*1024*1024 and len(rest)==9*1024*1024
  inflater=zlib.decompressobj(31);first_plain=inflater.decompress(first,24*1024*1024);tail=inflater.unconsumed_tail;rest_plain=inflater.decompress(tail+rest,72*1024*1024)
  plain=first_plain+rest_plain;state['source_decompressed_bytes_produced']=len(plain)
  assert len(first_plain)==24*1024*1024 and len(rest_plain)==72*1024*1024 and not inflater.eof
  assert sha(first)==old['repeated_part']['compressed_SHA256'] and sha(first_plain)==old['repeated_part']['decompressed_SHA256']
  assert sha(first+rest)==old['total_this_scope']['compressed12MiB_prefix_SHA256'] and sha(plain)==old['total_this_scope']['decompressed96MiB_prefix_SHA256']
  assert sig(GROUPS)==before
  newline=plain.rfind(b'\n');complete=plain[:newline+1];partial=plain[newline+1:]
  phase='capture every exact-missing group before planning selection'
  capture=BoundedCapture(OUTPUT_BUDGET-WRITTEN-512*1024)
  counts={'complete_prefix_rows_available':complete.count(b'\n'),'rows_processed':0,'same_admin_groups':0,'exact_stock_groups':0,'exact_missing_groups_seen':0,'exact_missing_groups_captured':0,'parse_failures':[],'output_truncated':False,'sourcepoint_calls':0,'raw24_calls':0,'old_source368_membership_calls':0}
  mapping={};old_counts={};examples=[];chosen=set();assessment=[];offset=0
  for line in complete.splitlines(keepends=True):
   counts['rows_processed']+=1
   try:group=json.loads(line)
   except Exception as error:
    counts['parse_failures'].append({'line':counts['rows_processed'],'offset':offset,'error':str(error),'SHA256':sha(line)});offset+=len(line);continue
   key=group.get('normalized_planning_key',[]);raw=group.get('raw_address',[])
   if len(key)!=4 or len(raw)!=4 or key[:2]!=['台中市','北屯區']:
    offset+=len(line);continue
   counts['same_admin_groups']+=1;street=key[2]
   if street in stock:counts['exact_stock_groups']+=1;offset+=len(line);continue
   counts['exact_missing_groups_seen']+=1;classification=classify(group,stock_rows)
   original_four_tags=dict(zip(['addr:city','addr:district','addr:street','addr:housenumber'],raw))
   record={'schema':'complete prepared exact-missing group capture/v1','original_prepared_group':group,'source_complete_JSONL_line_SHA256':sha(line),'source_line_bytes':len(line),'source_complete_line_number':counts['rows_processed'],'source_decompressed_prefix_offset':offset,'original_first_node_addr_tag_subset':original_four_tags,'tag_subset_basis':'Ingestion source reads these four exactaddr: keys into raw_address; values belong to first node in prepared group.','original_first_node_ID':group['source_ids'][0],'full_original_tags_per_node':None,'unavailable_input_fields':['Per-node complete tag dictionaries including otheraddr: keys','Other member raw_address variants','Per-node alternate coordinates when groupconflict exists','Original node version and timestamp'],'classification':classification,'source_city_district_relation':{'stock_city':snapshot['city'],'stock_district':snapshot['district'],'raw_city':raw[0],'raw_district':raw[1],'basis':'Exact original441 street-family native city/district; only city臺→台 normalization.'},'formal_address_alias_or_route_verified':False,'record_ID_reserved':False}
   if not capture.add(record):counts['output_truncated']=True;break
   counts['exact_missing_groups_captured']+=1
   entry=mapping.setdefault(street,{'candidate_literal':street,'group_ids':[],'source_group_capture_lines':[],'raw_house_literals':[],'name_shapes':[],'hold_reason_group_counts':{},'old_rule_reason_group_counts':{},'stock_nearby_witnesses':{'single_character_edit':classification['near_stock_witnesses'],'prefix':classification['prefix_stock_witnesses']},'technical_planning_group_count':0,'alias_relationship_verified':False,'complete_prepared_groups_saved':True,'full_original_per_node_tags_available':False})
   entry['group_ids'].append(group['group_id']);entry['source_group_capture_lines'].append(capture.rows);entry['raw_house_literals'].append(raw[3])
   if classification['name_shape']['kind'] not in entry['name_shapes']:entry['name_shapes'].append(classification['name_shape']['kind'])
   for reason in classification['all_hold_reasons']:entry['hold_reason_group_counts'][reason]=entry['hold_reason_group_counts'].get(reason,0)+1
   for reason in classification['old_rule_reasons_recomputed_for_same_group']:
    old_counts[reason]=old_counts.get(reason,0)+1;entry['old_rule_reason_group_counts'][reason]=entry['old_rule_reason_group_counts'].get(reason,0)+1
   if classification['technical_planning_eligible']:entry['technical_planning_group_count']+=1
   # Capture is committed before this gate; edit/prefix never drops source.
   if classification['technical_planning_eligible'] and street not in chosen and len(examples)<2:
    point=group['first_coordinate'];native=classification['point']['native24']
    a=membership.assess_source_point('台中市','北屯區',*point);counts['sourcepoint_calls']+=1
    b=membership.assess_raw24('台中市','北屯區',*native);counts['raw24_calls']+=1
    test={'group_id':group['group_id'],'source_capture_line':capture.rows,'sourcepoint':a,'exact_native24':b,'both_inside':a['eligible'] and b['eligible']};assessment.append(test)
    if test['both_inside']:
     reusable=labels.get(key[3])
     if reusable:assert type(reusable['primary_ref'])is int and 0<=reusable['primary_ref']<(1<<19)-1
     examples.append({'candidate_literal':street,'status':'held_alias_relation' if classification['relationship_holds'] else 'held_official_name_and_historical_alias_unknown','source_group_capture_line':capture.rows,'complete_original_prepared_group':group,'complete_source_node_IDs':group['source_ids'],'original_first_node_addr_tag_subset':original_four_tags,'full_original_tags_per_node':None,'sourcepoint':point,'native24':native,'native24_degrees':classification['point']['native24_degrees'],'classification':classification,'house_integer':int(raw[3]),'house_label':key[3],'original_house_label_ref':reusable,'original_house_label_ref_text_only_not_address_overlap':True,'district_membership':test,'formal_address_route_alias_or_official_name_verified':False,'record_ID_reserved':False,'IMG_JAI_or_install_bundle_created':False})
     chosen.add(street)
   offset+=len(line)
  capture_identity=capture.finish()
  assert not counts['parse_failures'] and sig(GROUPS)==before
  if not counts['output_truncated']:
   assert counts['rows_processed']==counts['complete_prefix_rows_available']==old['total_this_scope']['complete_JSONL_rows']==198103
   assert counts['same_admin_groups']==548 and counts['exact_stock_groups']==446 and counts['exact_missing_groups_captured']==counts['exact_missing_groups_seen']==102 and len(mapping)==28
   expected={k:v for k,v in old['reject_reason_counts'].items() if k!='exact_stock_street_present'}
   assert old_counts==expected,('same old reason counts did not replay',old_counts,expected)
  roster=[mapping[name] for name in sorted(mapping)]
  save('hold-mapping.json',{'schema':'all captured exact-missing literals/group holds/stock witnesses/v1','roster':roster,'literal_count':len(roster),'captured_complete_groups':capture.rows,'old_reason_counts_recomputed':old_counts,'names_or_reasons_truncated':counts['output_truncated'],'alias_relations_not_verified':True,'source_capture':capture_identity})
  save('planning-examples.json',examples);save('new-membership-assessments.json',assessment)
  table=['| Candidate literal | Groups / planning eligible | Stock nearby witnesses | Holds | Complete prepared source |','|---|---|---|---|---|']
  for row in roster:
   witness_names=sorted({v['stock_label'] for values in row['stock_nearby_witnesses'].values() for v in values});table.append('| '+row['candidate_literal']+' | '+str(len(row['group_ids']))+' / '+str(row['technical_planning_group_count'])+' | '+('、'.join(witness_names) or '無edit/prefix witness')+' | '+', '.join(row['hold_reason_group_counts'])+' | saved全group；完整逐node tags缺 |')
  raw_write('hold-mapping-table.md',('\n'.join(table)+'\n').encode())
  reread={'schema':'corrected explicit bounded source reread counters/v1','started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'source_path':str(GROUPS.relative_to(ROOT)),'source_file_bytes':before[2],'source_stat_before':before,'source_stat_after':sig(GROUPS),'source_stat_unchanged':True,'source_single_pass_claim':False,'all12MiB_compressed_and96MiB_plaintext_are_rereads_of_previously_pinned_prefix':True,'first_repeated_range':{'compressed_bytes':len(first),'decompressed_bytes':len(first_plain),'compressed_SHA256':sha(first),'decompressed_SHA256':sha(first_plain)},'later_repeated_range':{'compressed_offset':len(first),'compressed_bytes':len(rest),'decompressed_offset':len(first_plain),'decompressed_bytes':len(rest_plain),'compressed_SHA256':sha(rest),'decompressed_SHA256':sha(rest_plain),'unconsumed_first_range_bytes_used':len(tail)},'total_this_scope':dict(state,compressed_budget=CBUDGET,decompressed_budget=DBUDGET,compressed_prefix_SHA256=sha(first+rest),decompressed_prefix_SHA256=sha(plain),gzip_EOF=inflater.eof,gzip_footer_CRC_not_validated=True,complete_rows_available=complete.count(b'\n'),partial_final_row_bytes_not_parsed=len(partial),unconsumed_compressed_bytes=len(inflater.unconsumed_tail)),'classification_counts':counts,'capture_output':capture_identity,'total_output_byte_budget':OUTPUT_BUDGET,'old_prefix_source_pins_and_old_reason_counts_reproduced':not counts['output_truncated'],'fullsource_EOF_hash_PBF_nodeledger_IMG_or_DB_not_opened':True}
  save('read-counters.json',reread)
  save('source-pins.json',{'schema':'corrected ordinary source/dependency pins/v1','inputs':INPUTS,'large_source_only_bounded_prefix_pins':'read-counters.json','small_original_house_label_index':{'compressed_bytes':len(labels_raw),'decompressed_bytes':len(labels_plain),'gzip_EOF':True,'labels':len(labels),'ledger_not_source_node_ledger':True}})
  proof={'schema':'corrected all-missing Beitun source capture/v1','ordinary_data_capture_complete':not counts['output_truncated'],'status':'truncated_output_budget_stop' if counts['output_truncated'] else ('held_planning_examples_captured' if examples else 'held_truezero_planning_examples'),'source_prefix_explicitly_reread':True,'source_single_pass_claim':False,'source_origin_inherited':ingestion['source'],'all_exact_missing_groups_captured':not counts['output_truncated'],'missing_group_count':counts['exact_missing_groups_captured'],'missing_literal_names':sorted(mapping),'missing_literal_count':len(mapping),'previous28_count_reproduced':len(mapping)==28 and not counts['output_truncated'],'old28_literal_set_direct_comparison':'Old list was never saved; count/source-prefix/stock-family/old-reason replay comparisons are available, not an old literal-list comparison.','old28_source_prefix_and_classification_counter_replay':not counts['output_truncated'],'complete_groups_gzip':capture_identity,'hold_mapping':'hold-mapping.json','mapping_table':'hold-mapping-table.md','planning_examples':'planning-examples.json','planning_example_count':len(examples),'max_examples':2,'new_membership_assessments':'new-membership-assessments.json','actual_new_sourcepoint_calls':counts['sourcepoint_calls'],'actual_new_native24_calls':counts['raw24_calls'],'old_source368_or_seven_controls_rerun':False,'near_prefix_witnesses_are_pending_relationships_only':True,'original_four_addr_tags_of_first_node_preserved':True,'full_original_per_node_tags_versions_timestamps_or_conflict_coordinates_available':False,'unavailable_input_fields_explicitly_marked_not_invented':True,'record_IDs_reserved':False,'formal_address_route_official_alias_or_install_acceptance':False,'output_budget_bytes':OUTPUT_BUDGET,'known_output_bytes_before_receipts_handoff_seal':WRITTEN,'App_native_backend_music_direct_phone_speaker_install_fullTaiwan_flags':False,'native_guest_or_firmware_execution':False,'device_IO':False,'audio_execution':False,'IMG_JAI_or_install_bundle_created':False}
  save('proof.json',proof)
  for row in INPUTS:assert sig(ROOT/row['path'])==row['stat_after'] and sha((ROOT/row['path']).read_bytes())==row['SHA256']
  print(json.dumps({'ordinary_data_capture_complete':not counts['output_truncated'],'explicit12_96MiB_reread':True,'source_single_pass_claim':False,'complete_prefix_rows_processed':counts['rows_processed'],'missing_groups_captured':counts['exact_missing_groups_captured'],'missing_names_preserved':len(mapping),'previous28_count_and_old_rule_counters_reproduced':not counts['output_truncated'],'source_capture_gzip_bytes':capture_identity['compressed_bytes'],'output_bytes_so_far':WRITTEN,'output_budget':OUTPUT_BUDGET,'truncated':counts['output_truncated'],'planning_examples':[{'street':e['candidate_literal'],'house':e['house_label'],'group_id':e['complete_original_prepared_group']['group_id'],'source_ids':e['complete_source_node_IDs'],'sourcepoint':e['sourcepoint'],'native24':e['native24'],'status':e['status'],'both_points_inside_Beitun':e['district_membership']['both_inside'],'original_house_label_ref':None if not e['original_house_label_ref'] else e['original_house_label_ref']['primary_ref']} for e in examples],'new_sourcepoint_calls':counts['sourcepoint_calls'],'new_raw24_calls':counts['raw24_calls'],'old_source368_tests':0,'full_original_node_tags_available':False,'formal_alias_address_route_install_acceptance':False,'native_guest_device_audio':False},ensure_ascii=False),flush=True)
 except Exception as error:
  if capture is not None and not capture.closed:
   capture_identity=capture.finish()
  save('actual-failure.json',{'schema':'corrected bounded data actual failure/v1','phase':phase,'error_type':type(error).__name__,'error':str(error),'observed_read_counters':state,'partial_complete_capture_if_any':capture_identity,'truncated':True,'source_single_pass_claim':False,'native_guest_device_audio':False})
  traceback.print_exc();raise
if __name__=='__main__':main()
