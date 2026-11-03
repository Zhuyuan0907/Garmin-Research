#!/usr/bin/env python3
"""One budgeted ordinary JSONL data prefix. No PBF/node ledger/guest/device.

The complete groups file is deliberately neither read to EOF nor hashed.
At most two non-six-street examples are preserved; counters describe only
this prefix. No official name, house, entrance or routing claim follows.
"""
import sys
sys.dont_write_bytecode = True
import hashlib,json,re,zlib,traceback
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
SOURCE=ROOT/'staging/navigation-taiwan-address-ingestion-v1/address-planning-groups.jsonl.gz'
SNAPSHOT=ROOT/'staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json'
PRIOR=ROOT/'staging/navigation-native-new-street-source-example-v1/final-source-prefix-budget-receipt.json'
CLIMIT=3*1024*1024;DLIMIT=24*1024*1024
def sha(raw):return hashlib.sha256(raw).hexdigest()
def sig(path):
 s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,value):
 with (OUT/name).open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
 assert not (OUT/'prefix-read-receipt.json').exists()
 started=datetime.now(timezone.utc).isoformat();phase='load bounded existing snapshot';read_count=0;plain_count=0
 before=sig(SOURCE)
 try:
  snapshot_raw=SNAPSHOT.read_bytes();prior_raw=PRIOR.read_bytes()
  assert len(snapshot_raw)<350000 and len(prior_raw)<2000
  snapshot=json.loads(snapshot_raw);prior=json.loads(prior_raw)
  assert sha(snapshot_raw)=='929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6'
  assert snapshot['all_assigned_checks_passed'] and len(snapshot['old_info_rows'])==441
  assert snapshot['city']['record']==0x10000008 and snapshot['district']['record']==0x2000004a
  assert before[2]==prior['source_file_bytes']==137633122
  stock={r['label'] for r in snapshot['old_info_rows']}
  phase='single bounded compressed prefix read'
  with SOURCE.open('rb') as f:
   compressed=f.read(CLIMIT);read_count=len(compressed)
   assert read_count==CLIMIT and f.tell()==CLIMIT
  assert sha(compressed)==prior['compressed_prefix_SHA']
  phase='bounded gzip prefix decompression'
  inflater=zlib.decompressobj(16+zlib.MAX_WBITS);plain=inflater.decompress(compressed,DLIMIT);plain_count=len(plain)
  assert plain_count==DLIMIT and not inflater.eof
  phase='complete JSONL rows only'
  offset=0;rows=0;selection=[];selected_names=set();family_counts={};family_ready_counts={};excluded_six=0;not_ready={};parse_failures=[]
  newline=plain.rfind(b'\n');complete=plain[:newline+1];partial=plain[newline+1:]
  for line in complete.splitlines(keepends=True):
   rows+=1
   try:group=json.loads(line)
   except Exception as error:
    parse_failures.append({'line':rows,'decompressed_offset':offset,'raw_line_SHA256':sha(line),'error_type':type(error).__name__,'error':str(error)})
    offset+=len(line);continue
   raw=group.get('raw_address');key=group.get('normalized_planning_key')
   if not isinstance(raw,list) or len(raw)!=4 or not isinstance(key,list) or len(key)!=4:
    offset+=len(line);continue
   city,district,street,label=key
   if city=='台中市' and district=='北屯區' and isinstance(street,str) and street.startswith('敦富'):
    family_counts[street]=family_counts.get(street,0)+1
    if street=='敦富六街':excluded_six+=1
    else:
     reasons=[]
     if raw[0] not in ['台中市','臺中市'] or raw[1]!='北屯區' or raw[2]!=street:reasons.append('raw_admin_or_street_literal_requires_other_normalization')
     if street in stock:reasons.append('exact_stock_street_present')
     if not isinstance(raw[3],str) or not re.fullmatch(r'[1-9][0-9]*',raw[3]) or label!=raw[3]+'號':reasons.append('not_literal_positive_integer_house')
     ids=group.get('source_ids')
     if not isinstance(ids,list) or not ids or len(ids)!=group.get('source_node_count') or any(type(n) is not int or n<=0 for n in ids):reasons.append('incomplete_source_node_IDs')
     if group.get('different_coordinate_nodes')!=0 or group.get('coordinate_selection_ready') is not True or group.get('needs_coordinate_review') is not False:reasons.append('coordinate_selection_unready_or_conflicting')
     if group.get('embedded_floor_unit') or group.get('separate_floor_unit_nodes')!=0:reasons.append('floor_unit_metadata_present')
     try:street.encode('cp950');label.encode('cp950')
     except UnicodeEncodeError:reasons.append('CP950_unencodable')
     if reasons:
      for reason in reasons:not_ready[reason]=not_ready.get(reason,0)+1
     else:
      family_ready_counts[street]=family_ready_counts.get(street,0)+1
      if street not in selected_names and len(selection)<2:
       selected_names.add(street)
       selection.append({'group':group,'raw_complete_JSONL_line_SHA256':sha(line),'raw_complete_JSONL_line_bytes':len(line),'complete_line_number':rows,'decompressed_prefix_offset':offset,'selection_basis':'First ready complete group for a distinct actual Dunfu literal in this prefix; official/alias/district geometry not yet checked.'})
   offset+=len(line)
  assert rows==prior['complete_rows']==46470 and not parse_failures
  assert sig(SOURCE)==before
  receipt={'schema':'bounded ordinary prepared-groups prefix read/v1','started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'source_path':str(SOURCE.relative_to(ROOT)),'source_file_bytes':before[2],'source_stat_before':before,'source_stat_after':sig(SOURCE),'source_stat_unchanged':True,'compressed_byte_budget':CLIMIT,'compressed_bytes_actually_read':read_count,'compressed_prefix_SHA256':sha(compressed),'inherited_prefix_hash_matches':True,'decompressed_byte_budget':DLIMIT,'decompressed_bytes_produced':plain_count,'decompressed_prefix_SHA256':sha(plain),'decompressor_unconsumed_compressed_bytes':len(inflater.unconsumed_tail),'compressed_bytes_consumed_by_decompressor':read_count-len(inflater.unconsumed_tail),'gzip_EOF':inflater.eof,'gzip_footer_CRC_not_validated':True,'complete_JSONL_rows':rows,'complete_JSONL_bytes':len(complete),'partial_final_row_bytes_not_parsed':len(partial),'JSONL_parse_failures':parse_failures,'Dunfu_literal_group_counts_in_exact_admin_prefix':family_counts,'ready_non_six_street_group_counts_in_prefix':family_ready_counts,'not_ready_reason_counts_in_prefix':not_ready,'six_street_groups_excluded_from_new_examples':excluded_six,'new_distinct_street_examples_preserved':len(selection),'maximum_new_examples':2,'bounded_cached_snapshot_SHA256':sha(snapshot_raw),'inherited_prefix_receipt_SHA256':sha(prior_raw),'not_fullsource_scan_or_hash':True,'PBF_or_full_node_ledger_opened':False,'old_368_controls_or_suite_rerun':False,'native_CPU_execution':False,'device_IO':False,'audio_execution':False,'installable':False}
  save('source-examples-at-prefix.json',selection);save('prefix-read-receipt.json',receipt)
  print(json.dumps({'bounded_prefix_read_complete':True,'compressed_bytes_read':read_count,'decompressed_bytes':plain_count,'complete_rows':rows,'gzip_EOF':False,'Dunfu_family_prefix_counts':family_counts,'new_examples':[{'street':r['group']['raw_address'][2],'house':r['group']['raw_address'][3],'group_id':r['group']['group_id'],'source_ids':r['group']['source_ids']} for r in selection],'official_name_verified':False,'native_CPU_execution':False,'device_IO':False},ensure_ascii=False),flush=True)
 except Exception as error:
  failure={'schema':'actual bounded prefix analysis failure/v1','phase':phase,'error_type':type(error).__name__,'error':str(error),'compressed_bytes_actually_read':read_count,'decompressed_bytes_produced':plain_count,'source_stat_before':before,'source_stat_after':sig(SOURCE),'native_CPU_execution':False,'device_IO':False,'official_name_verified':False}
  save('capture-failure.json',failure);traceback.print_exc();raise
if __name__=='__main__':main()
