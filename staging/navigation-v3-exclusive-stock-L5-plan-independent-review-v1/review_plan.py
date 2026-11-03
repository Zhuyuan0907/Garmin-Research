#!/usr/bin/env python3
"""Finite independent artifact/data review; no IMG, scanner or producer run."""
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
import ast,gzip,hashlib,io,json,os,struct,traceback

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
IN=ROOT/'staging/navigation-v3-exclusive-stock-L5-reuse-feasibility-v1'
L4=ROOT/'staging/navigation-v3-exclusive-stock-L4-reuse-feasibility-v1'
V5=ROOT/'staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5'
CAP=1048576;DECOMP_CAP=8388608;PREVIEW_BYTES=109389
STATE={'phase':'initial','artifact_bytes':PREVIEW_BYTES,'decompressed_bytes':0,'inputs':[]}
PINS={'sealed-files.json':'3470bc9131486b71a3e661c95d9a85399c6e44c7aef72bc7f475d2b4a125ceba',
 'scope-summary.json':'3b68757d856d0efbd9cc1d3cd7ad33ba80c92a438cd2a969057690c466680d4a',
 'proof.json':'a4e321c6ac8c2be69cab45e147ac459b7f943db3fed45cd40ba5f91f58d59c50',
 'reuse-L5-group-plan.json.gz':'82f837f5f393dcee80c564a95780c088b1514086bd1bd814c864ca40b8707c17'}

def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(n,v):
 b=(json.dumps(v,ensure_ascii=False,indent=2)+'\n').encode();p=OUT/n
 with p.open('x') as f:f.write(b.decode());f.flush();os.fsync(f.fileno())
 return {'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b)}
def read(p,pin,row=None):
 need(p.parent in (IN,L4,V5) and p.is_file() and not p.is_symlink(),'Exact small artifact/code allowlist')
 before=stat(p);need(STATE['artifact_bytes']+before[2]<=CAP,'Total artifact input1MiB, previews included')
 if row is not None:need(before==row['stat_at_seal'],'Exact producer sealed source fullstat')
 with p.open('rb') as f:b=f.read(before[2]+1);need(f.read(1)==b'','Complete small artifact EOF')
 STATE['artifact_bytes']+=len(b)
 need(len(b)==before[2] and stat(p)==before and (pin is None or sha(b)==pin),'Actual complete artifact hash/stat pin')
 need(p.stat().st_mode&0o777==0o444,'Closed source mode0444')
 STATE['inputs'].append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b),
  'stat_before':before,'stat_after':stat(p),'EOF_verified':True})
 return b
def decompress(raw,label):
 declared=struct.unpack('<I',raw[-4:])[0];remaining=DECOMP_CAP-STATE['decompressed_bytes']
 need(0<declared<=remaining,'Declared'+label+' ISIZE within remaining8MiB before decoding')
 result=bytearray();h=hashlib.sha256()
 with gzip.GzipFile(fileobj=io.BytesIO(raw),mode='rb') as f:
  while True:
   b=f.read(min(65536,remaining-len(result)+1))
   if not b:break
   result.extend(b);h.update(b);need(len(result)<=remaining,'Actual aggregate gzip8MiB hard cap')
   STATE['decompressed_bytes']+=len(b)
 need(len(result)==declared,'Gzip complete CRC/EOF/ISIZE'+label)
 return json.loads(result),{'label':label,'gzip_bytes':len(raw),'decompressed_bytes':len(result),'decompressed_sha256':h.hexdigest()}
def arithmetic(components,saved):
 old5=3074293;new5=old5-saved;oldbytes=(old5*126+7)//8;newbytes=(new5*126+7)//8
 mdr=131330140-oldbytes+newbytes;sizes=dict(components);sizes['00004171.MDR']=mdr
 blocks={k:(v+4095)//4096 for k,v in sizes.items()};parts={k:(v+239)//240 for k,v in blocks.items()}
 rows=1+sum(parts.values());metadata=max(73728,((4096+rows*512+4095)//4096)*4096);image=metadata+4096*sum(blocks.values())
 return {'retained_counts':{'4':3781594,'5':new5,'6':2062771},'retained_L5_bits':new5*126,'retained_L5_bytes':newbytes,
  'old_L5_retained_bytes':oldbytes,'net_logical_MDR_saved_bytes':oldbytes-newbytes,'MDR_bytes':mdr,
  'full_six_component_sizes':sizes,'4K_blocks':blocks,'component_FAT_parts':parts,'root_plus_component_FAT_rows':rows,
  'metadata_bytes':metadata,'projected_IMG_bytes':image,'capacity_margin':134217728-image,
  'fits_original_4K_arithmetic':image<=134217728}
def fields126(x):
 return {'mapordinal':x&1,'primary_ref_word':(x>>1)&524287,'secondary_ref_word':(x>>20)&524287,
         'first_child':(x>>39)&2097151,'count':(x>>60)&511,'rawflag':(x>>69)&511,
         'coord_raw24':[(x>>78)&16777215,(x>>102)&16777215]}
def disjoint(rows,key):
 ranges=sorted((r[key],r[key]+r['count']-1,r['parent_context']) for r in rows)
 need(all(a[1]<b[0] for a,b in zip(ranges,ranges[1:])),'All1636'+key+' ranges pairwise disjoint')

def main():
 need(not (OUT/'proof.json').exists() and not (OUT/'actual-failure.json').exists(),'Fresh finite review only')
 names=['sealed-files.json','scope-summary.json','proof.json','reuse-L5-group-plan.json.gz','measure_l5_reuse.py',
 'actual-raw126-row-samples.json','actual-handle-read-closure.json','actual-exec-terminal-receipt.json',
 'actual-sealer-terminal-receipt.json','capacity-arithmetic.json','actual-L5-read-budget-preflight.json',
 'mapper-global-preflight.json','actual-rejected-L5-groups.json.gz']
 more=[L4/'sealed-files.json',L4/'scope-summary.json',L4/'reuse-root-plan.json.gz',
       V5/'proof.json',V5/'feasibility-summary.json',V5/'actual-stream-read-receipts.json']
 sizes={str((IN/n).relative_to(ROOT)):(IN/n).stat().st_size for n in names}
 sizes.update({str(p.relative_to(ROOT)):p.stat().st_size for p in more})
 projected=PREVIEW_BYTES+sum(sizes.values());need(projected<=CAP,'All selected artifact preflight within unchanged1MiB')
 save('budget-preflight.json',{'artifact_cap':CAP,'decompressed_cap':DECOMP_CAP,'prior_preview_bytes':PREVIEW_BYTES,
  'projected_complete_artifact_bytes':projected,'file_bytes':sizes,'IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO':0})
 seal=json.loads(read(IN/'sealed-files.json',PINS['sealed-files.json']));rows={r['path']:r for r in seal['files']}
 def load(n):
  p=IN/n;r=rows[str(p.relative_to(ROOT))];return json.loads(read(p,PINS.get(n,r['sha256']),r))
 summary=load('scope-summary.json');proof=load('proof.json')
 seal4=json.loads(read(L4/'sealed-files.json','4de5e8108e4760f34451c75654eac76d81184f2f1aaab87d71855c2e6c9d1246'))
 rows4={r['path']:r for r in seal4['files']}
 sum4=json.loads(read(L4/'scope-summary.json','31ff1e560798e9c772cb5cdb01682aa049ba161b80c82d071e0715751e116ec9',rows4[str((L4/'scope-summary.json').relative_to(ROOT))]))
 p=L4/'reuse-root-plan.json.gz';plan4,d4=decompress(read(p,'d8ae42d789ed5449657f5065ee703c7b731d02dd0f078ec88684407d90120a09',rows4[str(p.relative_to(ROOT))]),'closedL4')
 prior4={r['root_ID']:r for r in plan4['roots']}
 need(len(prior4)==1251 and sum(r['count'] for r in prior4.values())==108235 and sum4['arithmetic']['MDR_bytes']==131330140,
      'Complete sealed L4 plan and numerical baseline')
 p=IN/'reuse-L5-group-plan.json.gz';plan,d5=decompress(read(p,PINS[p.name],rows[str(p.relative_to(ROOT))]),'L5')
 save('actual-gzip-EOF-receipts.json',{'gzip_streams':[d4,d5],'aggregate_cap':DECOMP_CAP,
  'actual_decompressed_bytes':STATE['decompressed_bytes'],'complete_CRC_EOF_verified':True})
 groups=plan['groups'];need(plan['schema']=='exclusive-stock-L5-reuse-readonly-plan/v1' and len(groups)==1636,'Complete1636 groups')
 STATE['phase']='complete parent/ranges/unaligned geometry'
 bycontext={};kinds=Counter();dest=Counter();shiftpairs=Counter();total=edits=0;rolling=hashlib.sha256();mask3=((1<<35)-1)<<20;mask4=((1<<32)-1)<<39
 ts={tag:{r['level']:r for r in data} for tag,data in proof['actual_all_six_table_profiles'].items()}
 for r in groups:
  context=r['parent_context'];need(context not in bycontext,'All1636 unique parent contexts');bycontext[context]=r
  root=r['root_ID'];old,new,n=r['oldfirst'],r['newfirst'],r['count']
  need(all(isinstance(v,int) and not isinstance(v,bool) for v in (root,old,new,n)) and
       1<=root<=47870 and 1<=n<=4095 and 1<=old<=old+n-1<=2341096 and
       2341096<new<=new+n-1<=3077845,'All exact bounded oldstockL5/new poststock ranges')
  kinds[r['kind']]+=1
  if r['kind']=='L3':
   need(context=='L3:'+str(root),'Direct root context string')
   a=bytes.fromhex(r['old_parent112']);b=bytes.fromhex(r['new_parent112']);need(len(a)==len(b)==14,'True complete112bit parent prefixes')
   x=int.from_bytes(a,'little');y=int.from_bytes(b,'little')
   need((x^y)&~mask3==0 and (x>>55)&511==(y>>55)&511==r['parent_rawflag'] and r['parent_rawflag']&7==5,
        'DirectL3 parent highflags/nonpointer bits unchanged')
   need((x>>20)&8388607==old and (y>>20)&8388607==new and (x>>43)&4095==(y>>43)&4095==n,
        'Actual directL3 parent ranges match complete plan')
   need(r['combined_parent_ID_before_future_suffix_rank']==root,'DirectL3 ID remains exact');dest['L3']+=1
  elif r['kind']=='L4':
   ordinal=r['ordinal'];need(context=='L3:'+str(root)+'/L4ordinal:'+str(ordinal),'L4 parent context string')
   a=bytes.fromhex(r['old_parent128']);b=bytes.fromhex(r['new_parent128']);need(len(a)==len(b)==16,'Complete128bit parent prefixes')
   x=int.from_bytes(a,'little');y=int.from_bytes(b,'little')
   need((x^y)&~mask4==0 and (x>>71)&511==(y>>71)&511==r['parent_rawflag'] and r['parent_rawflag']&7==5,
        'L4 parent highflags/nonpointer bits unchanged')
   need((x>>39)&4194303==old and (y>>39)&4194303==new and (x>>61)&1023==(y>>61)&1023==n,
        'Actual L4 parent ranges match complete plan')
   ra=bytes.fromhex(r['root_old112']);rb=bytes.fromhex(r['root_new112']);need(len(ra)==len(rb)==14,'Complete actual root112')
   rx=int.from_bytes(ra,'little');ry=int.from_bytes(rb,'little')
   need((rx^ry)&~mask3==0 and (rx>>55)&7==(ry>>55)&7==4 and
        (rx>>43)&4095==(ry>>43)&4095 and 0<=ordinal<((rx>>43)&4095), 'L4 parent exact ordered root path')
   need(r['old_parent_ID']==((rx>>20)&8388607)+ordinal and r['new_parent_ID']==((ry>>20)&8388607)+ordinal,
        'L4 old/new selected node matches rootfirst+ordinal')
   reuse=root in prior4;need(r['parent_uses_closed_L4_stock_reuse'] is reuse,'Exact L4 reuse membership')
   destination=r['combined_parent_ID_before_future_suffix_rank']
   if reuse:
    q=prior4[root]
    need(q['original_v2_L3_hex']==r['root_old112'] and q['current_v3_L3_hex']==r['root_new112'] and
         q['oldfirst']+ordinal==r['old_parent_ID'] and q['newfirst']+ordinal==r['new_parent_ID'] and
         destination==q['oldfirst']+ordinal and 1<=destination<=2133948 and destination!=r['new_parent_ID'],
         '172 closedL4 redirects use retained oldstock parent, never discarded clone destination')
    dest['closed_L4_oldstock']+=1
   else:
    need(destination==r['new_parent_ID'],'Other currentV3 parent retained until later suffixrank');dest['L4']+=1
    need(not any(q['newfirst']<=destination<q['newfirst']+q['count'] for q in prior4.values()),
         'Other parent destination outside every discarded closedL4 clone range')
  else:need(False,'Unknown parent kind held')
  for tag,key,wkey in [('v2','oldfirst','old_physical_window'),('v3','newfirst','new_physical_window')]:
   w=r[wkey];bit=ts[tag][5]['start']*8+(r[key]-1)*126
   need(w['MDR_offset']==bit//8 and w['start_shift']==bit%8 and w['significant_bits']==n*126 and
        w['bytes']==(bit%8+n*126+7)//8 and bit%8 in (0,2,4,6),'Every actual global126bit window geometry')
  pair=str(r['old_physical_window']['start_shift'])+','+str(r['new_physical_window']['start_shift']);shiftpairs[pair]+=1
  need(r['rows_with_outside_mask_delta']==0 and 0<=r['rows_with_first_count_delta']<=n,'Full producer comparison receipt bounds')
  total+=n;edits+=r['rows_with_first_count_delta'];rolling.update(json.dumps(r,sort_keys=True,separators=(',',':')).encode()+b'\n')
 disjoint(groups,'oldfirst');disjoint(groups,'newfirst')
 need(total==38734 and edits==1914 and kinds=={'L4':1603,'L3':33} and dest=={'L4':1431,'closed_L4_oldstock':172,'L3':33} and
      dict(shiftpairs)==proof['global_old_new_shift_pair_counts'] and len(shiftpairs)==16 and
      rolling.hexdigest()==proof['group_comparison_receipts_SHA256'],'Complete sums/parent IDs/shifts/canonical rolling digest')
 samples=load('actual-raw126-row-samples.json');decoded=[];samplepairs=Counter();sample_delta=0
 for s in samples['samples']:
  r=bycontext[s['parent_context']];need(s['eligible'] and s['old_window']==r['old_physical_window'] and s['new_window']==r['new_physical_window'],
       'Actual canonical sample group binds complete plan/window digest')
  seen=set()
  for q in s['rows']:
   ordinal=q['ordinal'];need(0<=ordinal<r['count'] and ordinal not in seen,'Unique bounded sample ordinal');seen.add(ordinal)
   a=bytes.fromhex(q['old126hex']);b=bytes.fromhex(q['new126hex']);need(len(a)==len(b)==16,'Actual zeroextended canonical sample words')
   x=int.from_bytes(a,'little');y=int.from_bytes(b,'little');mask=((1<<30)-1)<<39
   need(x<1<<126 and y<1<<126 and ((x^y)&~mask)==0 and q['only_first_count_delta'],'126 significant bits only; all outside39..68 equal')
   for tag,key,bitkey,IDkey in [('v2','oldfirst','old_global_MDR_bit','old_ID'),('v3','newfirst','new_global_MDR_bit','new_ID')]:
    need(q[IDkey]==r[key]+ordinal and q[bitkey]==ts[tag][5]['start']*8+(q[IDkey]-1)*126,
         'Sample full global unaligned bit address and exact relative order')
   oldfields=fields126(x);newfields=fields126(y)
   for key in ('mapordinal','primary_ref_word','secondary_ref_word','rawflag','coord_raw24'):
    need(oldfields[key]==newfields[key],'Independent unchanged sample '+key)
   pair=str(q['old_global_MDR_bit']%8)+','+str(q['new_global_MDR_bit']%8);samplepairs[pair]+=1;sample_delta+=bool(x^y)
   decoded.append({'parent_context':r['parent_context'],'ordinal':ordinal,'old_ID':q['old_ID'],'new_ID':q['new_ID'],
                   'actual_global_old_new_shift_pair':pair,'old':oldfields,'new':newfields})
 sampleartifact=save('independent-canonical126-samples.json',{'decoded':decoded,'row_count':len(decoded),
  'actual_global_shift_pair_counts':dict(samplepairs),'saved_row_hex_is126significant_bits_not_physical_window':True,
  'unaligned_physical_window_bytes_independently_available_or_read':False,'all38734rawrows_independently_compared':False})
 STATE['phase']='static incoming/exclusive/pointer destination dataflow'
 p=IN/'measure_l5_reuse.py';source=read(p,rows[str(p.relative_to(ROOT))]['sha256'],rows[str(p.relative_to(ROOT))]);tree=ast.parse(source)
 fs={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};text=source.decode()
 snippet=lambda n:ast.get_source_segment(text,fs[n])
 incoming=snippet('l5_incoming');maintext=snippet('main');rowtext=snippet('row126')
 need('flag[ID]&7==5' in incoming and 'for ID in range(1,47871)' in incoming and
      'for ID,degree in enumerate(live4)' in incoming and 'if ID==0 or degree==0:continue' in incoming and
      'add_range(diff,total5,f,c,degree' in incoming and 'rawflag&7 in [0,5,6]' in incoming,
      'Actual all-L3 target5 and reachable L4 highflag weighted occupancy source')
 clauses=["incoming5['v2'][first:first+count]","incoming5['v3'][first:first+count]","incoming5['v3'][newfirst:newfirst+count]",
 "retained=(prior4[ID]['oldfirst']+ordinal) if ID in prior4 else newID","MASK5","other=delta&~MASK5","if bad:failed.append","else:accepted.append",
 "old=row126(oldraw,os,ordinal)","new=row126(newraw,ns,ordinal)"]
 need(all(c in maintext for c in clauses) and 'bit=shift+ordinal*126' in rowtext and 'inner=bit%8' in rowtext and
      '>>inner)&ROW5MASK' in rowtext,'Actual exclusivity/retained parent/global bit extraction/fullmask groupreject dataflow')
 need(".open('rb')" in maintext and 'image.f.close()' in text,'Readonly actual producer file handles')
 closure=load('actual-handle-read-closure.json');receipt=load('actual-exec-terminal-receipt.json');preflight=load('actual-L5-read-budget-preflight.json')
 flight=load('mapper-global-preflight.json');capacity=load('capacity-arithmetic.json')
 sealer=json.loads(read(IN/'actual-sealer-terminal-receipt.json',None))
 # The post-seal receipt hash is captured as data; avoid any IMG source access.
 need(receipt['exit_code']==0 and receipt['terminal_chunk']=='28762d' and
      receipt['actual_source_SHA256']==rows[str((IN/'measure_l5_reuse.py').relative_to(ROOT))]['sha256'] and
      sealer['exit_code']==0 and sealer['seal_SHA256']==PINS['sealed-files.json'] and sealer['actual_IMG_reads_during_sealer']==0,
      'Actual producer/sealer terminal identities and zero image writes/read repetition')
 p=IN/'actual-rejected-L5-groups.json.gz';rejected,dr=decompress(read(p,rows[str(p.relative_to(ROOT))]['sha256'],rows[str(p.relative_to(ROOT))]),'rejected')
 need(rejected['groups']==[],'No omitted rejected candidate groups')
 v5proof=json.loads(read(V5/'proof.json','ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82'))
 v5summary=json.loads(read(V5/'feasibility-summary.json','8cf117b560852b26e8fdadd8270987a3cdd5df0177c20364e34e4fb787b67fe5'))
 v5stream=json.loads(read(V5/'actual-stream-read-receipts.json','9ea624a4fa74107faa3b9ac2ff04ab94b1b6bcf8214301689f9213e35d913298'))
 for level,key in [(3,'L3_SHA256'),(4,'L4_SHA256')]:
  seg=next(r for r in v5stream['stream']['segments'] if r.get('level')==level)
  need(seg['sha256']==proof['actual_source_metadata']['v3'][key],'Actual V3 table hash binds closed V5 stream')
 need(not v5summary['stock_prefix_plus_active']['invalid_or_unclassified_child_encoding_counts'] and
      not v5summary['stock_prefix_plus_active']['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention'],
      'Typed forward relation remains conditional on closed V5 noanomaly source')
 need(proof['actual_L5_rows_compared']==proof['discardable_current_clone_L5_rows']==38734 and proof['accepted_L5_groups']==1636 and
      proof['rejected_L5_groups']==0 and proof['actual_126bit_mask']==[39,69] and
      proof['L4_parent_destination_counts_in_accepted']==dict(dest),'Full producer match scope counts')
 rb=proof['actual_read_receipts'];need(rb==closure['actual_IMG_reads'] and rb['actual_IMG_bytes']==141550252 and rb['actual_IMG_read_ops']==28074 and
      rb['cap']==160000000 and sum(rb['by_purpose'].values())==141550252 and preflight['required_actual_L5_group_read_bytes']==1222540,
      'Actual finite source read/counter closure and planned126bit windows')
 need(closure['all_handles_closed'] and closure['all_source_stats_unchanged'] and closure['new_IMG_written'] is False and
      proof['source_stats_before']==proof['source_stats_after'] and all(h['handle_closed'] and h['stat_unchanged'] for h in closure['handles']) and
      flight['unresolved']==[],'Exact unchanged rb source handles and dependency preflight')
 for tag,count in [('v2',2667573),('v3',3077845)]:
  f=proof['all_live_L5_incoming_occupancy'][tag]
  need(sum(f['saturated_slot_counts'].values())==count and f['all_L3_examined']==47870 and
       f['directL3_target5_ranges']==19053 and f['all_reachable_L4_parent_aliases_counted_conservatively'] and
       f['external_or_extra_highflag_refs_resolved'] is False,'Full incoming source/digest scope only, not independent graph census')
 calc=arithmetic(proof['actual_source_metadata']['v3']['components'],total)
 for k,v in calc.items():need(proof['combined_capacity_arithmetic'][k]==v and capacity['combined_reuse'][k]==v,'Independent whole6components/FAT capacity '+k)
 need(calc['retained_counts']=={'4':3781594,'5':3035559,'6':2062771} and calc['MDR_bytes']==130720080 and
      calc['projected_IMG_bytes']==134828032 and calc['capacity_margin']==-610304 and not calc['fits_original_4K_arithmetic'],
      'Still610304 excess; original declaration not hardwarelimit')
 for saved,expected in [(77244,134221824),(77245,134217728)]:
  q=arithmetic(proof['actual_source_metadata']['v3']['components'],saved)
  need(q['projected_IMG_bytes']==expected,'Exact hypothetical L5-only threshold boundary')
 need(proof['external_cache_extra_highflag_ref_absence_proved'] is False and all(v is False for v in proof['falseflags'].values()),
      'All external/highflag/renderer/UI/device/install holds retained')
 for item in STATE['inputs']:need(stat(ROOT/item['path'])==item['stat_before'],'All actual source artifacts fullstats unchanged')
 result=save('proof.json',{'schema':'independent-exclusive-stock-L5-plan-review/v1','created_utc':datetime.now(timezone.utc).isoformat(),
  'all_assigned_bounded_review_checks_passed':True,'producer_seal_sha256':PINS['sealed-files.json'],'producer_proof_sha256':PINS['proof.json'],
  'complete1636_groups_and38734_sum_verified':True,'parent_kind_counts':dict(kinds),'correct_retained_parent_destination_counts':dict(dest),
  'all172_reused_L4_parents_rewrite_oldstock_not_discarded_clone':True,'both_full_old_new_range_sets_disjoint_and_bounded':True,
  'stock_L5_count':2341096,'actual_L5_global_window_shift_pairs':dict(shiftpairs),'all16_group_shift_pairs_geometry_verified':True,
  'canonical_group_rolling_digest_verified':rolling.hexdigest(),'all_parent_actual112_128_prefixes_independently_decoded':True,
  'raw126_saved_canonical_samples_independently_decoded':len(decoded),'sample_global_shift_pairs':dict(samplepairs),
  'all16_shift_pairs_present_in_saved_sample_rows':len(samplepairs)==16,'sample_pointer_delta_rows':sample_delta,'sample_artifact':sampleartifact,
  'sampled126significantbits_mask39_to68_refs_coords_flags_order_verified':True,
  'all38734_rawrows_or_raw_unaligned_physical_window_bytes_independently_verified':False,
  'canonical_samples_plus_global_geometry_not_fresh_IMG_window_read':True,
  'whole_graph_incoming_occupancy_recomputed_independently':False,
  'producer_source_sha256':rows[str((IN/'measure_l5_reuse.py').relative_to(ROOT))]['sha256'],
  'producer_static_AST_sha256':sha(ast.dump(tree,include_attributes=False).encode()),
  'source_dataflow_reviewed':{'allL3target5_and_reachableL4_weighted_alias_census':True,'all_raw_highflags_retained':True,
   'oldv2degree1_oldv3degree0_newv3degree1':True,'closedL4_parent_destination_applied_before_suffixrank':True,
   'all126_significant_bits_compared_globalunaligned_excluding_only39_to68':True,'whole_group_rejection_on_otherbits':True},
  'comprehensive38734rawbits_and_fullincoming_evidence':'sealed producer source/dataflow, fullplan digests, closed source table hashes and readreceipts; not independent freshraw allcase',
  'oldstock_byte_provenance_inherited_not_originalIMG_reread':True,
  'independent_sixcomponent_capacity_arithmetic':calc,'not_original128MiB_hardware_limit_proof':True,
  'actual_reuse_notfit_excess_bytes':610304,'hypothetical_additional_L5_only_rows_needed':77245-38734,
  'hypothetical_threshold_does_not_identify_deletable_or_safe_rows':True,
  'external_highflag_cache_extra_refs_renderer_rootcause_UI_install_ready':False,
  'actual_inherited_producer_IMG_reads':141550252,'actual_inherited_peak_current_mm_KiB':273600,
  'review_IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO':0,
  'actual_artifact_bytes_including_previews':STATE['artifact_bytes'],'artifact_cap':CAP,
  'actual_gzip_decompressed_bytes':STATE['decompressed_bytes'],'decompressed_cap':DECOMP_CAP,
  'actual_input_receipts':STATE['inputs'],'all_inputs_fullstat_unchanged':True,'all_handles_closed':True})
 with (OUT/'HANDOFF.md').open('x') as f:f.write('Complete1636groups/38734sum and parent destination mapping reviewed.172 L4 parents target retained oldstock;1431 use other currentV3 parents pending suffixrank;33 directL3 IDs remain.\n\nSaved canonical126bit sample words/global positions were checked; physical unaligned windows/all38734rawrows/fullincoming graph were not independently reread. Producer source/digests remain the fullcase evidence.\n\nCombined IMG134828032B still exceeds original declaration134217728B by610304B; not a hardwarelimit proof or install/render result. No IMG/PBF/MAIN/producer/scanner/guest/audio/device execution.\n')
 print(json.dumps({'all_assigned_bounded_review_checks_passed':True,'proof_sha256':result['sha256'],'fullgroups':1636,'rowsum':38734,
  'saved_raw126_sample_rows':len(decoded),'saved_sample_shift_pairs':len(samplepairs),'artifact_bytes':STATE['artifact_bytes'],
  'decompressed_bytes':STATE['decompressed_bytes'],'capacity_still_excess':610304,'no_IMG_or_producer_execution':True,'all_handles_closed':True}))

if __name__=='__main__':
 try:main()
 except BaseException as e:
  save('actual-failure.json',{'schema':'bounded-L5-plan-review-failure/v1','type':type(e).__name__,'error':str(e),
   'traceback':traceback.format_exc(),'actual_state':STATE,'artifact_cap':CAP,'decompressed_cap':DECOMP_CAP,
   'caps_not_raised':True,'IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO':0})
  raise
