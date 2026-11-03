#!/usr/bin/env python3
"""Independent bounded DATA/artifact review. No producer/scanner/IMG execution."""
from pathlib import Path
from datetime import datetime,timezone
import ast
import gzip
import hashlib
import io
import json
import os
import struct
import traceback

ROOT=Path('/root/garmin')
IN=ROOT/'staging/navigation-v3-exclusive-stock-L4-reuse-feasibility-v1'
OUT=Path(__file__).resolve().parent
V5=ROOT/'staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5'
MAP=ROOT/'staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py'
CAP=1048576
DECOMP_CAP=8388608
EXPLORATORY_READ_BYTES=173821
STATE={'phase':'initial','artifact_read_bytes':EXPLORATORY_READ_BYTES,'gzip_decompressed_bytes':0,'inputs':[]}
PINS={
 'sealed-files.json':'4de5e8108e4760f34451c75654eac76d81184f2f1aaab87d71855c2e6c9d1246',
 'scope-summary.json':'31ff1e560798e9c772cb5cdb01682aa049ba161b80c82d071e0715751e116ec9',
 'proof.json':'353092976130fe4c1f8522c6fe8dc55b03b4225d9fc946751e098a1b0ec2c803',
 'reuse-root-plan.json.gz':'d8ae42d789ed5449657f5065ee703c7b731d02dd0f078ec88684407d90120a09'}


def need(v,msg):
 if not v:raise ValueError(msg)


def sha(b):return hashlib.sha256(b).hexdigest()


def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def save(name,value):
 p=OUT/name;b=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
 with p.open('x') as f:f.write(b.decode());f.flush();os.fsync(f.fileno())
 return {'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b)}


def read(p,pin=None,sealed_row=None):
 allowed=p==MAP or p.parent in (IN,V5) or p.parent==IN/'failed-run-v1'
 need(allowed and p.is_file() and not p.is_symlink(),'Exact bounded artifact/code allowlist')
 before=stat(p);need(STATE['artifact_read_bytes']+before[2]<=CAP,'Total actual artifact input1MiB incl exploratory reads')
 if sealed_row is not None:need(before==sealed_row['stat_at_seal'],'Exact producer sealed input full stat')
 with p.open('rb') as f:
  data=f.read(before[2]+1);need(f.read(1)==b'','Actual small artifact EOF')
 STATE['artifact_read_bytes']+=len(data)
 need(len(data)==before[2] and stat(p)==before,'Artifact full EOF/stat stable')
 digest=sha(data);need(pin is None or digest==pin,'Exact artifact/source hash pin')
 need(p.stat().st_mode&0o777==0o444,'Closed source mode0444')
 STATE['inputs'].append({'path':str(p.relative_to(ROOT)),'bytes':len(data),'sha256':digest,
  'stat_before':before,'stat_after':stat(p),'EOF_verified':True})
 return data


def arithmetic(counts,components,baseline):
 lower={i:(counts[i]*w+7)//8 for i,w in ((4,128),(5,126),(6,68))}
 mdr=baseline['MDR_bytes_after']-baseline['lower_table_bytes_after']['4']+lower[4]
 sizes=dict(components);sizes['00004171.MDR']=mdr
 blocks={n:(v+4095)//4096 for n,v in sizes.items()};parts={n:(v+239)//240 for n,v in blocks.items()}
 rows=1+sum(parts.values());metadata=max(73728,((4096+rows*512+4095)//4096)*4096)
 image=metadata+4096*sum(blocks.values())
 return {'lower_table_bytes_after':{str(k):v for k,v in lower.items()},'MDR_bytes_after':mdr,
         'component_sizes':sizes,'component_4K_blocks':blocks,'component_FAT_parts':parts,
         'root_plus_component_FAT_rows':rows,'4K_metadata_bytes':metadata,'projected_4K_IMG_bytes':image,
         'capacity_margin':134217728-image,'fits_original_4K_arithmetic':image<=134217728}


def raw_fields(b):
 x=int.from_bytes(b,'little')
 return {'mapordinal':x&1,'primary_ref':(x>>1)&524287,'secondary_ref':(x>>20)&524287,
         'first_child':(x>>39)&4194303,'count':(x>>61)&1023,'rawflags':(x>>71)&511,
         'coordinate_raw24':[(x>>80)&16777215,(x>>104)&16777215]}


def main():
 need(not (OUT/'proof.json').exists() and not (OUT/'actual-failure.json').exists(),'Fresh finite review, no replay')
 names=['sealed-files.json','scope-summary.json','proof.json','reuse-root-plan.json.gz','measure_reuse_v2.py',
        'actual-raw-row-samples.json','actual-handle-read-closure.json','actual-exec-terminal-receipt.json',
        'actual-sealer-terminal-receipt.json','capacity-arithmetic.json','actual-L4-read-budget-preflight.json',
        'mapper-global-preflight.json','actual-rejected-L4-groups.json.gz',
        'failed-run-v1/actual-failure.json','failed-run-v1/actual-terminal-receipt.json']
 external=[V5/'proof.json',V5/'feasibility-summary.json',V5/'actual-stream-read-receipts.json',MAP]
 sizes={str((IN/n).relative_to(ROOT)):(IN/n).stat().st_size for n in names}
 sizes.update({str(p.relative_to(ROOT)):p.stat().st_size for p in external})
 projected=EXPLORATORY_READ_BYTES+sum(sizes.values())
 need(projected<=CAP,'Preflight complete artifact set within unchanged1MiB incl previews')
 save('budget-preflight.json',{'schema':'exclusive-L4-plan-review-budget/v1','artifact_cap':CAP,
  'decompressed_cap':DECOMP_CAP,'preliminary_exploratory_reads':EXPLORATORY_READ_BYTES,
  'projected_complete_actual_artifact_bytes':projected,'individual_bytes':sizes,
  'producer_scanner_IMG_PBF_MAIN_guest_audio_device_execution':False})
 seal=json.loads(read(IN/'sealed-files.json',PINS['sealed-files.json']))
 rows={r['path']:r for r in seal['files']}
 def load(name):
  p=IN/name;r=rows.get(str(p.relative_to(ROOT)));need(r is not None,'All selected preseal artifacts included')
  return json.loads(read(p,PINS.get(name,r['sha256']),r))
 summary=load('scope-summary.json');proof=load('proof.json')
 STATE['phase']='full gzip plan bounded EOF'
 p=IN/'reuse-root-plan.json.gz';compressed=read(p,PINS[p.name],rows[str(p.relative_to(ROOT))])
 declared=struct.unpack('<I',compressed[-4:])[0]
 save('decompression-preflight.json',{'gzip_bytes':len(compressed),'gzip_ISIZE':declared,
  'unchanged_decompressed_cap':DECOMP_CAP,'stream_cap_still_enforced':True})
 need(0<declared<=DECOMP_CAP,'Gzip declared ISIZE within8MiB before parse/decompression')
 output=bytearray();h=hashlib.sha256()
 with gzip.GzipFile(fileobj=io.BytesIO(compressed),mode='rb') as f:
  while True:
   chunk=f.read(min(65536,DECOMP_CAP-len(output)+1))
   if not chunk:break
   output.extend(chunk);h.update(chunk);STATE['gzip_decompressed_bytes']=len(output)
   need(len(output)<=DECOMP_CAP,'Actual gzip decompression8MiB hard cap')
 need(len(output)==declared,'Complete gzip CRC/EOF and declared ISIZE')
 plan=json.loads(output);del output,compressed
 need(plan['schema']=='exclusive-stock-L4-reuse-readonly-plan/v1','Actual full plan schema')
 roots=plan['roots'];need(len(roots)==1251,'All1251 roots, not sample subset')
 STATE['phase']='independent complete plan structure'
 ids=[r['root_ID'] for r in roots]
 need(len(set(ids))==1251 and ids==sorted(ids) and 1<=min(ids)<=max(ids)<=47870,'Unique ordered bounded root IDs')
 mask3=((1<<35)-1)<<20;total=changed=outside=0;rolling=hashlib.sha256();byid={}
 for r in roots:
  ID,old,new,n=r['root_ID'],r['oldfirst'],r['newfirst'],r['count'];byid[ID]=r
  need(all(isinstance(x,int) and not isinstance(x,bool) for x in (ID,old,new,n)), 'Exact integer root/range fields')
  need(1<=n<=4095 and 1<=old<=old+n-1<=2133948 and 2133948<new<=new+n-1<=4896236,
       'Old original prefix and poststock clone ranges bounded')
  a=bytes.fromhex(r['original_v2_L3_hex']);b=bytes.fromhex(r['current_v3_L3_hex'])
  need(len(a)==len(b)==14,'Actual complete112bit root samples in every plan row')
  x=int.from_bytes(a,'little');y=int.from_bytes(b,'little')
  need(x&1==y&1==1 and (x>>55)&511==(y>>55)&511==4 and ((x^y)&~mask3)==0,
       'Exact rawflag4/ordinal and root outsidefirst-count bits identical')
  need((x>>20)&8388607==old and (y>>20)&8388607==new and
       (x>>43)&4095==(y>>43)&4095==n,'Every actual L3 root old/new first/count matches plan')
  need(r['rows_with_outside_mask_delta']==0 and 0<=r['rows_with_first_count_delta']<=n,
       'Full producer row-comparison receipt claims bounded masked differences only')
  for key in ('old_group_SHA256','new_group_SHA256','outside_mask_original_bits_SHA256'):
   need(len(r[key])==64 and all(c in '0123456789abcdef' for c in r[key]),'Exact group SHA shape')
  total+=n;changed+=r['rows_with_first_count_delta'];outside+=r['rows_with_outside_mask_delta']
  rolling.update(json.dumps(r,sort_keys=True,separators=(',',':')).encode()+b'\n')
 for key in ('oldfirst','newfirst'):
  ranges=sorted((r[key],r[key]+r['count']-1,r['root_ID']) for r in roots)
  need(all(a[1]<b[0] for a,b in zip(ranges,ranges[1:])),'Complete'+key+'1251 ranges pairwise disjoint')
 need(total==108235 and changed==1879 and outside==0 and
      rolling.hexdigest()==proof['complete_comparison_group_receipts_SHA256'],
      'Independent full plan sums/order canonical rolling comparison digest')
 need(proof['accepted_reuse_roots']==proof['structural_candidate_roots']==1251 and
      proof['actual_old_new_L4_rows_compared']==proof['discardable_newclone_L4_rows']==108235 and
      proof['exact128bit_comparison_except_mask_bits']==[39,71] and
      proof['L4_groups_rejected_for_outside_mask_difference']==0,'Actual comprehensive producer comparison scope')
 samples=load('actual-raw-row-samples.json');decoded=[];sample_changed=0
 v2tables={r['level']:r for r in proof['actual_source_tables']['v2']}
 v3tables={r['level']:r for r in proof['actual_source_tables']['v3']}
 for group in samples['samples']:
  r=byid[group['root_ID']]
  need(group['old_first']==r['oldfirst'] and group['new_first']==r['newfirst'] and group['count']==r['count'] and
       group['group_reuse_eligible'] is True,'Actual raw sample binds complete plan root/ranges')
  seen=set()
  for q in group['rows']:
   i=q['ordinal'];need(0<=i<r['count'] and i not in seen,'Bounded unique sample row ordinal');seen.add(i)
   a=bytes.fromhex(q['old128']);b=bytes.fromhex(q['new128']);need(len(a)==len(b)==16,'Actual raw128bit sample bytes')
   x=int.from_bytes(a,'little');y=int.from_bytes(b,'little');mask=((1<<32)-1)<<39
   need((x^y)&~mask==0 and q['only_first_count_delta'] is True,'Independent sample outside39..70 fullbit equality')
   need(q['old_ID']==r['oldfirst']+i and q['new_ID']==r['newfirst']+i and
        q['old_MDR_offset']==v2tables[4]['start']+(q['old_ID']-1)*16 and
        q['new_MDR_offset']==v3tables[4]['start']+(q['new_ID']-1)*16,'Sample actual logical offsets/order')
   oldfields=raw_fields(a);newfields=raw_fields(b)
   for key in ('mapordinal','primary_ref','secondary_ref','rawflags','coordinate_raw24'):
    need(oldfields[key]==newfields[key],'Independent unchanged sample '+key)
   sample_changed+=bool(x^y)
   decoded.append({'root_ID':r['root_ID'],'ordinal':i,'old_ID':q['old_ID'],'new_ID':q['new_ID'],
                   'old':oldfields,'new':newfields,'all_outside_mask_bits_equal':True})
 need(samples['sample_only_fullcase_comparison_count']==108235 and len(decoded)>0,'Samples not full108235 raw evidence')
 sampleartifact=save('independent-decoded-raw-samples.json',{'samples':decoded,'decoded_row_count':len(decoded),
  'rows_with_pointer_delta':sample_changed,'record_bits':128,'masked_pointer_bit_range':[39,71],
  'raw_reference_words_and_coordinates_decoded_only_no_LBL_or_IMG_read':True,
  'all108235_rows_independently_rawbit_verified':False})
 STATE['phase']='producer source static dataflow'
 source=read(IN/'measure_reuse_v2.py',rows[str((IN/'measure_reuse_v2.py').relative_to(ROOT))]['sha256'],
             rows[str((IN/'measure_reuse_v2.py').relative_to(ROOT))]);tree=ast.parse(source)
 funcs={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 snippets={name:ast.get_source_segment(source.decode(),funcs[name]) for name in ('roots','occupancy','main','arithmetic')}
 need("if flags[ID]&7!=4:continue" in snippets['occupancy'] and
      "for ID in range(1,47871):" in snippets['occupancy'] and
      "occupied[ID]=saturated" in snippets['occupancy'] and "saturated=min(2,running)" in snippets['occupancy'],
      'All L3 lower-three-bit target4 including highflags occupancy census source')
 maintext=snippets['main']
 clauses=["flag2[ID]!=4 or flag3[ID]!=4","(a^b)&~mask3", "n2[ID]!=n3[ID]",
  "first+count-1<=STOCK_L4","newfirst<=STOCK_L4", "degrees['v2'][first:first+count]",
  "degrees['v3'][first:first+count]","degrees['v3'][newfirst:newfirst+count]",
  "mask4=((1<<32)-1)<<39","strict=True","outside=delta&~mask4","if bad:failed.append","else:accepted.append"]
 need(all(s in maintext for s in clauses),'Actual candidate and full128bit/order/whole-root rejection dataflow')
 need(".open('rb')" in maintext and "image.f.close()" in source.decode() and
      "'new_IMG_or_patchfile_written':False" in source.decode(),'Read-only IMG producer handles and artifact-only closure scope')
 mapper=read(MAP,'a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095');mt=ast.parse(mapper)
 im=[n for n in mt.body if isinstance(n,ast.ClassDef) and n.name=='Image']
 need(len(im)==1 and sha(ast.dump(im[0],include_attributes=False).encode())==proof['mapper_AST_SHA256'],
      'Actual source bound to closed original mapper Image AST')
 occ=proof['actual_saturated_occupancy_all_L3target4']
 for tag,size,zeros in [('v2',3781594,1559552),('v3',4896236,2674194)]:
  v=occ[tag]
  need(v['all_L3_records_examined']==47870 and v['all_actual_L3target4_ranges']==20107 and
       v['all_highflags_target4_included'] and v['maximum_actual_degree']==1 and
       v['saturated_slot_counts']=={'0':zeros,'1':2222042} and sum(v['saturated_slot_counts'].values())==size,
       'Producer whole-L3 occupancy evidence completeness and aggregate bounds')
 actualclosure=load('actual-handle-read-closure.json');actualexec=load('actual-exec-terminal-receipt.json')
 sealerreceipt=json.loads(read(IN/'actual-sealer-terminal-receipt.json'))
 preflight=load('actual-L4-read-budget-preflight.json');mapflight=load('mapper-global-preflight.json');capacity=load('capacity-arithmetic.json')
 rejectedraw=read(IN/'actual-rejected-L4-groups.json.gz',rows[str((IN/'actual-rejected-L4-groups.json.gz').relative_to(ROOT))]['sha256'],
                  rows[str((IN/'actual-rejected-L4-groups.json.gz').relative_to(ROOT))])
 rejected_isize=struct.unpack('<I',rejectedraw[-4:])[0]
 remaining=DECOMP_CAP-STATE['gzip_decompressed_bytes']
 need(rejected_isize<=remaining,'Rejected-group gzip preflight within remaining unchanged8MiB')
 with gzip.GzipFile(fileobj=io.BytesIO(rejectedraw),mode='rb') as f:
  rejected=f.read(remaining+1);need(len(rejected)<=remaining and f.read(1)==b'','Rejected gzip bounded full EOF')
 STATE['gzip_decompressed_bytes']+=len(rejected)
 need(len(rejected)==rejected_isize and json.loads(rejected)['failed_groups']==[],'Empty bounded rejected-group artifact')
 firstfail=load('failed-run-v1/actual-failure.json');firstreceipt=load('failed-run-v1/actual-terminal-receipt.json')
 v5proof=json.loads(read(V5/'proof.json','ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82'))
 v5summary=json.loads(read(V5/'feasibility-summary.json','8cf117b560852b26e8fdadd8270987a3cdd5df0177c20364e34e4fb787b67fe5'))
 v5stream=json.loads(read(V5/'actual-stream-read-receipts.json','9ea624a4fa74107faa3b9ac2ff04ab94b1b6bcf8214301689f9213e35d913298'))
 table3=next(s for s in v5stream['stream']['segments'] if s.get('level')==3)
 need(table3['sha256']==proof['actual_source_metadata']['v3']['L3_SHA256'],'Actual V3 full-L3 hash binds prior one-stream source')
 baseline=v5summary['stock_prefix_plus_active'];need(not baseline['unknown_raw_flag_counts'] and
      not baseline['invalid_or_unclassified_child_encoding_counts'] and
      not baseline['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention'],'Closed V5 noanomaly structural baseline')
 need(proof['source_stats_before']==proof['source_stats_after'] and actualclosure['all_source_handles_closed'] and
      all(h['readonly_handle_closed'] and h['stat_unchanged'] for h in actualclosure['handles']) and
      actualclosure['new_IMG_or_patchfile_written'] is False and
      actualclosure['actual_IMG_read_receipts']==proof['actual_read_receipts'],'Actual rb handle/read closure source pins')
 rb=proof['actual_read_receipts'];need(rb['actual_IMG_bytes_read']==4945952 and rb['actual_IMG_read_ops']==3384 and
      rb['hard_combined_IMG_read_cap']==64000000 and rb['by_source']=={'v2':2472976,'v3':2472976} and
      sum(rb['by_purpose'].values())==4945952 and preflight['required_exact_old_new_L4_read_bytes']==108235*32 and
      preflight['projected_total_actual_IMG_bytes']==4945952 and mapflight['unresolved_globals']==[],
      'Exact sealed finite producer read budget and preflight')
 # Tool receipt schemas are saved actual JSON objects, inspected as data only.
 need(actualexec['terminal_exit_code']==0 and actualexec['terminal_chunk']=='d1a040' and
      actualexec['source_sha256']==rows[str((IN/'measure_reuse_v2.py').relative_to(ROOT))]['sha256'] and
      sealerreceipt['terminal_exit_code']==0 and sealerreceipt['actual_seal_sha256']==PINS['sealed-files.json'] and
      sealerreceipt['actual_IMG_reads']==0 and firstreceipt['exit_code']==1 and
      firstfail['actual_reads']['actual_IMG_bytes_read']==0,'Actual successful/failure receipts remain separate')
 counts={4:3889829-total,5:3074293,6:2062771}
 calc=arithmetic(counts,proof['actual_source_metadata']['v3']['components'],baseline['arithmetic'])
 for k,v in calc.items():need(proof['revised_arithmetic'][k]==v and capacity[k]==v,'Independent sixcomponent/FAT arithmetic '+k)
 need(calc['projected_4K_IMG_bytes']==135438336 and calc['capacity_margin']==-1220608 and
      calc['fits_original_4K_arithmetic'] is False and summary['arithmetic']['additional_needed_rows']==76038,
      'Reuse still misses declared capacity by1220608B')
 need(all(v is False for v in proof['falseflags'].values()) and
      proof['same_file_external_cache_or_highflag_ABI_resolved'] is False and
      proof['full_original_lowerIDs_verbatim_parentbytes_preserved'] is False,'All consumer/renderer/UI/install holds retained')
 for item in STATE['inputs']:need(stat(ROOT/item['path'])==item['stat_before'],'All actual small input fullstats still unchanged')
 report=save('proof.json',{'schema':'independent-exclusive-stock-L4-readonly-plan-review/v1',
  'created_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_bounded_review_checks_passed':True,
  'producer_seal_sha256':PINS['sealed-files.json'],'producer_proof_sha256':PINS['proof.json'],
  'complete_gzip_plan_sha256':PINS['reuse-root-plan.json.gz'],'complete_plan_decompressed_sha256':h.hexdigest(),
  'complete_plan_roots':1251,'all_unique_ordered_root_IDs_and_both_disjoint_range_sets_verified':True,
  'row_count_sum':total,'rows_with_first_count_delta_in_full_receipts':changed,
  'complete_canonical_group_receipt_rolling_sha256':rolling.hexdigest(),
  'all1251_actual112bit_L3_root_prefixes_independently_decoded':True,
  'old_stock_L4_range_bounds_verified':True,'poststock_clone_range_bounds_verified':True,
  'old_current_v2_stock_prefix_original_byte_provenance_inherited_not_originalIMG_reread':True,
  'minimum_clone_first':min(r['newfirst'] for r in roots),'maximum_clone_last':max(r['newfirst']+r['count']-1 for r in roots),
  'independent_actual128bit_sample_row_count':len(decoded),'independent_sample_roots':len(samples['samples']),
  'sample_pointer_delta_rows':sample_changed,'independent_sample_artifact':sampleartifact,
  'all108235_actual128bit_rows_independently_read_or_compared':False,
  'comprehensive_rawbit_equality_evidence':'sealed producer complete pair comparison plus pergroup/rolling hashes and reviewed exact-byte source dataflow',
  'all47870_incoming_occupancy_recomputed_independently':False,
  'incoming_exclusivity_evidence':'actual producer fullL3 hashes/counts/saturated occupancy digests; reviewed alltarget4 highflag census and candidate source predicates',
  'producer_static_AST_sha256':sha(ast.dump(tree,include_attributes=False).encode()),
  'producer_source_sha256':rows[str((IN/'measure_reuse_v2.py').relative_to(ROOT))]['sha256'],
  'source_dataflow':{'L3_only_range_mask':[20,55],'L4_only_first_count_mask':[39,71],
   'outside_flags_refs_coords_and_bitfields_full128comparison':True,'strict_zip_preserves_complete_relative_row_order':True,
   'alltarget4_highflags_included_in_occupancy':True,'candidate_roots_require_exact_rawflag4':True,
   'old_v2_occupancy1_old_v3_occupancy0_new_v3_occupancy1':True,
   'desired_v3_first_count_only_would_be_patched_into_oldstock_rows':True,
   'no_actual_stock_parent_write_or_transplant_executed':True},
  'independent_sixcomponent_FAT_capacity_arithmetic':calc,'does_not_fit_original4K':True,
  'remaining_L4_only_row_threshold_is_capacity_only_not_deletable_rows':76038,
  'known_graph_relations_do_not_prove_external_lowerrefs_absent_or_highflag_ABI':True,
  'external_refs_renderer_rootcause_UI_or_install_accepted':False,
  'actual_producer_IMG_reads_inherited':4945952,'review_IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO':0,
  'initial_producer_failure_IMG0_preserved':True,'input_artifact_cap':CAP,
  'actual_total_artifact_bytes_including_previews':STATE['artifact_read_bytes'],
  'decompressed_cap':DECOMP_CAP,'actual_total_gzip_decompressed_bytes':STATE['gzip_decompressed_bytes'],
  'actual_inputs':STATE['inputs'],'all_inputs_fullstat_unchanged':True,'all_handles_closed':True})
 note=('Independent bounded small-artifact review passed complete1251root plan uniqueness/ranges/disjointness, '
       '108235 countsum, actual112bit root samples, canonical comparison digest and saved128bit samples. '
       'All108235 L4 rawrows and complete47870 occupancy were not independently reread; their fullcase '
       'evidence remains producer hashes/receipts plus static dataflow.\n\n'
       'Reuse saves108235 L4 rows but projected4K IMG135438336B still exceeds134217728B by1220608B. '
       'External lower references/highflag/cache ABI, rendering rootcause, UI/install remain unknown. '
       'Review read no IMG/PBF/MAIN and executed no producer/scanner/guest/audio. Source files remain unchanged.\n')
 with (OUT/'HANDOFF.md').open('x') as f:f.write(note)
 print(json.dumps({'all_assigned_bounded_review_checks_passed':True,'proof_sha256':report['sha256'],
  'full_roots':1251,'full_row_count_sum':108235,'independent_raw_sample_rows':len(decoded),
  'actual_artifact_bytes':STATE['artifact_read_bytes'],'actual_gzip_decompressed_bytes':STATE['gzip_decompressed_bytes'],
  'projected4K_IMG_bytes':135438336,'capacity_shortfall':1220608,'no_IMG_or_producer_execution':True,'all_handles_closed':True}))


if __name__=='__main__':
 try:main()
 except BaseException as e:
  save('actual-failure.json',{'schema':'bounded-L4-plan-independent-review-failure/v1','type':type(e).__name__,
   'error':str(e),'traceback':traceback.format_exc(),'state':STATE,'unchanged_artifact_cap':CAP,
   'unchanged_decompression_cap':DECOMP_CAP,'review_IMG_producer_guest_audio_device_IO':0,
   'no_guard_relaxation_or_false_success':True})
  raise
