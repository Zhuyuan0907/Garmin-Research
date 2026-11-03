#!/usr/bin/env python3
"""Bounded static L3 policy review. Reads saved artifacts only; IMG0/CPU0."""
import hashlib,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(v,m):
 if not v:raise ValueError(m)
def write(n,v):
 with(HERE/n).open('x')as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
 started=datetime.now(timezone.utc).isoformat();cache={};seals={};ledger=[]
 def read(rel,cap,expected=None):
  if rel in cache:return cache[rel]
  p=ROOT/rel;before=stat(p);need(before[2]<=cap,'Small artifact cap:'+rel)
  b=p.read_bytes();need(stat(p)==before,'Unchanged artifact:'+rel)
  if expected:need(sha(b)==expected,'Sealed identity:'+rel)
  ledger.append(dict(path=rel,bytes=len(b),sha256=sha(b),stat_before=before,stat_after=stat(p),full_EOF_read=True))
  cache[rel]=b;return b
 def sealed(stage,leaf,cap):
  if stage not in seals:seals[stage]=json.loads(read('staging/'+stage+'/sealed-files.json',25000))
  row=next(x for x in seals[stage]['files']if x['path']=='staging/'+stage+'/'+leaf)
  b=read(row['path'],cap,row['sha256']);need(len(b)==row['bytes'],'Sealed size');return b
 def proofprefix(stage):
  # CPU proofs contain huge historical trace arrays. No full proof scan/hash/replay.
  if stage not in seals:sealed(stage,'HANDOFF.md',6000)
  rel='staging/'+stage+'/proof.json';row=next(x for x in seals[stage]['files']if x['path']==rel)
  p=ROOT/rel;before=stat(p);need(before[2]==row['bytes'],'Inherited proof size')
  with p.open('rb')as f:b=f.read(65536)
  need(len(b)==65536 and stat(p)==before,'Exact immutable64KiB saved proof prefix')
  ledger.append(dict(path=rel,bytes=len(b),prefix_sha256=sha(b),inherited_whole_sha256=row['sha256'],
   inherited_whole_sha256_not_repeated=True,stat_before=before,stat_after=stat(p),full_EOF_read=False))
  t=b.decode();dec=json.JSONDecoder();out={}
  for k in ['schema','all_assigned_checks_passed','candidate','actual_MDR_header_source','actual_directory_source','actual_original_directory']:
   m=re.search(r'^  "'+k+r'":\s*',t,re.M);need(m is not None,'Required bounded top field:'+k)
   out[k],end=dec.raw_decode(t,m.end());need(end<=len(t),'Complete top field within prefix')
  out['proof_inherited_sha256']=row['sha256'];return out
 cpu2='navigation-country-native-cpu-v2';cpu3='navigation-country-native-lane-cpu-v3'
 h2=sealed(cpu2,'HANDOFF.md',6000).decode();h3=sealed(cpu3,'HANDOFF.md',6000).decode()
 v2=proofprefix(cpu2);v3=proofprefix(cpu3)
 b2=json.loads(sealed('navigation-country-native-candidate-v2','proof.json',30000))
 b3=json.loads(sealed('navigation-country-native-lane-candidate-v3','proof.json',12000))
 selection=json.loads(sealed(cpu3,'finite-selection.json',100000))
 profiles={}
 for label,obj in [('country_v2',v2),('lane_v3',v3)]:
  raw=bytes.fromhex(obj['actual_directory_source']['hex']);need(len(raw)==120 and sha(raw)==obj['actual_directory_source']['sha256'],'Saved actual directory identity')
  header=bytes.fromhex(obj['actual_MDR_header_source']['hex']);need(len(header)==772 and sha(header)==obj['actual_MDR_header_source']['sha256'],'Saved actual header identity')
  tables=[]
  for i in range(6):
   start,size,stride,x,y=struct.unpack_from('<5I',raw,i*20)
   widths=[(x>>18)&63,(x>>24)&63,(x>>12)&63,(x>>6)&63,x&63,y&63,(y>>11)&63,(y>>17)&63]
   flags=[(x>>30)&1,x>>31]
   tables.append(dict(level=i+1,start=start,bytes=size,stride_bits=stride,count=(size*8)//stride,widths=widths,flags=flags,raw_directory_entry_hex=raw[i*20:i*20+20].hex()))
  need(tables[2]['count']==47870 and tables[2]['stride_bits']==112 and tables[2]['widths'][0]==23,'Actual bothcandidateL3 profile23/112')
  profiles[label]=dict(candidate=obj['candidate'],directory_source=obj['actual_directory_source'],tables=tables,
   actual_original_directory=obj['actual_original_directory'],CPU_proof_inherited_sha256=obj['proof_inherited_sha256'],
   MDR_component_bytes=struct.unpack_from('<I',header,600)[0]+120,raw_header_sha256=sha(header))
 need(profiles['country_v2']['tables'][3]['count']==3781594 and profiles['lane_v3']['tables'][3]['count']==4896236,'L4 crossingfacts')
 need(profiles['country_v2']['MDR_component_bytes']==124255307 and profiles['lane_v3']['MDR_component_bytes']==149220356,'MDRsizefacts')
 need(b2['candidate_sha256']==profiles['country_v2']['candidate']['inherited_root_readback_sha256'],'Candidatev2pin')
 need(b3['candidate_sha256']==profiles['lane_v3']['candidate']['sha256_inherited_from_completed_actual_builder_readback'],'Candidatev3pin')
 need(b3['source_v2']['sha256']==b2['candidate_sha256'],'Actualsame23/112 lineage')
 raw13=selection['raw13_clone_witness'];high=selection['extra_root_samples'][0]['sample']
 need(high['first_child']==4194360 and high['one_based_street_ID']==13865,'Frozen over22bitcase selection')
 need(raw13['actual_root_fields']['first_child']==4499618 and raw13['actual_root_fields']['ID']==26718,'Frozen actual over22bitraw witness')
 write('candidate-layout-and-CPU-facts.json',dict(schema='native-L3-policy-candidate-facts/v1',profiles=profiles,
  stock_profile_comparison=dict(first_child_width=22,stride_bits=111,scope='Original stock profile; not sealed country-v2',platformwide_hard_limit_claim=False),
  requested_v2_width22_stride111_erratum=dict(original_scope_assumption_incorrect=True,
   correction='Actual country-v2 SHA925a515b... already width23/stride112; lane-v3 inherits it. Not a v3-specific profile delta.',root_acknowledged_correction=True),
  frozen_generic_CPU_scope=dict(v2='18parents/23newleaves/4separateoldprefixes;45nativeprefixes;stopsbefore0448F740',
   v3='23nativeprefixes,including7newlaneleaves;23separateLBLfragments;stopsbefore0448F740',
   highfirst_selection=high,actual_saved_raw13_root_fields=raw13['actual_root_fields'],
   CPU_replayed_this_scope=False,does_not_prove_renderer_or_UI=True),
  facts=dict(L4_v2=3781594,L4_v3=4896236,old22bit_max=2**22-1,crosses2pow22=True,
   L3_streets_unchanged=47870,L3_record_bits_unchanged=112,MDR_bytes_v2=124255307,MDR_bytes_v3=149220356,
   MDR_bytes_fit_u32=True,L4_v3_last_record_end_bit=4896236*128,L4_bitoffset_fits_u32=True),
  original_actual_IMG_reread=False,renderer_failure_rootcause_deduced=False))
 mat='navigation-native-jai-img-materializer-abi-v1';con='navigation-native-query-dir-constructor-v1';ctx='navigation-native-query-context-producer-static-v1'
 pages={}
 for s,n,a in [(mat,'MAIN-page-044b2000.bin',0x44b2000),(mat,'MAIN-page-044b1000.bin',0x44b1000),
  (mat,'MAIN-page-002cd000.bin',0x2cd000),(ctx,'MAIN-page-002cc000.bin',0x2cc000),(con,'MAIN-page-00173000.bin',0x173000)]:
  pages[a]=(sealed(s,n,4096),'staging/'+s+'/'+n)
 cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 def span(a,b):
  base=a&~4095;data,path=pages[base];need(b<=base+4096,'Single-page span');data=data[a-base:b-base]
  return dict(start=a,end_exclusive=b,source_path=path,bytes=len(data),hex=data.hex(),sha256=sha(data),
   instructions=[dict(address=i.address,hex=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)for i in cs.disasm(data,a)])
 ws=[]
 def w(i,title,spans,facts,limit):ws.append(dict(id=i,title=title,evidence_kind='Original saved bytes/static, or inherited sealed actualCPUfacts',spans=spans,facts=facts,claim_limit=limit))
 w('W1','Pinned actual country-v2 and v3 share L3 profile; value ranges changed',[],{
  'profile':'BothactualL3 count47870,w0=23,stride112;stockcomparison22/111',
  'L4':'3781594→4896236;old22-bitmax4194303',
  'MDR_component_bytes':'124255307→149220356',
  'container':'Country-v2 4K/128356352B/SHA925a515b...;lane-v3 8K/153346048B/SHA1f468e...',
  'inherited_CPU':'BothboundednativeDIR/prefixcasespassedbeforemetadata0448F740;noactualCPUexecutednow',
  'frozen_high_first':'Root13865first4194360;actualroot26718first4499618/rawpayload saved inselection',
  'facts_artifact':'candidate-layout-and-CPU-facts.json'
 },'Not a new width22→23 experiment or renderer/device acceptance proof. Original assignment erratum retained.')
 w('W2','Header parser supplies dynamic DIR offset/stride/count without a profile literal compare',[
  span(0x2cc44c,0x2cc4d6),span(0x2cd378,0x2cd37e),span(0x2cd448,0x2cd49e)],{
  'observed_guards':'Native FS status, GARMIN MDR signature, version/header minimum-length branches; not a width22/23 or stride111/112 comparison in these spans',
  'DIR_metadata':'ctx+2B4 receives directory offset;+2B8stride;+2BCflags;+2C0=size/stride count via38C168',
  'both_actual_DIR':'Six20-byteentries;count6unchanged.149220236+120 givesv3MDR149220356',
  'compare_domain':'Header length/IO status, not a149MB whole-component-size guard'
 },'Exact bounded spans only; complete file admission/mount/renderer policy is outside the parser-fragment evidence.')
 w('W3','Original DIR parser expands packed six-bit fields and copies record stride dynamically',[
  span(0x44b209e,0x44b219e)],{
  'guards':'Nonnullctx/DIR;tablecount0→status3;directoryentryreadsize=min(ctx+2B8,20)',
  'table_count':'ctx+2C0 copied toDIR+0;loop runsdynamic count;count6unchanged',
  'fields':'20-byteentry start/bytes/stride copied to28-bytedecodeddescriptor; six-bit fields extracted by shifts andstored asbytes',
  'w0':'044B212A..2130 extracts bits18..23 and storesdescriptor+14hex;23fits encoded6bits',
  'stride':'044B211A..2120 stores raw recordstride atdescriptor+8;neither111nor112literal enforced',
  'count':'044B217C..218E computesbytecount*8/recordstride; no4194304/profile22comparison in inspected completeDIRfunction'
 },'Dynamic parser support is proven only by original bytes and inherited limitedCPU; no claim arbitrary width is safe or allhigherpolicy absent.')
 w('W4','Packed reader has level/record bounds and dynamic32-bit offsets; no22-bit first-child mask here',[
  span(0x44b10e4,0x44b1158),span(0x44b122e,0x44b126c)],{
  'level_guard':'Levelnonzero and<=DIRtablecount;lowIDnonzero',
  'record_bound':'(lowID-1)*dynamicstride + stride <= dynamictablebytes*8;failstatus3',
  'offset':'MULusesdynamicrecordstride loadedfromDIRdescriptor;not hardcoded111/112',
  'first_child':'044B1232 loadsdescriptorw0;dynamicextraction writes32-bit outputfirst_child;no22-bitconstantmaskinthisspan',
  'numeric_range':'v3L4 count4896236*128=626718208bits fits32-bit MUL/compare;MDR149220356bytes fitsu32',
  'same_profile':'BothL3 bitcount47870*112=5361440;tablebytes670180 unchanged'
 },'Generic records andnumericrange checks are not renderer policy. No newCPU, malformedinput test, or broadplatformlimit inferred.')
 w('W5','Selected query DIR cache path delegates parser/reader; bounded higher-policy negative',[
  span(0x173b78,0x173bba),span(0x173c1a,0x173c60)],{
  'cache':'Coldalloc17C DIR→2E3834(original044B209E);cachedhandleunwrap thenDIR154source store',
  'selected_record':'Descriptorlevel/lowID→2E382C(original044B10E4);status checked;first/count/childlevelfields copiedaswords',
  'observed_higher_calls':'2E383C relationship/iterationcallee followsrange setup;unexaminedhere',
  'explicit_profile_reject_found_in_inspected_spans':False,
  'explicit_L4_2pow22_or_MDR149MB_guard_found':False,
  'finite_negative_scope':'Header spans,wholeDIRparser,packedreaderentry/firstchildspans,andselectedquerycachecallsite only'
 },'No wholeMAINscan or claim that native mount/registry/maploader/renderer imposes nootherguard. Road-displayregression cause remains unknown.')
 need(len(ws)==5,'Stopfivewitness')
 write('width-policy-witnesses.json',dict(schema='native-L3-width-five-static-witnesses/v1',witness_count=5,witnesses=ws))
 write('source-artifact-read-ledger.json',dict(schema='native-L3-policy-static-source-ledger/v1',reads=ledger,
  saved_code_artifact_bytes=5*4096,new_MAIN_bytes=0,new_IMG_bytes=0,CPU_cases_executed=0,
  large_CPU_proofs_read_only_first65536_bytes_each=True,whole_MAIN_IMG_CPUproof_hashes_not_repeated=True,
  all_artifact_stats_unchanged=True,all_actual_handles_closed=True))
 proof=dict(schema='native-L3-width-policy-static-proof/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
  all_assigned_checks_passed=True,scope_work_completed=True,script_sha256=sha(Path(__file__).read_bytes()),
  exact_byte_witness_count=5,new_MAIN_bytes_read=0,new_MAIN_bytes_cap=24576,new_IMG_bytes_read=0,CPU_cases_executed=0,
  scope_erratum_retained=True,bothactualcountryv2andv3_L3width23_stride112=True,
  generic_width23_support_inherited_not_replayed=True,higher_profile_policy_proven_absent=False,
  explicit_reject_observed_in_this_bounded_static_scope=False,explicit_reject_policy_elsewhere_unknown=True,
  renderer_failure_rootcause_deduced=False,renderer_UI_device_App_installable_full_Taiwan_verified=False,
  unknown_returns_faked=False,heap_music_admission_name_key_registry_token_guests_or_traces_run=False,
  sharedseals_MAIN_IMG_device_canonical_audio_mutated=False,all_actual_source_handles_closed=True,
  remaining_gap='Uninspected original relationship/iteration and higher mount/metadata/rendererpolicy may still impose limits. No evidence here identifying totalcount/filesize as road-displayfailurecause.',
  stop_reason='Fivefinitewitnesses and boundednegative reached; no furtherreads or CPU cases authorized in thisscope.')
 write('proof.json',proof)
 print(json.dumps(dict(all_assigned_checks_passed=True,witnesses=5,new_MAIN_bytes=0,IMG_bytes=0,CPU_cases=0,
  proof_sha256=sha((HERE/'proof.json').read_bytes()))))
if __name__=='__main__':main()
