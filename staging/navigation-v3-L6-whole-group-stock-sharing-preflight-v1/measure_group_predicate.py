#!/usr/bin/env python3
"""Artifact-only bounded gzip predicates; no IMG, producer import/exec or native/device I/O."""
import sys
sys.dont_write_bytecode=True
import ast,base64,gzip,hashlib,json,stat as statmod,struct,traceback,zlib
from array import array
from collections import Counter
from pathlib import Path
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
RAW_CAP=6*1024*1024;DEC_CAP=64*1024*1024;MM_CAP=128*1024;OUTPUT_CAP=1024*1024
STOCK6=1973316;V2COUNT6=1984066;TOTAL6=2062771;TARGET=89455
COW=ROOT/'staging/navigation-native-lane-tree-cow-append-v1';UP=ROOT/'staging/navigation-v3-L6-exact-record-reuse-upper-bound-v1'
STATE={'phase':'notstarted','raw_bytes':184907,'decoded_bytes':288575,'completed':False};READS=[];NORMAL=[];RAM=[];GZIP_HINTS=[];HANDLES=[]
def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def st(p):
 s=p.stat();need(statmod.S_ISREG(s.st_mode),'Ordinary regular-file only')
 return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def account(raw=0,decoded=0):
 STATE['raw_bytes']+=raw;STATE['decoded_bytes']+=decoded
 need(STATE['raw_bytes']<=RAW_CAP and STATE['decoded_bytes']<=DEC_CAP,'Hard6MiB raw/64MiB decoded cumulative caps')
def read_small(p):
 before=st(p);need(before[2]<=65536 and STATE['raw_bytes']+before[2]<=RAW_CAP,'Small normal artifact cap')
 b=p.read_bytes();account(len(b),len(b));need(st(p)==before,'Normal owned artifact immutable')
 NORMAL.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':sha(b),'before':before,'after':st(p)})
 return b
def owned_gzip(p):
 b=read_small(p);decoded=gzip.decompress(b);account(decoded=len(decoded))
 return json.loads(decoded)
def save(name,data):
 b=(json.dumps(data,ensure_ascii=False,separators=(',',':'))+'\n').encode();need(len(b)<=150000,'Small new JSON')
 need(sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file() and p!=OUT/name)+len(b)<=OUTPUT_CAP,'Small new output namespace<=1MiB')
 (OUT/name).write_bytes(b)
def mm(phase):
 vals={}
 with open('/proc/self/status') as f:
  for l in f:
   k,_,v=l.partition(':')
   if k in ['VmRSS','VmHWM']:
    n,unit=v.split();need(unit=='kB','Actual current-mm unit');vals[k]=int(n)
 need(set(vals)=={'VmRSS','VmHWM'},'Actual current-mm RSS/HWM')
 bound=max(vals.values());STATE['phase']=phase;RAM.append({'phase':phase,**vals,'guarded_KiB':bound})
 need(bound<=MM_CAP,'128MiB sampled current-mm guard')
def seal_row(seal,name):
 return next(r for r in seal['files'] if r['path'].endswith('/'+name))
def check_row(path,r):
 expected=r.get('stat_at_seal',r.get('stat_after_freeze'));need(expected is not None and st(path)==expected,'Full inherited artifact stat pin')
 need(path.stat().st_size==r['bytes'],'Exact inherited artifact size');return expected
def isize_hint(path,r,decoded_expected):
 before=check_row(path,r)
 with path.open('rb') as f:f.seek(-4,2);tail=f.read(4)
 account(4,4);hint=struct.unpack('<I',tail)[0];need(st(path)==before,'ISIZE source unchanged')
 need(hint==decoded_expected,'GzipISIZE hint exact known source amount; not an EOF claim')
 GZIP_HINTS.append({'path':str(path.relative_to(ROOT)),'gzip_bytes':before[2],'ISIZE_hint':hint,'expected_decoded_bytes':decoded_expected,'actual_trailer_read_bytes':4})
 return hint
def stream_gzip(path,r,decoded_expected,decoded_digest,consumer):
 before=check_row(path,r);rawhash=hashlib.sha256();dechash=hashlib.sha256();rn=dn=ops=0;d=zlib.decompressobj(31)
 f=path.open('rb');closure={'path':str(path.relative_to(ROOT)),'before':before,'handle_closed':False};HANDLES.append(closure)
 try:
  while True:
   n=min(65536,before[2]-rn)
   if n==0:break
   need(STATE['raw_bytes']+n<=RAW_CAP,'Pre-read compressed source budget')
   raw=f.read(n);account(len(raw));rn+=len(raw);ops+=1;need(len(raw)==n,'Complete compressed fragment')
   rawhash.update(raw);pending=raw
   while pending:
    available=min(65536,DEC_CAP-STATE['decoded_bytes']);need(available>0,'Decoded budget before inflation')
    out=d.decompress(pending,available);account(decoded=len(out));dn+=len(out);dechash.update(out)
    if out:consumer(out)
    pending=d.unconsumed_tail;need(not d.unused_data,'Only source-observed single gzip member; trailing members held')
  out=d.flush();account(decoded=len(out));dn+=len(out);dechash.update(out)
  if out:consumer(out)
  need(d.eof and not d.unused_data and not d.unconsumed_tail,'Actualgzip CRC/trailer/EOF verified')
  need(rn==before[2] and rawhash.hexdigest()==r['sha256'],'Entire actual compressed digest matches closedpin')
  need(dn==decoded_expected and dechash.hexdigest()==decoded_digest,'Entire actual decoded length/digest matches closedpin')
  need(st(path)==before,'Full gzip source stat unchanged')
  row={'path':str(path.relative_to(ROOT)),'raw_bytes':rn,'decoded_bytes':dn,'raw_SHA256':rawhash.hexdigest(),'decoded_SHA256':dechash.hexdigest(),
       'compressed_read_ops':ops,'gzip_EOF_CRC_verified':True,'before':before,'after':st(path)}
  READS.append(row);return row
 finally:
  f.close();closure.update(handle_closed=f.closed,after=st(path),stat_unchanged=st(path)==before)
def main():
 need(not (OUT/'proof.json').exists() and not (OUT/'actual-failure.json').exists(),'Unique finite actual artifact pass')
 mm('initial')
 prep=json.loads(read_small(OUT/'preparation-read-budget.json'));extra=json.loads(read_small(OUT/'v3-integration-preparation-read-counts.json'))
 need(prep['total_actual_before_main_raw']+extra['raw_bytes']==184907 and prep['total_actual_before_main_decoded']+extra['decoded_bytes']==288575,'Exact prior ordinary source-read counters')
 c=owned_gzip(OUT/'small-input-capture.json.gz');v3cap=owned_gzip(OUT/'v3-integration-small-capture.json.gz')
 blobs={k:base64.b64decode(v) for k,v in c['blobs_base64'].items()};vblobs={k:base64.b64decode(v) for k,v in v3cap['blobs_base64'].items()}
 cow=json.loads(blobs['cow/proof.json']);cs=json.loads(blobs['cow/sealed-files.json']);upper=json.loads(blobs['upper/proof.json']);us=json.loads(blobs['upper/sealed-files.json']);result=json.loads(blobs['upper/result-summary.json']);v3=json.loads(vblobs['proof.json'])
 need(sha(blobs['cow/proof.json'])=='1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9'
  and sha(blobs['cow/sealed-files.json'])=='1c25b3963a3f9eb3b218a3747287e8154e253745698f5087064df1135445b077','COW closed fullpins bound by candidatev3proof')
 need(sha(blobs['upper/proof.json'])=='4afaafa7acddd900b63d648eedc22f1af0ac418ff4325051032b8758ad676a12'
  and sha(blobs['upper/sealed-files.json'])=='f116357618c853f8b50628cc290035c2fe4dcfd0b98439590155a2c82348888d'
  and sha(blobs['upper/result-summary.json'])=='4315cbbeb88143b9efe75748b165fa6a8e6da95dfcd833544378e9d7c8fab814','Exact upperproof/seal/summary pins')
 for tag,base,se in [('cow',COW,cs),('upper',UP,us)]:
  for rec in c['receipts']:
   if not rec['key'].startswith(tag+'/'):continue
   name=rec['key'].split('/',1)[1]
   if name=='sealed-files.json':continue
   row=seal_row(se,name);need(row['bytes']==rec['bytes'] and row['sha256']==rec['SHA256'],'Captured smallfile closed SHA/size')
   need(st(ROOT/rec['path'])==rec['stat_after'],'Captured closed smallfile source unchanged')
 need(v3['producer_proof_sha256']==sha(blobs['cow/proof.json']) and v3['all_assigned_checks_passed'],'Closed candidate binds exact COWproducer')
 app6=next(r for r in v3['actual_append_extraction_checks'] if r['level']==6)
 need(app6['matches_sealed_producer_stream'] and app6['records']==78705 and app6['extracted_sha256']==cow['append_artifacts']['6']['sha256'],'Actual candidate extracted L6append stream matches sameproducer')
 need(upper['all_assigned_checks_passed'] and upper['whole_actual_L6_digest_matches_closed'] and upper['stock_prefix_count']==STOCK6
  and upper['full_L6count']==TOTAL6 and upper['target_rows']==TARGET,'Counter source actual full68bit table/stockboundary')
 need(result['target_rows']==result['target_unique_keys']==TARGET and result['target_duplicate_multiplicity_histogram']=={'1':TARGET},'Source whole target unique verified')
 producer=blobs['cow/prepare_lane_cow_appends.py'].decode();measure=blobs['upper/measure_upper_bound.py'].decode();ast.parse(producer);ast.parse(measure);ast.parse(vblobs['build_country_native_lane_candidate_v3.py'])
 need(sha(blobs['cow/prepare_lane_cow_appends.py'])==cow['script_sha256'],'Exact closed COWscript sourcepin')
 need('index=len(multiplicity);target[key]=index;multiplicity.append(1);hits.append(0)' in measure and
  'for key in keys(tail,STOCK_COUNT,TARGET_COUNT,split):' in measure and 'for count,stockhits in zip(multiplicity,hits):' in measure
  and "need(sys.byteorder=='little' and pairs.itemsize==4" in measure,'Exact ordinal-preserving insertion/zip/u32le static flow')
 need("key=lambda x:(-x[0][0],x[1]['planned_new_first'])" in producer and "oldordinal==currentcount" in producer
  and "new_integer_leaf_count=len(inserts),inserted_new_ordinals=sorted(inserts)" in producer,'Exact ordered COW groupmetadata static flow')
 sourceflow={'upper_source_SHA256':sha(blobs['upper/measure_upper_bound.py']),'cow_source_SHA256':cow['script_sha256'],
  'counter_ordinal_rule':'Unique tailkeys extracted ascending fromglobal ordinalSTOCK_COUNT; insertionindex len(multiplicity), thenzip arrays withoutsort; counterrow i→L6ID1973317+i.',
  'COWmetadata_rule':'Sort levels descending then newfirst; newfirst=currenttablecount+writer.records+1, emits entiregroupcount in preserved oldorder plus insertedordinals. Each copiedparent points to full newfirst/newcount; selectedL3 ranges also fullgroup.',
  'actual_compiled_binding':'Closed candidateproof extracts full78705 significant L6append and matches exact producer append digest; upper actual fullL6digest matches closedsource table. No fresh IMG/table comparison here.',
  'limits':['These are nominal closed writer/source/dataflow proofs, not fresh inventory of all actual/native incoming references.','Additional unknown runtime partialranges,external indices,caches/highflags remainheld.','Counter ledger holds counts only; no stockdonor IDs or contiguousmatching sequences are supplied.'],
  'reviewedcode_execution':False}
 save('source-dataflow-review.json',sourceflow)
 gr=cow['artifacts']['groups'];cr=seal_row(cs,'emitted-cow-groups.jsonl.gz');ur=seal_row(us,'target-multiplicity-stock-hits.u32le.gz');um=result['ledger']
 need(gr['path']==cr['path'] and gr['bytes']==cr['bytes']==4631695 and gr['sha256']==cr['sha256'],'Exact group ledger pins')
 need(ur['sha256']==um['gzip_sha256']=='17d910c60343f68d5ef3d565078de266dc757ab6456057d563c8fd6e1f65d4cf'
  and ur['bytes']==um['gzip_bytes']==11207 and um['uncompressed_bytes']==715640,'Exact ordinalcounter gzip pins')
 isize_hint(ROOT/cr['path'],cr,gr['uncompressed_bytes']);isize_hint(ROOT/ur['path'],ur,um['uncompressed_bytes'])
 future_raw=STATE['raw_bytes']+cr['bytes']+ur['bytes'];future_dec=STATE['decoded_bytes']+gr['uncompressed_bytes']+um['uncompressed_bytes']
 need(future_raw<=RAW_CAP and future_dec<=DEC_CAP,'Exacthint length source preflight within6MiB/64MiB without raising')
 save('preflight.json',{'actual_cumulative_before_gzip':dict(STATE),'GZIP_ISIZE_hints':GZIP_HINTS,'planned_final_raw_bytes_before_smallproof_readback':future_raw,
  'planned_final_decoded_bytes_before_smallproof_readback':future_dec,'caps':{'raw':RAW_CAP,'decoded':DEC_CAP},'IMGreads':0,'no_EOF_claim_from_ISIZE_alone':True})
 counter=bytearray()
 def consume_counter(b):
  counter.extend(b);need(len(counter)<=715640,'Counter decoded payload715640 exact upperbound')
 stream_gzip(ROOT/ur['path'],ur,um['uncompressed_bytes'],um['uncompressed_sha256'],consume_counter)
 need(len(counter)==TARGET*8,'Every counter row pair available')
 zeros=array('I',[0]);hist=Counter();allone=True
 for multiplicity,hits in struct.iter_unpack('<II',counter):
  need(multiplicity==1 and hits in [0,1,2],'Actual targetkeysunique and bounded source stockhits0/1/2')
  zeros.append(zeros[-1]+int(hits==0));hist[(multiplicity,hits)]+=1
 need(len(zeros)==TARGET+1 and zeros[-1]==15683 and hist==Counter({(1,0):15683,(1,1):73767,(1,2):5}),'All89455 actual ordinal counters/histogram match closed result')
 mm('full ordinalcounter parsed')
 rows=0;levels=Counter();oldcounts=Counter();newcounts=Counter();insertcounts=Counter();patchcounts=Counter();seen=set();cursor={i:int(cow['final_table_counts'][str(i)])-cow['append_artifacts'][str(i)]['record_count']+1 for i in [4,5,6]}
 prior_sort=None;buffer=bytearray();l6groups=0;group_zero=Counter();l6newonly=0;insertnewonly=0;oldnewonly=0;owners=Counter();selectedh=hashlib.sha256();selectedbytes=0
 samples=[];outpath=OUT/'selected-L6-group-summary.jsonl.gz';outf=outpath.open('xb');zout=gzip.GzipFile(filename='',fileobj=outf,mode='wb',mtime=0)
 def parse_line(line):
  nonlocal rows,prior_sort,l6groups,l6newonly,insertnewonly,oldnewonly,selectedbytes
  need(line.endswith(b'\n') and len(line)<=1048576,'Complete bounded original JSONL line')
  r=json.loads(line);g=r['current_group'];level=g['level'];first=g['first'];count=g['count'];nf=r['new_first'];nc=r['new_count'];ins=r['new_integer_leaf_count'];insertions=r['inserted_new_ordinals'];patch=r['explicit_patch_count']
  need(level in [4,5,6] and all(type(x)is int and x>0 for x in [first,count,nf,nc]),'Exact positive typed group shape')
  key=(level,first,count);need(key not in seen,'Every exact currentgroup unique');seen.add(key)
  sk=(-level,nf);need(prior_sort is None or prior_sort<sk,'Actual groups levelsdesc/newfirst sortedstrict');prior_sort=sk
  need(nf==cursor[level] and nc==count+ins,'Complete contiguous append group coverage and no oldrows lost');cursor[level]+=nc
  need(r['record_bits']=={4:128,5:126,6:68}[level] and r['appended_bit_offset']==(nf-(int(cow['final_table_counts'][str(level)])-cow['append_artifacts'][str(level)]['record_count'])-1)*r['record_bits'],
       'Actual global appendbit offset/stride first relation')
  need(r['append_initial_bit_shift']==r['appended_bit_offset']%8 and r['all_other_old_significant_bits_preserved'] and r['old_relative_order_preserved'],'Complete original field/order preservation metadata')
  need(type(ins)is int and ins>=0 and len(insertions)==ins and all(type(i)is int and 0<=i<nc for i in insertions)
   and all(a<b for a,b in zip(insertions,insertions[1:])), 'Exact unique sorted insertedordinals')
  need(r['source_significant_records_sha256']==g['significant_records_sha256'] and type(patch)is int and 0<=patch<=count,'Original significantrecords/patch metadata')
  rows+=1;levels[level]+=1;oldcounts[level]+=count;newcounts[level]+=nc;insertcounts[level]+=ins;patchcounts[level]+=patch
  if level==6:
   need(patch==0 and nf>=V2COUNT6+1 and nf+nc-1<=TOTAL6,'Original L6 nochildpatch and complete v3suffix bounds')
   start=nf-(STOCK6+1);end=start+nc;need(0<=start<end<=TARGET,'Counter global sourceordinal bounds')
   zero= zeros[end]-zeros[start];insertzero=sum(int(zeros[start+i+1]!=zeros[start+i]) for i in insertions);clonezero=zero-insertzero
   l6groups+=1;l6newonly+=zero;insertnewonly+=insertzero;oldnewonly+=clonezero;group_zero['has_stockhit0' if zero else 'all_rows_have_stockhit']+=1
   own=r['current_parent_owners'];need(isinstance(own,list) and len(own)>0 and all(type(x)is int and x>0 for x in own),'Closed parentowner typed positive records')
   owners[len(own)]+=1
   item={'source_first':first,'source_count':count,'new_first':nf,'new_count':nc,'new_integer_leaf_count':ins,
    'stockhit0_rows':zero,'inserted_stockhit0_rows':insertzero,'cloned_stockhit0_rows':clonezero,'all_current_parent_owners_count':len(own),
    'counter_ordinals':[start,end],'actual_counter_range_SHA256':sha(memoryview(counter)[start*8:end*8]),
    'new_significant_records_SHA256':r['new_significant_records_sha256'],'source_significant_records_SHA256':r['source_significant_records_sha256'],
    'whole_originalstock_identical68bit_group_excluded':zero>0}
   raw=(json.dumps(item,separators=(',',':'))+'\n').encode();zout.write(raw);selectedh.update(raw);selectedbytes+=len(raw)
   if len(samples)<6:samples.append({k:item[k] for k in ['new_first','new_count','new_integer_leaf_count','stockhit0_rows','inserted_stockhit0_rows']})
  if rows%5000==0:
   mm('parsed groupmetadata '+str(rows));print(json.dumps({'phase':'streaming groupmetadata','groups':rows,'decoded_artifact_bytes':STATE['decoded_bytes']}),flush=True)
 def consume_groups(data):
  buffer.extend(data)
  while True:
   at=buffer.find(b'\n')
   if at<0:break
   line=bytes(buffer[:at+1]);del buffer[:at+1];parse_line(line)
  need(len(buffer)<=1048576,'Actual pendingJSONL line bound')
 try:stream_gzip(ROOT/cr['path'],cr,gr['uncompressed_bytes'],gr['uncompressed_sha256'],consume_groups)
 finally:zout.close();outf.close()
 need(not buffer and rows==gr['rows']==29866,'All original group rowsEOF parsed once')
 need(dict(levels)=={6:4676,5:17608,4:7582},'Exactgroup levels fromclosed appendshifts')
 need(all(cursor[i]==int(cow['final_table_counts'][str(i)])+1 for i in [4,5,6]),'Entire appendedsource suffix levelscovered')
 need(newcounts[6]==78705 and oldcounts[6]==65090 and insertcounts[6]==13615,'Actual all L6groups old/newleaf counts exact sourceproof')
 need(newcounts[5]==410272 and oldcounts[5]==365654 and insertcounts[5]==44618 and newcounts[4]==1114642,'Complete alllevels groupmetadata agreesclosedcounts')
 mm('all actual artifactpredicates complete')
 all_excluded=group_zero['all_rows_have_stockhit']==0
 prefix_zero=zeros[V2COUNT6-STOCK6];optimistic_v2bound=V2COUNT6-STOCK6
 conclusion={'v3_introduced_whole_group_count':l6groups,'groups_containing_at_least_one_actual_stockhit0':group_zero['has_stockhit0'],
  'groups_with_every_row_stockmatched':group_zero['all_rows_have_stockhit'],'all_v3_introduced_complete_groups_excluded_from_identical_originalstock_sharing':all_excluded,
  'actual_v3_suffix_rows':newcounts[6],'suffix_stockhit0_rows':l6newonly,'inserted_newleaf_stockhit0_rows':insertnewonly,'cloned_old_stockhit0_rows':oldnewonly,
  'actual_v2_poststock_rows':optimistic_v2bound,'v2_poststock_stockhit0_rows':prefix_zero,'optimistically_every_v2_poststock_row_savable':optimistic_v2bound,
  'required_savings_under_closed_combined_L4_L5_capacity':71359,'whole_group_only_capacity_route_excluded_if_fullgroup_contract':all_excluded and optimistic_v2bound<71359,
  'not_global_zero_reuse_or_other_encoding_exclusion':True}
 save('result-summary.json',conclusion)
 save('proof.json',{'schema':'artifact-only-L6-whole-group-stock-sharing-preflight/v1','all_assigned_actual_artifact_checks_completed':True,
  'predicate_conclusion':conclusion,'complete_group_counts_by_level':dict(levels),'complete_oldrow_counts_by_level':dict(oldcounts),
  'complete_appended_counts_by_level':dict(newcounts),'complete_inserted_leaf_counts_by_level':dict(insertcounts),'all_patch_counts_by_level':dict(patchcounts),
  'L6_owner_count_distribution':dict(owners),'all_source_groups_sorted_and_complete_contiguous_append_coverage':True,
  'actual_counter_histogram':[{'target_multiplicity':a,'stock_hits':b,'rows':n} for (a,b),n in sorted(hist.items())],
  'counter_i_exact_global_L6ID':'1973317+i, i0..89454; static sourceflow + actual uniquemultiplicity and fullcounter source pins',
  'group_source_actual_full_read_receipts':READS,'all_normal_cached_input_reads':NORMAL,'sourceflow':sourceflow,
  'preparation_initial_budgets':{'raw':184907,'decoded':288575},'actual_resource_counters':dict(STATE),'raw_cap':RAW_CAP,'decoded_cap':DEC_CAP,
  'current_mm_observations':RAM,'current_mm_cap_KiB':MM_CAP,'selected_summary':{'path':'selected-L6-group-summary.jsonl.gz','groups':l6groups,
   'uncompressed_bytes':selectedbytes,'uncompressed_SHA256':selectedh.hexdigest(),'compressed_bytes':outpath.stat().st_size},
  'finite_samples_no_labels_or_coordinates':samples,'limitations':['Counter stockhit0 denies any identical originalstock68bit row, hence each entire group containing0 cannot equal any ordered originalstock group. No donor search is needed for this negative predicate.',
   'Maximum10750 treats every prior v2poststock row as savable; it is an optimistic upper bound only for complete emitted v3group→originalstock sharing, not safe deletion.',
   'Closed writer fullparentfirst/count/source append integration binds generateddata; no fresh inventory of actual/native runtime incoming,partialranges,externalindices/caches/highflag ABI.',
   'Inplace free-run reuse,new encoding,expanded4K/header controls,renderer/UI/rootcause and physicalcapacity are not excluded by this finite predicate.'],
  'falseflags':{'IMG_read':False,'IMG_constructed':False,'compactor':False,'source_or_oldseal_write':False,'nativeCPU':False,'guest':False,'MAIN':False,'PBF':False,'device':False,'audio':False,'install':False,'rendererfix':False,'routeUI':False,'App':False,'fullgoal':False}})
 STATE['completed']=True
 print(json.dumps({'all_assigned_artifact_checks_completed':True,'all_original_group_rows':rows,'L6groups':l6groups,'groups_with_stockhit0':group_zero['has_stockhit0'],
  'whole_v3_groups_excluded':all_excluded,'old_v2_optimistic_bound':optimistic_v2bound,'required_rows':71359,
  'wholegroup_capacity_route_excluded_conditionally':all_excluded and optimistic_v2bound<71359,'actual_raw_artifact_bytes':STATE['raw_bytes'],
  'actual_decoded_artifact_bytes':STATE['decoded_bytes'],'current_mm_peak_KiB':max(r['guarded_KiB'] for r in RAM),'IMGreads':0}),flush=True)
 return True
if __name__=='__main__':
 try:main()
 except BaseException as e:
  save('actual-failure.json',{'type':type(e).__name__,'error':str(e),'traceback':traceback.format_exc(),'actual_state':STATE,
   'normal_input_reads':NORMAL,'completed_gzip_read_receipts':READS,'gzip_hints':GZIP_HINTS,'handles':HANDLES,'RAM':RAM,
   'constraints_not_relaxed':True,'stop_after_this_failure':True});raise
 finally:save('actual-file-handle-closure.json',{'gzip_handles':HANDLES,'all_handles_closed':all(r['handle_closed'] for r in HANDLES),
  'all_source_stats_unchanged':all(r.get('stat_unchanged',False) for r in HANDLES),'actual_state':STATE,'all_completed_source_read_receipts':READS})
