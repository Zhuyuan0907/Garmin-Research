#!/usr/bin/env python3
"""Bounded ordinary DATA exclusivity/fullbit comparison. No IMG output or patch."""
import sys
sys.dont_write_bytecode=True
import ast,builtins,dis,gzip,hashlib,json,os,struct,traceback
from array import array
from collections import Counter
from pathlib import Path
from types import CodeType,FunctionType

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
V5=ROOT/'staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5'
IMG_LIMIT=64000000;RSS_LIMIT=192*1024;OUTPUT_LIMIT=1048576;STOCK_L4=2133948
PROFILES=[(122,[16,9,24,19,1,10,0,0],[1,1]),(122,[16,9,24,19,1,10,0,0],[1,1]),
 (112,[23,9,24,19,1,12,0,0],[1,0]),(128,[22,9,24,19,1,10,0,0],[1,1]),
 (126,[21,9,24,19,1,9,0,0],[1,1]),(68,[0,0,24,19,1,0,0,0],[1,0])]
PINS={
 'v2':{'path':'staging/navigation-country-native-candidate-v2/gmapprom1.img','bytes':128356352,'block_bytes':4096,
   'SHA256':'925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb','counts':[22,343,47870,3781594,2667573,1984066],
   'seal':'staging/navigation-country-native-candidate-v2/sealed-files.json','seal_SHA256':'659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766'},
 'v3':{'path':'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img','bytes':153346048,'block_bytes':8192,
   'SHA256':'1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360','counts':[22,343,47870,4896236,3077845,2062771],
   'seal':'staging/navigation-country-native-lane-candidate-v3/sealed-files.json','seal_SHA256':'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335'}}
NORMAL_PINS=[];RAM=[];IMAGES=[];SOURCE_BEFORE={};JOURNAL={'phase':'preparation','program_completed':False}

def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(n,x):
 b=(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n').encode()
 if n.endswith('.gz'):b=gzip.compress(b,mtime=0)
 need(len(b)<=600000,'Small per-artifact bound')
 projected=sum(p.stat().st_size for p in OUT.iterdir() if p.is_file() and p.name!=n)+len(b)
 need(projected<=OUTPUT_LIMIT,'Whole new namespace <=1MiB before output write')
 (OUT/n).write_bytes(b)
def rss(phase):
 values={}
 with open('/proc/self/status') as f:
  for line in f:
   key,_,v=line.partition(':')
   if key in ['VmRSS','VmHWM','VmSize','VmPeak']:
    n,unit=v.split();need(unit=='kB','Actual proc unit');values[key+'_KiB']=int(n)
 need('VmRSS_KiB' in values and 'VmHWM_KiB' in values,'Current-mm RSS/HWM observations')
 guarded=max(values['VmRSS_KiB'],values['VmHWM_KiB'])
 RAM.append({'phase':phase,**values,'guarded_current_mm_KiB':guarded,'cap_KiB':RSS_LIMIT})
 JOURNAL['phase']=phase
 need(guarded<=RSS_LIMIT,'192MiB sampled current-mm RSS/HWM guard')
 return guarded
def pin(p,digest,as_json=True):
 before=stat(p);need(before[2]<=65536,'Only small normal input<=64KiB')
 b=p.read_bytes();need(stat(p)==before and sha(b)==digest,'Normal input SHA/stat pin '+str(p))
 NORMAL_PINS.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':digest,'stat_before':before,'stat_after':stat(p)})
 return json.loads(b) if as_json else b

class Budget:
 def __init__(self):
  self.bytes=self.ops=0;self.h=hashlib.sha256();self.first=[];self.last=[];self.sources=Counter();self.purposes=Counter()
 def read(self,image,at,n,purpose):
  need(0<=at<=at+n<=image.size and self.bytes+n<=IMG_LIMIT,'Actual combined IMG64000000-byte cap')
  image.f.seek(at);b=image.f.read(n);need(len(b)==n,'Actual complete physical read')
  row={'source':image.name,'offset':at,'bytes':n,'SHA256':sha(b),'purpose':purpose}
  self.h.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
  self.bytes+=len(b);self.ops+=1;self.sources[image.name]+=len(b);self.purposes[purpose.split(';')[0]]+=len(b)
  if len(self.first)<8:self.first.append(row)
  self.last=(self.last+[row])[-8:]
  return b
 def receipt(self):
  return {'actual_IMG_bytes_read':self.bytes,'actual_IMG_read_ops':self.ops,'hard_combined_IMG_read_cap':IMG_LIMIT,
   'by_source':dict(self.sources),'by_purpose':dict(self.purposes),'all_actual_physical_read_receipts_SHA256':self.h.hexdigest(),
   'first_actual_reads':self.first,'last_actual_reads':self.last,'whole_IMG_or_MDR_hash_recomputed':False}

def preflight(env,cls):
 required=set();objects=[]
 def visit(code,label):
  objects.append(label)
  for op in dis.get_instructions(code):
   if op.opname=='LOAD_GLOBAL':required.add(op.argval)
  for i,c in enumerate(code.co_consts):
   if isinstance(c,CodeType):visit(c,label+':nested'+str(i))
 for name,value in cls.__dict__.items():
  if isinstance(value,FunctionType):visit(value.__code__,name)
 missing=sorted(k for k in required if k not in env and not hasattr(builtins,k))
 result={'code_objects_checked':objects,'required_globals':sorted(required),'unresolved_globals':missing,'IMG_bytes_at_preflight':0}
 save('mapper-global-preflight.json',result);need(not missing,'Mapper global preflight missing '+str(missing))
 return result

def actual_tables(image,pinrow):
 h=image.logical('00004171.MDR',0,772,'actual MDR header')
 need(struct.unpack_from('<H',h)[0]==772 and h[2:12]==b'GARMIN MDR','MDR marker')
 at,n,item,flag=struct.unpack_from('<4I',h,600)
 need((n,item,flag)==(120,20,1) and at+120==image.components['00004171.MDR']['size'],'Actual DIR EOF')
 d=image.logical('00004171.MDR',at,120,'actual six table descriptors')
 tables=[]
 for i,profile in enumerate(PROFILES):
  a,b,stride,w,x=struct.unpack_from('<5I',d,i*20)
  widths=[w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63,x>>11&63,x>>17&63];refs=[w>>30&1,w>>31&1]
  count=b*8//stride
  need((stride,widths,refs)==profile and count==pinrow['counts'][i] and b==(count*stride+7)//8,'Exact actual pinned descriptor profile/count')
  tables.append({'level':i+1,'start':a,'bytes':b,'stride':stride,'count':count,'widths':widths,'refs':refs})
 cursor=tables[5]['start'];need(cursor==4195100,'Actual unchanged pre-table suffix boundary')
 for level in [6,5,4,3,2,1]:
  t=tables[level-1];need(t['start']==cursor,'Actual tight table sequence');cursor+=t['bytes']
 need(cursor==at,'Actual tables end at DIR')
 raw=image.logical('00004171.MDR',tables[2]['start'],tables[2]['bytes'],'actual complete L3 cache')
 need(len(raw)==670180,'Actual47870 stride112 L3 bytes')
 return tables,raw,{'header_SHA256':sha(h),'DIR_hex':d.hex(),'DIR_SHA256':sha(d),'L3_bytes':len(raw),'L3_SHA256':sha(raw),
  'directory_start':at,'container_metadata_bytes':image.directory_end,'components':{k:v['size'] for k,v in image.components.items()}}

def roots(raw):
 f=array('I',[0])*47871;n=array('H',[0])*47871;flags=array('H',[0])*47871;counts=Counter()
 for ID,(lo,_,__) in enumerate(struct.iter_unpack('<QIH',raw),1):
  need(lo&1==1,'Actual L3 mapordinal1 required for this fixed profile')
  f[ID]=(lo>>20)&0x7fffff;n[ID]=(lo>>43)&4095;flags[ID]=(lo>>55)&511;counts[flags[ID]]+=1
 return (f,n,flags),dict(counts)

def occupancy(tag,fields,total):
 rss(tag+' before difference array')
 diff=array('i',[0])*(total+2);ranges=0;f,n,flags=fields
 for ID in range(1,47871):
  if flags[ID]&7!=4:continue
  if f[ID]==n[ID]==0:continue
  need(1<=f[ID]<=f[ID]+n[ID]-1<=total and n[ID]>0,'Every actual L3target4 range bounds')
  diff[f[ID]]+=1;diff[f[ID]+n[ID]]-=1;ranges+=1
 rss(tag+' difference array allocated')
 occupied=bytearray(total+1);running=0;distribution=Counter();maximum=0
 for ID in range(1,total+1):
  running+=diff[ID];need(running>=0,'Nonnegative actual occupancy')
  saturated=min(2,running);occupied[ID]=saturated;distribution[saturated]+=1;maximum=max(maximum,running)
  if ID%262144==0:rss(tag+' occupancy '+str(ID))
 need(running+diff[total+1]==0,'All actual range ends accounted')
 del diff;rss(tag+' occupancy completed')
 return occupied,{'all_L3_records_examined':47870,'all_actual_L3target4_ranges':ranges,'all_highflags_target4_included':True,
   'saturation':'0=no liveL3 ref,1=exclusive,2=two or more','saturated_slot_counts':dict(distribution),
   'maximum_actual_degree':maximum,'occupancy_bytes':len(occupied),'occupancy_SHA256':sha(occupied)}

def arithmetic(summary,containers,savings):
 baseline=summary['stock_prefix_plus_active'];retained={int(k):v for k,v in baseline['retained_total_lower_counts'].items()}
 retained[4]-=savings;need(retained[4]>=STOCK_L4,'Keep complete stock L4 ID prefix')
 lower={i:(retained[i]*stride+7)//8 for i,stride in [(4,128),(5,126),(6,68)]}
 mdr=baseline['arithmetic']['MDR_bytes_after']-savings*16
 sizes=dict(containers);sizes['00004171.MDR']=mdr
 blocks={k:(v+4095)//4096 for k,v in sizes.items()};parts={k:(n+239)//240 for k,n in blocks.items()}
 rows=1+sum(parts.values());metadata=((4096+rows*512+4095)//4096)*4096;metadata=max(73728,metadata)
 image=metadata+sum(blocks.values())*4096;capacity=134217728
 widths=retained[4]<1<<23 and retained[5]<1<<22 and retained[6]<1<<21
 return {'baseline_retained_lower_counts':baseline['retained_total_lower_counts'],'discarded_exclusive_newclone_L4_rows':savings,
  'retained_lower_counts_after_reuse':retained,'L5_L6_retention_counts_changed':False,'lower_table_bytes_after':lower,
  'MDR_bytes_after':mdr,'component_sizes':sizes,'component_4K_blocks':blocks,'component_FAT_parts':parts,
  'root_plus_component_FAT_rows':rows,'4K_metadata_bytes':metadata,'projected_4K_IMG_bytes':image,
  'original_declared_capacity':capacity,'capacity_margin':capacity-image,'fits_original_4K_arithmetic':image<=capacity,
  'incoming_field_widths_valid':widths,'metadata_single_root_blocks_valid':metadata//4096<=240,
  'all_original_stock_lower_IDs_retained':True,'future_compactor_must_apply_suffix_rank_and_pointer_remap':True,
  'arithmetic_only_not_constructed_IMG_or_install':True}

def main():
 need(not (OUT/'proof.json').exists() and not (OUT/'actual-failure.json').exists(),'Fresh unique scope, no replay')
 rss('initial current-mm')
 v5proof=pin(V5/'proof.json','ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82')
 summarypin=v5proof['artifacts']['summary'];summary=pin(ROOT/summarypin['path'],summarypin['sha256'])
 pin(V5/'observed_analyzer.py','1e7888373c759b72c206f0fef11cf189cffa4ef98299f61ebe2c7bb948be1a6b',False)
 baseline=summary['stock_prefix_plus_active'];need(v5proof['all_assigned_data_feasibility_checks_completed'] and
  baseline['retained_total_lower_counts']=={'4':3889829,'5':3074293,'6':2062771} and
  baseline['arithmetic']['projected_conservative_4K_IMG_bytes']==137170944 and
  not baseline['invalid_or_unclassified_child_encoding_counts'] and not baseline['unknown_raw_flag_counts'] and
  not baseline['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention'],'Exact noanomaly V5 baseline')
 mapper=pin(ROOT/'staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py',
   'a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095',False)
 tree=ast.parse(mapper.decode());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Image')
 names=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NAMES' for t in n.targets))
 astpin=sha(ast.dump(cls,include_attributes=False).encode());need(astpin==v5proof['mapper_AST_sha256'],'Same frozen mapper Image AST')
 env={'need':need,'struct':struct};exec(compile(ast.Module(body=[names,cls],type_ignores=[]),'pinned_normal_Image_AST','exec'),env)
 pre=preflight(env,env['Image']);del tree,cls,names,mapper
 pin(ROOT/'staging/navigation-country-native-lane-candidate-v3/proof.json',
   'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0')
 facts=pin(ROOT/'staging/navigation-native-L3-width-policy-static-v1/candidate-layout-and-CPU-facts.json',
   '3305e1aa1019c1920fee5e8993936d21aa0fe0ebb79d745a624ae900978868e9')
 imagefacts={};before={};caches={};tables={};fields={};degrees={};degreefacts={};rootflags={}
 for tag,p in PINS.items():
  s=pin(ROOT/p['seal'],p['seal_SHA256']);r=next(r for r in s['files'] if r['path']==p['path'])
  before[tag]=stat(ROOT/p['path']);SOURCE_BEFORE[tag]=before[tag]
  need(before[tag][:4]==r['stat_at_seal'][:4] and r['sha256']==p['SHA256'],'Exact inherited IMG dev/inode/size/mtime/hash pin')
  f=(ROOT/p['path']).open('rb')
  try:image=env['Image'](tag,f,p,BUDGET)
  except BaseException:
   f.close();JOURNAL['constructor_failed_readonly_handle_closed']=f.closed;raise
  IMAGES.append(image)
  tables[tag],caches[tag],imagefacts[tag]=actual_tables(image,p);fields[tag],rootflags[tag]=roots(caches[tag])
  degrees[tag],degreefacts[tag]=occupancy(tag,fields[tag],tables[tag][3]['count'])
  profile=facts['profiles']['country_v2' if tag=='v2' else 'lane_v3'];need(imagefacts[tag]['DIR_hex']==profile['directory_source']['hex'],'Actual DIR matches sealed prior profile witness')
  rss(tag+' metadata/L3/occupancy done')
 need(imagefacts['v2']['L3_SHA256']=='2cd4c24f263cb6df6c863d1113992f3959090c1d99ebf26159288109b1d9ad21','Original current v2 L3 complete hash')
 rejected=Counter();structural=[];mask3=((1<<35)-1)<<20
 f2,n2,flag2=fields['v2'];f3,n3,flag3=fields['v3']
 for ID in range(1,47871):
  if flag2[ID]!=4 or flag3[ID]!=4:rejected['not_exact_rawflag4_both']+=1;continue
  a,b=int.from_bytes(caches['v2'][(ID-1)*14:ID*14],'little'),int.from_bytes(caches['v3'][(ID-1)*14:ID*14],'little')
  if (a^b)&~mask3:rejected['root_bits_outside_first_count_differ']+=1;continue
  if n2[ID]!=n3[ID] or n2[ID]==0:rejected['root_group_count_diff_or_empty']+=1;continue
  first,count,newfirst=f2[ID],n2[ID],f3[ID]
  if not(1<=first<=first+count-1<=STOCK_L4):rejected['old_v2_group_not_entire_stockprefix']+=1;continue
  if newfirst<=STOCK_L4:rejected['current_group_not_poststock_clone']+=1;continue
  if any(x!=1 for x in degrees['v2'][first:first+count]):rejected['old_v2_range_not_exclusive_across_allL3']+=1;continue
  if any(x!=0 for x in degrees['v3'][first:first+count]):rejected['old_stock_range_still_live_under_v3_L3']+=1;continue
  if any(x!=1 for x in degrees['v3'][newfirst:newfirst+count]):rejected['new_v3_range_not_exclusive_across_allL3']+=1;continue
  structural.append({'root_ID':ID,'oldfirst':first,'newfirst':newfirst,'count':count})
 required=sum(r['count']*32 for r in structural)
 read_plan={'structural_candidate_roots':len(structural),'structural_candidate_L4_rows':sum(r['count'] for r in structural),
  'actual_IMG_bytes_before_L4':BUDGET.bytes,'required_exact_old_new_L4_read_bytes':required,
  'projected_total_actual_IMG_bytes':BUDGET.bytes+required,'hard_total_limit':IMG_LIMIT,'rejected_root_counts':dict(rejected)}
 save('actual-L4-read-budget-preflight.json',read_plan)
 print(json.dumps({'phase':'actual structural candidate preflight',**read_plan}),flush=True)
 if BUDGET.bytes+required>IMG_LIMIT:
  # Keep cap: close with a real finite gap, never raise or silently select a successful subset.
  save('budget-gap.json',{'all_structural_roots_examined':True,'all_target_L4_rows_compared':False,**read_plan,
   'cap_not_raised':True,'next_root_decision_required':True});return False
 accepted=[];failed=[];samples=[];mask4=((1<<32)-1)<<39;compared=changed=0;flags=Counter();rolling=hashlib.sha256()
 for ordinal,r in enumerate(structural):
  ID,first,newfirst,count=r['root_ID'],r['oldfirst'],r['newfirst'],r['count']
  oldat=tables['v2'][3]['start']+(first-1)*16;newat=tables['v3'][3]['start']+(newfirst-1)*16
  oldraw=IMAGES[0].logical('00004171.MDR',oldat,count*16,'candidate old stock L4 root'+str(ID))
  newraw=IMAGES[1].logical('00004171.MDR',newat,count*16,'candidate new v3 L4 root'+str(ID))
  bad=edits=0;firstbad=[];row_samples=[];outsidehash=hashlib.sha256();gflags=Counter()
  for i,((alo,ahi),(blo,bhi)) in enumerate(zip(struct.iter_unpack('<QQ',oldraw),struct.iter_unpack('<QQ',newraw),strict=True)):
   a=alo|(ahi<<64);b=blo|(bhi<<64);delta=a^b;outside=delta&~mask4
   if outside:
    bad+=1
    if len(firstbad)<3:firstbad.append({'ordinal':i,'old128':a.to_bytes(16,'little').hex(),'new128':b.to_bytes(16,'little').hex(),'outside_mask_delta_hex':outside.to_bytes(16,'little').hex()})
   if delta&mask4:edits+=1
   outsidehash.update((a&~mask4).to_bytes(16,'little'));gflags[(ahi>>7)&511]+=1
   if (i<2 or (delta&mask4 and len(row_samples)<4)) and len(row_samples)<4:
    row_samples.append({'ordinal':i,'old_ID':first+i,'new_ID':newfirst+i,'old128':a.to_bytes(16,'little').hex(),'new128':b.to_bytes(16,'little').hex(),
     'old_MDR_offset':oldat+i*16,'new_MDR_offset':newat+i*16,'only_first_count_delta':not bool(outside)})
  compared+=count;changed+=edits;flags.update(gflags)
  row=dict(r,old_group_SHA256=sha(oldraw),new_group_SHA256=sha(newraw),outside_mask_original_bits_SHA256=outsidehash.hexdigest(),
     rows_with_first_count_delta=edits,rows_with_outside_mask_delta=bad,
     original_v2_L3_hex=caches['v2'][(ID-1)*14:ID*14].hex(),current_v3_L3_hex=caches['v3'][(ID-1)*14:ID*14].hex())
  rolling.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
  if bad:failed.append(dict(row,first_bad_rows=firstbad))
  else:accepted.append(row)
  if len(samples)<20:samples.append({'root_ID':ID,'group_reuse_eligible':not bad,'old_first':first,'new_first':newfirst,'count':count,'rows':row_samples})
  if ordinal%64==0:rss('actual L4 group comparisons '+str(ordinal))
 def disjoint(key):
  ordered=sorted((r[key],r[key]+r['count']-1,r['root_ID']) for r in accepted)
  need(all(a[1]<b[0] for a,b in zip(ordered,ordered[1:])),'Accepted '+key+' ranges pairwise disjoint')
  return {'ranges_checked':len(ordered),'all_pairwise_disjoint':True}
 pairwise={'oldstock':disjoint('oldfirst'),'newclones':disjoint('newfirst')}
 savings=sum(r['count'] for r in accepted);plan=arithmetic(summary,imagefacts['v3']['components'],savings)
 baselinecalc=arithmetic(summary,imagefacts['v3']['components'],0)
 need(baselinecalc['projected_4K_IMG_bytes']==137170944,'Independent original4K/FAT baseline matches V5')
 need(BUDGET.bytes==read_plan['projected_total_actual_IMG_bytes'],'Exact targeted source read plan consumed, no hidden fulltable pass')
 for tag in PINS:need(stat(ROOT/PINS[tag]['path'])==before[tag],'Source stat immutable during actual comparisons')
 save('reuse-root-plan.json.gz',{'schema':'exclusive-stock-L4-reuse-readonly-plan/v1','roots':accepted,
  'source_pairwise_ranges':pairwise,'only_old_L4_first_count_fields_would_be_patched':True,
  'all_actual_128bits_outside39_to70_identical':True,'all_original_stock_lower_IDs_unchanged':True,
  'v3_root_first_would_redirect_to_oldstock_count_unchanged':True,'L5_L6_childtrees_not_dropped_or_rewritten':True,
  'current_v3_newclone_groups_would_be_omitted_from_future_compaction':True,'this_scope_has_no_actual_image_edits':True})
 save('actual-rejected-L4-groups.json.gz',{'failed_groups':failed,'any_outside_mask_difference_rejects_whole_root':True})
 save('actual-raw-row-samples.json',{'samples':samples,'sample_only_fullcase_comparison_count':compared})
 save('capacity-arithmetic.json',plan)
 rss('all actual DATA comparisons completed')
 save('proof.json',{'schema':'actual-exclusive-stock-L4-reuse-feasibility/v1','all_assigned_actual_DATA_checks_completed':True,
  'V5_baseline_proof_SHA256':'ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82',
  'normal_input_pins':NORMAL_PINS,'mapper_AST_SHA256':astpin,'mapper_global_preflight':pre,
  'actual_source_metadata':imagefacts,'actual_source_tables':tables,'all_L3_raw_flag_counts':rootflags,
  'actual_saturated_occupancy_all_L3target4':degreefacts,'structural_candidate_roots':len(structural),
  'actual_old_new_L4_rows_compared':compared,'exact128bit_comparison_except_mask_bits':[39,71],
  'L4_groups_rejected_for_outside_mask_difference':len(failed),'accepted_reuse_roots':len(accepted),
  'discardable_newclone_L4_rows':savings,'actual_rows_with_first_count_difference_in_all_compared_groups':changed,
  'original_compared_L4_rawflag_counts':dict(flags),'complete_comparison_group_receipts_SHA256':rolling.hexdigest(),
  'source_group_pairwise_disjoint':pairwise,'rejection_root_classifications':dict(rejected),
  'revised_arithmetic':plan,'all_current_v3_L3_address_tree_paths_structurally_retained_conditionally':True,
  'retention_argument':'Each exclusive live new L3root group maps to one identical-order fullbit oldstock group except desired first/count. Desired childlinks and all L5/L6 retainedbaseline data remain. V5 forward noanomaly closure excludes lower→L4 edges. Stock lower IDs remain, parent pointer bytes may change.',
  'actual_read_receipts':BUDGET.receipt(),'sampled_current_mm_RAM':RAM,'RAM_sampled_limit_KiB':RSS_LIMIT,
  'source_stats_before':before,'source_stats_after':{k:stat(ROOT/p['path']) for k,p in PINS.items()},
  'same_file_external_cache_or_highflag_ABI_resolved':False,'full_original_lowerIDs_verbatim_parentbytes_preserved':False,
  'limitations':['Pointer-field-only DATA feasibility and capacity arithmetic; no compact IMG or actual in-place edit emitted.',
    'Live L3 range exclusivity excludes known structural aliases; external file/cache/query refs and unknown highflag semantics remain held.',
    'All active source leaf bits/order remain in desired original v3 childtrees by structural relation; no complete native lookup/UI/render/route/physical acceptance.',
    'Future fullcompactor must preserve all stock IDprefixes, stable suffixrank/pointers and all nonrange bits; this plan does not implement it.'],
  'falseflags':{'IMG_constructed':False,'stock_inplace_write':False,'nativeCPU':False,'guest':False,'device':False,'audio':False,
     'UI':False,'route':False,'renderfix':False,'install':False,'App':False,'directPhone':False,'music':False,'fullgoal':False}})
 JOURNAL['program_completed']=True
 print(json.dumps({'all_assigned_actual_DATA_checks_completed':True,'accepted_reuse_roots':len(accepted),'discardable_newclone_L4_rows':savings,
  'rows_compared':compared,'rejected_outside_mask_groups':len(failed),'projected_4K_IMG_bytes':plan['projected_4K_IMG_bytes'],
  'capacity_margin':plan['capacity_margin'],'fits_arithmetic':plan['fits_original_4K_arithmetic'],'actual_IMG_bytes':BUDGET.bytes,
  'max_sampled_current_mm_KiB':max(r['guarded_current_mm_KiB'] for r in RAM),'IMG_or_device_written':False}),flush=True)
 return True

BUDGET=Budget()
if __name__=='__main__':
 try:
  completed=main()
  if not completed:sys.exit(2)
 except BaseException as e:
  save('actual-failure.json',{'type':type(e).__name__,'error':str(e),'traceback':traceback.format_exc(),
    'phase':JOURNAL['phase'],'program_completed':JOURNAL['program_completed'],'actual_reads':BUDGET.receipt(),
     'normal_input_pins':NORMAL_PINS,'source_stats_before':SOURCE_BEFORE,'RAM_observations':RAM,'no_guard_relaxation_or_fake_success':True})
  raise
 finally:
  closure=[]
  for image in IMAGES:
   image.f.close();p=ROOT/PINS[image.name]['path'];closure.append({'source':image.name,'path':str(p.relative_to(ROOT)),
       'readonly_handle_closed':image.f.closed,'stat_before_open':SOURCE_BEFORE.get(image.name),
       'stat_at_final_close':stat(p),'stat_unchanged':stat(p)==SOURCE_BEFORE.get(image.name)})
  save('actual-handle-read-closure.json',{'handles':closure,'all_source_handles_closed':all(r['readonly_handle_closed'] for r in closure),
    'actual_IMG_read_receipts':BUDGET.receipt(),'RAM_observations':RAM,'new_IMG_or_patchfile_written':False})
