#!/usr/bin/env python3
"""Ordinary map DATA only: full L4 cache / live L5 aliases / bounded 126-bit group equivalence."""
import sys
sys.dont_write_bytecode=True
import ast,builtins,dis,gzip,hashlib,json,struct,traceback
from array import array
from collections import Counter
from pathlib import Path
from types import CodeType,FunctionType
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
V5=ROOT/'staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5'
L4PLAN=ROOT/'staging/navigation-v3-exclusive-stock-L4-reuse-feasibility-v1'
IMG_LIMIT=160000000;RSS_LIMIT=384*1024;OUTPUT_LIMIT=4*1024*1024
STOCK4=2133948;STOCK5=2341096;MASK3=((1<<35)-1)<<20;MASK4=((1<<32)-1)<<39
MASK5=((1<<30)-1)<<39;ROW5MASK=(1<<126)-1
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
NORMAL=[];RAM=[];IMAGES=[];BEFORE={};JOURNAL={'phase':'preparation','completed':False};ARTIFACTS={}
def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(n,x):
 b=(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n').encode()
 uncompressed=len(b)
 if n.endswith('.gz'):b=gzip.compress(b,mtime=0)
 need(len(b)<=2*1024*1024,'Small output artifact <=2MiB')
 used=sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file() and p!=OUT/n)
 need(used+len(b)<=OUTPUT_LIMIT,'Total new small output <=4MiB before write')
 (OUT/n).write_bytes(b);ARTIFACTS[n]={'bytes':len(b),'uncompressed_JSON_bytes':uncompressed,'SHA256':sha(b)}
def rss(phase):
 vals={}
 with open('/proc/self/status') as f:
  for l in f:
   k,_,v=l.partition(':')
   if k in ['VmRSS','VmHWM','VmSize','VmPeak']:
    n,unit=v.split();need(unit=='kB','Actual proc unit');vals[k+'_KiB']=int(n)
 need('VmRSS_KiB' in vals and 'VmHWM_KiB' in vals,'Current-mm observation available')
 guarded=max(vals['VmRSS_KiB'],vals['VmHWM_KiB']);RAM.append({'phase':phase,**vals,'guarded_current_mm_KiB':guarded})
 JOURNAL['phase']=phase;need(guarded<=RSS_LIMIT,'384MiB sampled current-mm limit');return guarded
def pin(p,digest,kind='json'):
 before=stat(p);need(before[2]<=262144,'Only small normal input <=256KiB')
 b=p.read_bytes();need(stat(p)==before and sha(b)==digest,'Small input SHA/stat pin '+str(p))
 NORMAL.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':digest,'stat_before':before,'stat_after':stat(p),'mode':oct(p.stat().st_mode&0o777)})
 if kind=='json':return json.loads(b)
 if kind=='gzipjson':return json.loads(gzip.decompress(b))
 return b
class ReadBudget:
 def __init__(self):self.bytes=0;self.ops=0;self.h=hashlib.sha256();self.first=[];self.last=[];self.sources=Counter();self.purposes=Counter()
 def read(self,image,at,n,purpose):
  need(0<=at<=at+n<=image.size and self.bytes+n<=IMG_LIMIT,'Actual combined160000000-byte source cap')
  image.f.seek(at);b=image.f.read(n);need(len(b)==n,'Complete actual physical read')
  row={'source':image.name,'at':at,'bytes':n,'SHA256':sha(b),'purpose':purpose}
  self.h.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
  self.bytes+=n;self.ops+=1;self.sources[image.name]+=n;self.purposes[purpose.split(';')[0]]+=n
  if len(self.first)<8:self.first.append(row)
  self.last=(self.last+[row])[-8:];return b
 def receipt(self):
  return {'actual_IMG_bytes':self.bytes,'actual_IMG_read_ops':self.ops,'cap':IMG_LIMIT,'by_source':dict(self.sources),
   'by_purpose':dict(self.purposes),'complete_read_receipts_SHA256':self.h.hexdigest(),'first_reads':self.first,'last_reads':self.last,
   'whole_IMG_or_MDR_hash_recomputed':False,'full_L4_caches_written_to_disk':False}
BUDGET=ReadBudget()
def check_mapper_globals(env,cls):
 required=set();objects=[]
 def visit(c,label):
  objects.append(label)
  for op in dis.get_instructions(c):
   if op.opname=='LOAD_GLOBAL':required.add(op.argval)
  for i,n in enumerate(c.co_consts):
   if isinstance(n,CodeType):visit(n,label+':nested'+str(i))
 for k,v in cls.__dict__.items():
  if isinstance(v,FunctionType):visit(v.__code__,k)
 missing=sorted(k for k in required if k not in env and not hasattr(builtins,k))
 result={'required_globals':sorted(required),'code_objects':objects,'unresolved':missing,'actual_IMG_bytes_at_check':BUDGET.bytes}
 save('mapper-global-preflight.json',result);need(not missing and BUDGET.bytes==0,'All mapper globals resolve before any IMG read');return result
def tables_and_l3(image,p):
 h=image.logical('00004171.MDR',0,772,'actual MDR header')
 need(struct.unpack_from('<H',h)[0]==772 and h[2:12]==b'GARMIN MDR','Actual MDR marker')
 at,n,item,flags=struct.unpack_from('<4I',h,600)
 need((n,item,flags)==(120,20,1) and at+120==image.components['00004171.MDR']['size'],'Actual DIR endpoint')
 rawdir=image.logical('00004171.MDR',at,120,'actual full DIR');ts=[]
 for i,profile in enumerate(PROFILES):
  a,b,stride,w,x=struct.unpack_from('<5I',rawdir,i*20)
  widths=[w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63,x>>11&63,x>>17&63];refs=[w>>30&1,w>>31&1]
  count=b*8//stride
  need((stride,widths,refs)==profile and count==p['counts'][i] and b==(count*stride+7)//8,'Exact actual profile/widths/counts')
  ts.append({'level':i+1,'start':a,'bytes':b,'stride':stride,'count':count,'widths':widths,'refs':refs})
 cursor=4195100
 for level in [6,5,4,3,2,1]:
  t=ts[level-1];need(t['start']==cursor,'Exact actual tight suffix layout');cursor+=t['bytes']
 need(cursor==at,'Actual table end matches DIR')
 l3=image.logical('00004171.MDR',ts[2]['start'],ts[2]['bytes'],'complete L3 cache')
 need(len(l3)==670180,'47870*112-bit L3 cache')
 return ts,l3,{'header_SHA256':sha(h),'DIR_SHA256':sha(rawdir),'DIR_hex':rawdir.hex(),'L3_SHA256':sha(l3),
  'container_metadata_bytes':image.directory_end,'components':{k:v['size'] for k,v in image.components.items()}}
def root_fields(raw):
 first=array('I',[0])*47871;count=array('H',[0])*47871;flag=array('H',[0])*47871;flags=Counter()
 for ID,(lo,_,__) in enumerate(struct.iter_unpack('<QIH',raw),1):
  need(lo&1==1,'Pinned L3 mapordinal1');first[ID]=(lo>>20)&0x7fffff;count[ID]=(lo>>43)&4095;flag[ID]=(lo>>55)&511;flags[flag[ID]]+=1
 return (first,count,flag),dict(flags)
def add_range(diff,total,first,count,weight,description):
 if first==count==0:return False
 need(1<=first<=first+count-1<=total and count>0,description+' exact actual bounds')
 diff[first]+=weight;diff[first+count]-=weight;return True
def finish_occupancy(tag,diff,total,range_count):
 occupied=bytearray(total+1);running=0;distribution=Counter();maximum=0
 for ID in range(1,total+1):
  running+=diff[ID];need(running>=0,'Nonnegative incoming degree')
  value=min(2,running);occupied[ID]=value;distribution[value]+=1;maximum=max(maximum,running)
  if ID%524288==0:rss(tag+' saturation '+str(ID))
 need(running+diff[total+1]==0,'All range ends balanced')
 return occupied,{'all_actual_ranges_added':range_count,'saturated_slot_counts':dict(distribution),'maximum_weighted_degree':maximum,
   'bytes':len(occupied),'SHA256':sha(occupied),'saturation':'0=no incoming,1=exclusive,2=shared; reachable-L4 alias weights saturated at2'}
def live4_occupancy(tag,fields,total):
 diff=array('i',[0])*(total+2);first,count,flag=fields;n=0
 for ID in range(1,47871):
  if flag[ID]&7==4:n+=add_range(diff,total,first[ID],count[ID],1,'All L3target4')
 result=finish_occupancy(tag+' L4live',diff,total,n);del diff;rss(tag+' L4live complete');return result
def l5_incoming(tag,fields,raw4,live4,total5):
 diff=array('i',[0])*(total5+2);n=direct=parents=weighted=0;flags=Counter();rootflags=Counter();first,count,flag=fields
 for ID in range(1,47871):
  if flag[ID]&7==5:
   rootflags[flag[ID]]+=1
   if add_range(diff,total5,first[ID],count[ID],1,'Every directL3 target5'):
    direct+=1;n+=1
 for ID,degree in enumerate(live4):
  if ID==0 or degree==0:continue
  lo,hi=struct.unpack_from('<QQ',raw4,(ID-1)*16);f=(lo>>39)&0x3fffff;c=((lo>>61)|((hi&127)<<3))&1023;rawflag=(hi>>7)&511
  flags[rawflag]+=1
  # Closed V5 no-anomaly forward graph supplies childlevel contract; retain all highflag bits.
  need(rawflag&7 in [0,5,6],'Unexpected reachableL4 backwards/unclassified childlevel; do not infer aliases')
  if rawflag&7==5 and add_range(diff,total5,f,c,degree,'Every reachableL4 target5'):
   parents+=1;weighted+=degree;n+=1
  if ID%262144==0:rss(tag+' live L4→L5 '+str(ID))
 occupied,facts=finish_occupancy(tag+' L5incoming',diff,total5,n);del diff;rss(tag+' L5incoming complete')
 facts.update({'all_L3_examined':47870,'directL3_target5_ranges':direct,'directL3_target5_rawflags':dict(rootflags),
   'reachable_L4_target5_parent_nodes':parents,'reachable_L4_weighted_L5_edges':weighted,'all_reachable_L4_rawflags':dict(flags),
   'all_reachable_L4_parent_aliases_counted_conservatively':True,'external_or_extra_highflag_refs_resolved':False})
 return occupied,facts
def disjoint(rows,key):
 ranges=sorted((r[key],r[key]+r['count']-1,r['parent_context']) for r in rows)
 need(all(a[1]<b[0] for a,b in zip(ranges,ranges[1:])),'Selected '+key+' ranges ambiguous/shared; do not coalesce')
 return {'ranges':len(ranges),'all_pairwise_disjoint':True}
def arithmetic(containers,saved):
 old5=3074293;new5=old5-saved;need(new5>=STOCK5,'Retain all stockL5 IDs')
 oldbytes=(old5*126+7)//8;newbytes=(new5*126+7)//8
 mdr=131330140-oldbytes+newbytes;sizes=dict(containers);sizes['00004171.MDR']=mdr
 blocks={k:(v+4095)//4096 for k,v in sizes.items()};parts={k:(v+239)//240 for k,v in blocks.items()}
 rows=1+sum(parts.values());metadata=max(73728,((4096+rows*512+4095)//4096)*4096)
 image=metadata+sum(blocks.values())*4096
 return {'combined_L4_savings':108235,'new_L5_savings':saved,'retained_counts':{'4':3781594,'5':new5,'6':2062771},
  'retained_L5_bits':new5*126,'retained_L5_bytes':newbytes,'old_L5_retained_bytes':oldbytes,'net_logical_MDR_saved_bytes':oldbytes-newbytes,
  'MDR_bytes':mdr,'full_six_component_sizes':sizes,'4K_blocks':blocks,'component_FAT_parts':parts,'root_plus_component_FAT_rows':rows,
  'metadata_bytes':metadata,'projected_IMG_bytes':image,'original_capacity':134217728,'capacity_margin':134217728-image,
  'fits_original_4K_arithmetic':image<=134217728,'same_profile_23_112_128_126_68':True,
  'incoming_width_bounds':{'L4_23bit':3781594<1<<23,'L5_22bit':new5<1<<22,'L6_21bit':2062771<1<<21},
  'metadata_one_root_valid':metadata//4096<=240,'IMG_constructed':False}
def row126(raw,shift,ordinal):
 bit=shift+ordinal*126;at=bit//8;inner=bit%8
 return (int.from_bytes(raw[at:at+(inner+126+7)//8],'little')>>inner)&ROW5MASK
def main():
 need(not (OUT/'proof.json').exists() and not (OUT/'actual-failure.json').exists(),'Fresh unique actual run')
 rss('initial current-mm')
 v5=pin(V5/'proof.json','ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82')
 summary=pin(ROOT/v5['artifacts']['summary']['path'],v5['artifacts']['summary']['sha256']);baseline=summary['stock_prefix_plus_active']
 need(v5['all_assigned_data_feasibility_checks_completed'] and baseline['retained_total_lower_counts']=={'4':3889829,'5':3074293,'6':2062771}
  and not baseline['invalid_or_unclassified_child_encoding_counts'] and not baseline['unknown_raw_flag_counts']
  and not baseline['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention'],'Closed complete no-anomaly V5 baseline')
 seal4=pin(L4PLAN/'sealed-files.json','4de5e8108e4760f34451c75654eac76d81184f2f1aaab87d71855c2e6c9d1246')
 sum4=pin(L4PLAN/'scope-summary.json','31ff1e560798e9c772cb5cdb01682aa049ba161b80c82d071e0715751e116ec9')
 plan4=pin(L4PLAN/'reuse-root-plan.json.gz','d8ae42d789ed5449657f5065ee703c7b731d02dd0f078ec88684407d90120a09','gzipjson')
 need(sum4['discardable_newclone_rows']==108235 and sum4['arithmetic']['MDR_bytes']==131330140 and len(plan4['roots'])==1251,'Closed L4 reuse baseline')
 for name,digest in [('scope-summary.json','31ff1e560798e9c772cb5cdb01682aa049ba161b80c82d071e0715751e116ec9'),
                     ('reuse-root-plan.json.gz','d8ae42d789ed5449657f5065ee703c7b731d02dd0f078ec88684407d90120a09')]:
  r=next(r for r in seal4['files'] if r['path']==str((L4PLAN/name).relative_to(ROOT)));need(r['sha256']==digest and stat(L4PLAN/name)==r['stat_at_seal'],'Closed L4 small artifact actual SHA/stat')
 prior4={r['root_ID']:r for r in plan4['roots']};del plan4,seal4
 mapper=pin(ROOT/'staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py',
  'a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095','bytes')
 tree=ast.parse(mapper.decode());image_ast=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Image')
 names_ast=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NAMES' for t in n.targets))
 asthash=sha(ast.dump(image_ast,include_attributes=False).encode());need(asthash==v5['mapper_AST_sha256'],'Frozen ordinary mapper Image AST')
 env={'need':need,'struct':struct};exec(compile(ast.Module(body=[names_ast,image_ast],type_ignores=[]),'pinned_ordinary_Image_AST','exec'),env)
 mappercheck=check_mapper_globals(env,env['Image']);del tree,image_ast,names_ast,mapper
 facts=pin(ROOT/'staging/navigation-native-L3-width-policy-static-v1/candidate-layout-and-CPU-facts.json',
  '3305e1aa1019c1920fee5e8993936d21aa0fe0ebb79d745a624ae900978868e9')
 tables={};l3={};raw4={};imagefacts={};fields={};rootflags={};live4={};l4occfacts={};incoming5={};l5occfacts={}
 for tag,p in PINS.items():
  s=pin(ROOT/p['seal'],p['seal_SHA256']);r=next(r for r in s['files'] if r['path']==p['path']);BEFORE[tag]=stat(ROOT/p['path'])
  need(BEFORE[tag][:4]==r['stat_at_seal'][:4] and r['sha256']==p['SHA256'],'Inherited whole IMG SHA/dev/inode/size/mtime pin')
  f=(ROOT/p['path']).open('rb')
  try:image=env['Image'](tag,f,p,BUDGET)
  except BaseException:f.close();JOURNAL['constructor_failure_handle_closed']=f.closed;raise
  IMAGES.append(image);tables[tag],l3[tag],imagefacts[tag]=tables_and_l3(image,p);fields[tag],rootflags[tag]=root_fields(l3[tag])
  profile=facts['profiles']['country_v2' if tag=='v2' else 'lane_v3'];need(imagefacts[tag]['DIR_hex']==profile['directory_source']['hex'],'Actual DIR matches pinned profile')
  rss(tag+' before fullL4 RAM-only cache')
  raw4[tag]=image.logical('00004171.MDR',tables[tag][3]['start'],tables[tag][3]['bytes'],'full L4 cache;RAM only')
  need(len(raw4[tag])==p['counts'][3]*16,'Complete exact 128-bit L4 cache bytes')
  imagefacts[tag]['L4_SHA256']=sha(raw4[tag]);imagefacts[tag]['L4_bytes']=len(raw4[tag]);rss(tag+' after fullL4 RAM-only cache')
  live4[tag],l4occfacts[tag]=live4_occupancy(tag,fields[tag],tables[tag][3]['count'])
  incoming5[tag],l5occfacts[tag]=l5_incoming(tag,fields[tag],raw4[tag],live4[tag],tables[tag][4]['count'])
 need(BUDGET.bytes==140327712,'Exact fresh metadata/L3 + two full L4 cache bytes')
 need(imagefacts['v2']['L3_SHA256']=='2cd4c24f263cb6df6c863d1113992f3959090c1d99ebf26159288109b1d9ad21','Original v2 L3 hash')
 f2,n2,flags2=fields['v2'];f3,n3,flags3=fields['v3'];rejected=Counter();candidates=[];rootmatch=Counter();combinedparent=Counter()
 def consider(parent,first,count,newfirst,newcount):
  if count!=newcount or count==0:rejected['parent_L5_group_count_different_or_empty']+=1;return
  if not (1<=first<=first+count-1<=STOCK5):rejected['old_L5_group_not_entire_stockprefix']+=1;return
  if newfirst<=STOCK5:rejected['new_L5_group_not_poststock_clone']+=1;return
  need(newfirst+count-1<=tables['v3'][4]['count'],'Actual prospective new L5 range bounds')
  if any(x!=1 for x in incoming5['v2'][first:first+count]):rejected['old_live_L5_group_not_exclusive']+=1;return
  if any(x!=0 for x in incoming5['v3'][first:first+count]):rejected['old_stock_L5_group_still_has_live_v3_incoming']+=1;return
  if any(x!=1 for x in incoming5['v3'][newfirst:newfirst+count]):rejected['new_L5_clone_not_exclusive']+=1;return
  candidates.append(dict(parent,oldfirst=first,newfirst=newfirst,count=count));combinedparent[parent['kind']]+=1
 for ID in range(1,47871):
  a=int.from_bytes(l3['v2'][(ID-1)*14:ID*14],'little');b=int.from_bytes(l3['v3'][(ID-1)*14:ID*14],'little')
  target2,target3=flags2[ID]&7,flags3[ID]&7
  if target2!=target3 or (a^b)&~MASK3:
   rejected['root_path_rawbits_or_childlevel_mismatch']+=1;continue
  if target2==5:
   rootmatch['directL3_same_nonpointer_rawbits']+=1
   consider({'kind':'L3','parent_context':'L3:'+str(ID),'root_ID':ID,'parent_rawflag':flags2[ID],
     'old_parent112':a.to_bytes(14,'little').hex(),'new_parent112':b.to_bytes(14,'little').hex(),
     'combined_parent_ID_before_future_suffix_rank':ID},f2[ID],n2[ID],f3[ID],n3[ID])
  elif target2==4:
   if n2[ID]!=n3[ID] or not n2[ID]:rejected['root4_ordered_group_count_mismatch_or_empty']+=1;continue
   need(1<=f2[ID]<=f2[ID]+n2[ID]-1<=tables['v2'][3]['count'] and 1<=f3[ID]<=f3[ID]+n3[ID]-1<=tables['v3'][3]['count'],'Actual root4 ranges')
   bad=0;pairs=[]
   for ordinal in range(n2[ID]):
    oldID,newID=f2[ID]+ordinal,f3[ID]+ordinal
    lo,hi=struct.unpack_from('<QQ',raw4['v2'],(oldID-1)*16);old=lo|(hi<<64)
    nl,nh=struct.unpack_from('<QQ',raw4['v3'],(newID-1)*16);new=nl|(nh<<64)
    if (old^new)&~MASK4:bad+=1
    if (hi>>7)&7==5:pairs.append((ordinal,oldID,newID,old,new))
   if bad:rejected['root4_any_ordered_L4_outside_pointer_bits_diff']+=1;continue
   rootmatch['root4_entire_ordered_L4_group_matches_outside_pointer_bits']+=1
   if ID in prior4:
    r=prior4[ID];need((r['oldfirst'],r['newfirst'],r['count'])==(f2[ID],f3[ID],n2[ID]),'Closed L4 reuse context exact current caches')
   for ordinal,oldID,newID,old,new in pairs:
    retained=(prior4[ID]['oldfirst']+ordinal) if ID in prior4 else newID
    consider({'kind':'L4','parent_context':'L3:'+str(ID)+'/L4ordinal:'+str(ordinal),'root_ID':ID,'ordinal':ordinal,
      'old_parent_ID':oldID,'new_parent_ID':newID,'parent_rawflag':(old>>71)&511,
      'old_parent128':old.to_bytes(16,'little').hex(),'new_parent128':new.to_bytes(16,'little').hex(),
      'root_old112':a.to_bytes(14,'little').hex(),'root_new112':b.to_bytes(14,'little').hex(),
      'combined_parent_ID_before_future_suffix_rank':retained,'parent_uses_closed_L4_stock_reuse':ID in prior4},
      (old>>39)&0x3fffff,(old>>61)&1023,(new>>39)&0x3fffff,(new>>61)&1023)
  if ID%2048==0:rss('actual matching original parent paths '+str(ID))
 pairwisepre={'old':disjoint(candidates,'oldfirst'),'new':disjoint(candidates,'newfirst')}
 def group_geometry(tag,first,count):
  bit=tables[tag][4]['start']*8+(first-1)*126;at=bit//8;shift=bit%8;n=(shift+count*126+7)//8
  return at,shift,n
 extra=sum(group_geometry(tag,r[key],r['count'])[2] for r in candidates for tag,key in [('v2','oldfirst'),('v3','newfirst')])
 read_plan={'structural_L5_candidate_groups':len(candidates),'candidate_L5_rows':sum(r['count'] for r in candidates),
  'parent_kinds':dict(combinedparent),'actual_IMG_bytes_before_L5':BUDGET.bytes,'required_actual_L5_group_read_bytes':extra,
  'projected_actual_total_IMG_reads':BUDGET.bytes+extra,'cap':IMG_LIMIT,'all_global_126bit_shifts_included':True,
  'parent_matching_counts':dict(rootmatch),'rejection_counts':dict(rejected),'pairwise_ranges':pairwisepre}
 save('actual-L5-read-budget-preflight.json',read_plan);print(json.dumps({'phase':'L5 read-budget preflight',**read_plan}),flush=True)
 if BUDGET.bytes+extra>IMG_LIMIT:
  save('budget-gap.json',{'actual_target_L5_reads_not_attempted':True,'cap_not_raised':True,'next_root_decision_required':True,**read_plan});return False
 accepted=[];failed=[];samples=[];rows_compared=edits=0;flags=Counter();rolling=hashlib.sha256();shiftpairs=Counter()
 for number,r in enumerate(candidates):
  oa,os,on=group_geometry('v2',r['oldfirst'],r['count']);na,ns,nn=group_geometry('v3',r['newfirst'],r['count'])
  oldraw=IMAGES[0].logical('00004171.MDR',oa,on,'L5 old stock group;'+r['parent_context'])
  newraw=IMAGES[1].logical('00004171.MDR',na,nn,'L5 current clone group;'+r['parent_context'])
  bad=changes=0;firstbad=[];sample=[];oldsign=hashlib.sha256();newsign=hashlib.sha256();outside=hashlib.sha256()
  for ordinal in range(r['count']):
   old=row126(oldraw,os,ordinal);new=row126(newraw,ns,ordinal);delta=old^new;other=delta&~MASK5
   oldsign.update(old.to_bytes(16,'little'));newsign.update(new.to_bytes(16,'little'));outside.update((old&~MASK5).to_bytes(16,'little'))
   flags[(old>>69)&511]+=1
   if other:
    bad+=1
    if len(firstbad)<3:firstbad.append({'ordinal':ordinal,'old126hex':old.to_bytes(16,'little').hex(),'new126hex':new.to_bytes(16,'little').hex(),'outside_mask_delta':other.to_bytes(16,'little').hex()})
   if delta&MASK5:changes+=1
   if (ordinal<2 or delta&MASK5) and len(sample)<4:sample.append({'ordinal':ordinal,'old_ID':r['oldfirst']+ordinal,'new_ID':r['newfirst']+ordinal,
     'old126hex':old.to_bytes(16,'little').hex(),'new126hex':new.to_bytes(16,'little').hex(),'only_first_count_delta':not bool(other),
     'old_global_MDR_bit':tables['v2'][4]['start']*8+(r['oldfirst']+ordinal-1)*126,'new_global_MDR_bit':tables['v3'][4]['start']*8+(r['newfirst']+ordinal-1)*126})
  row=dict(r,old_physical_window={'MDR_offset':oa,'bytes':on,'start_shift':os,'significant_bits':r['count']*126,'SHA256':sha(oldraw)},
    new_physical_window={'MDR_offset':na,'bytes':nn,'start_shift':ns,'significant_bits':r['count']*126,'SHA256':sha(newraw)},
    old_significant_rows_126bit_zero_extended_SHA256=oldsign.hexdigest(),new_significant_rows_126bit_zero_extended_SHA256=newsign.hexdigest(),
    outside_mask_126bit_rows_SHA256=outside.hexdigest(),rows_with_first_count_delta=changes,rows_with_outside_mask_delta=bad)
  rows_compared+=r['count'];edits+=changes;shiftpairs[str(os)+','+str(ns)]+=1;rolling.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
  if bad:failed.append(dict(row,first_bad_rows=firstbad))
  else:accepted.append(row)
  if len(samples)<20:samples.append({'parent_context':r['parent_context'],'eligible':not bad,'old_window':row['old_physical_window'],'new_window':row['new_physical_window'],'rows':sample})
  if number%128==0:rss('actual full126bit L5 comparisons '+str(number))
 savings=sum(r['count'] for r in accepted);revised=arithmetic(imagefacts['v3']['components'],savings)
 need(arithmetic(imagefacts['v3']['components'],0)['projected_IMG_bytes']==135438336,'Independent complete4K/FAT baseline reproduces closed L4 result')
 low,high=0,3074293-STOCK5
 while low<high:
  mid=(low+high)//2
  if arithmetic(imagefacts['v3']['components'],mid)['fits_original_4K_arithmetic']:high=mid
  else:low=mid+1
 threshold={'exact_minimum_L5_savings':low,'one_less':arithmetic(imagefacts['v3']['components'],low-1),'minimum':arithmetic(imagefacts['v3']['components'],low)}
 need(BUDGET.bytes==read_plan['projected_actual_total_IMG_reads'],'Actual reads consume exact planned unaligned groups, no hidden table pass')
 for tag,p in PINS.items():need(stat(ROOT/p['path'])==BEFORE[tag],'Original IMG source stat still immutable')
 pairwise={'old':disjoint(accepted,'oldfirst'),'new':disjoint(accepted,'newfirst')}
 save('reuse-L5-group-plan.json.gz',{'schema':'exclusive-stock-L5-reuse-readonly-plan/v1','groups':accepted,'pairwise':pairwise,
  'parent_destination_note':'For L4 parents closed L4-reused roots write oldstock parent; others use currentv3 parent before later stable suffixrank. DirectL3 IDs unchanged.',
  'only_old_L5_bits_39_to_68_would_change':True,'old_L6_ranges_and_all_desired_current_v3_childtrees_retained':True,'actual_IMG_edits':False})
 save('actual-rejected-L5-groups.json.gz',{'groups':failed,'outside_mask_difference_rejects_whole_group':True})
 save('actual-raw126-row-samples.json',{'samples':samples,'allcase_rows_actually_compared':rows_compared,'126bit_rule':'global unaligned shifts respected; row hex is126 significant bits zero-extended to16 bytes, not concatenated padded rows'})
 save('capacity-arithmetic.json',{'combined_reuse':revised,'exact_threshold':threshold});rss('all assigned pureDATA checks complete')
 save('proof.json',{'schema':'actual-exclusive-stock-L5-reuse-feasibility/v1','all_assigned_pureDATA_checks_completed':True,
  'normal_input_pins':NORMAL,'mapper_AST_SHA256':asthash,'mapper_globals_before_IMG':mappercheck,
  'actual_source_metadata':imagefacts,'actual_all_six_table_profiles':tables,'actual_L3_rawflags':rootflags,
  'all_L3_to_L4_live_occupancy':l4occfacts,'all_live_L5_incoming_occupancy':l5occfacts,'strict_matching_parent_and_read_plan':read_plan,
  'actual_L5_rows_compared':rows_compared,'accepted_L5_groups':len(accepted),'rejected_L5_groups':len(failed),
  'discardable_current_clone_L5_rows':savings,'rows_with_pointer_delta_in_all_compared_groups':edits,'original_compared_L5_rawflags':dict(flags),
  'actual_126bit_mask':[39,69],'global_old_new_shift_pair_counts':dict(shiftpairs),'group_comparison_receipts_SHA256':rolling.hexdigest(),
  'accepted_pairwise_ranges':pairwise,'combined_capacity_arithmetic':revised,'exact_capacity_threshold':threshold,
  'L4_parent_destination_counts_in_accepted':dict(Counter('closed_L4_oldstock' if r.get('parent_uses_closed_L4_stock_reuse') else r['kind'] for r in accepted)),
  'structural_current_v3_address_tree_equivalence_conditional':True,
  'conditional_relation':'Known exclusive target5 parent paths redirect to existing stock L5 group with identical ordered significant bits outside desired childfirst/count. Old L5 numeric IDs stay; desired currentv3 L6 edges/full retained baseline remain. Apply existing L4 redirect when locating changed parent; future suffixrank/remap remains unimplemented.',
  'original_stock_prefix_byte_provenance_inherited_not_fresh_stock_read':True,'external_cache_extra_highflag_ref_absence_proved':False,
  'limitations':['Only ordinary compiled-data known-graph equivalence and arithmetic, not complete native lookup or renderer acceptance.',
   'All highflags preserved raw; no unknown extra flags/cache/external-reference absence claim.',
   'Future combined COW/reuse compactor must actually redirect parents, edit permitted old child fields, preserve complete stock IDprefixes and stable suffixrank. No IMG emitted.'],
  'actual_read_receipts':BUDGET.receipt(),'sampled_current_mm_RAM':RAM,'RAM_cap_KiB':RSS_LIMIT,
  'source_stats_before':BEFORE,'source_stats_after':{tag:stat(ROOT/p['path']) for tag,p in PINS.items()},'small_artifacts_before_proof':ARTIFACTS,
  'falseflags':{'IMG':False,'pointer_write':False,'nativeCPU':False,'guest':False,'MAIN':False,'device':False,'audio':False,
   'UI':False,'route':False,'renderfix':False,'install':False,'App':False,'directPhone':False,'SPEAKER':False,'STOP_DONE':False,'fullgoal':False}})
 JOURNAL['completed']=True
 print(json.dumps({'all_assigned_pureDATA_checks_completed':True,'accepted_L5_groups':len(accepted),'saved_L5_rows':savings,
  'L5_rows_compared':rows_compared,'rejected_groups':len(failed),'combined_projected_4K_IMG':revised['projected_IMG_bytes'],
  'capacity_margin':revised['capacity_margin'],'fits_arithmetic':revised['fits_original_4K_arithmetic'],'exact_minimum_L5_rows':low,
  'actual_IMG_bytes':BUDGET.bytes,'current_mm_max_KiB':max(r['guarded_current_mm_KiB'] for r in RAM),'IMG_or_device_written':False}),flush=True)
 return True
if __name__=='__main__':
 try:
  completed=main()
  if not completed:sys.exit(2)
 except BaseException as e:
  save('actual-failure.json',{'type':type(e).__name__,'error':str(e),'traceback':traceback.format_exc(),'phase':JOURNAL['phase'],
   'completed':JOURNAL['completed'],'actual_IMG_reads':BUDGET.receipt(),'normal_input_pins':NORMAL,'RAM':RAM,
   'source_stats_before':BEFORE,'guards_not_relaxed':True});raise
 finally:
  handles=[]
  for image in IMAGES:
   image.f.close();after=stat(ROOT/PINS[image.name]['path']);handles.append({'source':image.name,'handle_closed':image.f.closed,
    'before_open':BEFORE[image.name],'at_close':after,'stat_unchanged':after==BEFORE[image.name]})
  save('actual-handle-read-closure.json',{'handles':handles,'all_handles_closed':all(r['handle_closed'] for r in handles),
   'all_source_stats_unchanged':all(r['stat_unchanged'] for r in handles),'actual_IMG_reads':BUDGET.receipt(),'RAM':RAM,'new_IMG_written':False})
