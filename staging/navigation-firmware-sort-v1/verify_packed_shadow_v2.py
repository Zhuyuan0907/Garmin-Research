#!/usr/bin/env python3
"""Successor packed16/10/6 shadow Sort tests vs actual original unit/comparator functions."""
import hashlib,json,datetime,struct
from pathlib import Path
from probe_original_sort_units_v4 import Probe,NativeImage,ROOT,BASE,DESC,ITER,STRING,extract,EXPECTED

def read_java(path):
 keys={};cmp={};meta=None;after=None
 for line in path.read_text().splitlines():
  a=line.split('\t')
  if a[0]=='META':meta={'maxPrimary':int(a[1]),'maxExpSize':int(a[2]),'maxPage':int(a[3]),'tables_sha256':a[4]}
  elif a[0]=='KEY':keys[a[1]]=bytes.fromhex(a[2])
  elif a[0]=='CMP':cmp[(a[1],a[2],int(a[3]))]=int(a[4])
  elif a[0]=='TABLES_AFTER':after=a[1]
 assert meta and meta['tables_sha256']==after
 return keys,cmp,meta

def levels(key):
 pos=0;out=[];primary=[]
 while True:
  v=struct.unpack_from('>H',key,pos)[0];pos+=2
  if not v:break
  primary.append(v)
 out.append(primary)
 for _ in range(2):
  x=[]
  while key[pos]:x.append(key[pos]);pos+=1
  pos+=1;out.append(x)
 assert not any(key[pos:]);return out

def verify_packing(old,new):
 sys_path=str(ROOT/'staging/navigation-search-encoding-v1')
 import sys
 sys.path.insert(0,sys_path)
 from compare_fixture_components import weight,srt_header
 ro,so,_,_,_=srt_header(old);rn,sn,_,_,_=srt_header(new)
 ep_o,sz_o=struct.unpack_from('<II',old,so+28);ep_n,sz_n=struct.unpack_from('<II',new,sn+28);assert sz_o==sz_n
 defined=0;materialized=0;fail=[]
 for cp in range(1,65536):
  if 0xd800<=cp<=0xdfff:continue
  a=weight(old,cp);b=weight(new,cp);assert b is not None
  flags,pri,sec_byte,ter_byte=b;packed=sec_byte|(ter_byte<<8);decoded=(flags,pri,packed&1023,packed>>10)
  if a is not None:
   defined+=1
   if a!=decoded:fail.append(hex(cp))
  else:
   materialized+=1
   if decoded!=(0,(cp+10690)&65535,0,0):fail.append(hex(cp))
 expansions=sz_o//4
 for i in range(expansions):
  a=struct.unpack_from('<HBB',old,so+ep_o+4*i);pri,packed=struct.unpack_from('<HH',new,sn+ep_n+4*i);b=(pri,packed&1023,packed>>10)
  if a!=b:fail.append('expansion'+str(i))
 assert struct.unpack_from('<I',new,sn+8)[0]==struct.unpack_from('<I',old,so+8)[0]==0x6f02
 return {'all_records_preserved_numerically':not fail,'original_defined_BMP_records':defined,'missing_BMP_records_materialized':materialized,'original_expansion_records':expansions,'header_flags_unchanged':'0x6f02','mismatches':fail}

def main():
 old,oldcmp,oldmeta=read_java(BASE/'packed-fixture-original-v2.tsv');new,newcmp,newmeta=read_java(BASE/'packed-fixture-aligned-v2.tsv');assert oldmeta==newmeta
 image=NativeImage();srt=(BASE/'packed-fixture-aligned-v2.SRT').read_bytes();p=Probe(image,srt);res,tr=p.load(19,4);assert res==0;p.trace.clear()
 checks=[];names=(BASE/'packed-fixture-names-v2.txt').read_text().splitlines();allpass=True;units_matches=[]
 for name in names:
  if len(name)>50:continue
  lv=[];n=0
  for strength in range(3):
   got=p.units(name,strength=strength);lv.append(got['primary_units']);n+=len(p.trace);p.trace.clear()
  ok=levels(new[name])==lv;allpass&=ok
  units_matches.append({'name':name,'actual_original_native_levels':lv,'shadow_key_levels':levels(new[name]),'all_three_levels_equal':ok,'native_instructions':n,'non_Han_old_key_byte_equal':old[name]==new[name] if not any((0x3400<=ord(x)<=0x4dbf or 0x4e00<=ord(x)<=0x9fbb or 0x20000<=ord(x)<=0x2a6d6) for x in name) else None})
 for line in (BASE/'packed-fixture-pairs-v2.tsv').read_text().splitlines():
  a,b=line.split('\t');native=[]
  for strength in range(3):
   p.u.mem_write(STRING,a.encode()+b'\0');p.u.mem_write(STRING+512,b.encode()+b'\0');p.u.mem_write(ITER,struct.pack('<3I',DESC,STRING,STRING+512)+bytes(84));p.u.mem_write(ITER+12,bytes([strength]))
   res,tr=p.call(0x1ac788,[ITER,4096,0,0]);signed=res if res<0x80000000 else res-0x100000000;assert signed in (-1,0,1);native.append(signed);p.trace.clear()
  collapsed=[next((x for x in native[:strength+1] if x),0) for strength in range(3)]
  java=[newcmp[(a,b,strength)] for strength in range(3)];ok=java==collapsed;allpass&=ok
  checks.append({'left':a,'right':b,'actual_native_one_level_comparisons':native,'actual_native_combined_signs':collapsed,'shadow_collator_signs':java,'original_host_collator_signs':[oldcmp[(a,b,strength)] for strength in range(3)],'matches_primary_secondary_tertiary':ok})
 old_srt=(BASE/'shadow-fixture-original-v1.SRT').read_bytes();new_srt=srt;packing=verify_packing(old_srt,new_srt);allpass&=packing['all_records_preserved_numerically']
 long=[]
 for name in names:
  if len(name)<=50:continue
  lv=levels(new[name]);expected=[[0xfb40,0xec11],[0xfb80,0xb400],[0xfb84,0x8000]][['民','㐀','𠀀'].index(name[0])];ok=lv==[expected*1024,[32,32]*1024,[2,2]*1024];allpass&=ok;long.append({'character':name[0],'Unicode_codepoints':len(name),'key_bytes':len(new[name]),'expected_implicit_levels':ok,'native_long_string_executed':False})
 result={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'all_passed':bool(allpass),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'stock_main_sha256':EXPECTED,'original_native_functions':['0x23ce92','0x1ac3dc','0x1ac788'],'policy_hooks':[],'synthetic_caller_iterator_and_file_kind2':True,'meta_old':oldmeta,'meta_shadow':newmeta,'tables_and_maxPrimary_and_maxExp_unchanged':oldmeta==newmeta,'SRT_native_16_10_6_layout':True,'SRT_all_weight_records':packing,'SRT_bytes':len(new_srt),'unit_tests':units_matches,'comparator_tests':checks,'long_key_buffer_tests':long,'device_search_or_real_query_caller_verified':False,'full_map_built':False,'limitations':'Only verified defined non-Han controls and classified Han ranges. Non-Han absent-page behavior, map discovery/selection, keyboard conversion, native MDR/UI caller and physical address search remain unproven. Host key wire layout still mkgmap key format, though tested numerical positions and compare signs match original functions.'}
 (BASE/'packed-shadow-alignment-proof-v2.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_passed':bool(allpass),'unit_tests':len(units_matches),'comparator_pairs':len(checks),'failed_units':[x['name'] for x in units_matches if not x['all_three_levels_equal']],'failed_comparators':[x['left'] for x in checks if not x['matches_primary_secondary_tertiary']],'all_SRT_weight_records_preserved':packing['all_records_preserved_numerically']},ensure_ascii=False))
 if not allpass:raise SystemExit(1)
if __name__=='__main__':main()
