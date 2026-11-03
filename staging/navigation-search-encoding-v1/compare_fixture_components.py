#!/usr/bin/env python3
"""Inspect unlocked IMG components and the exact SRT page/weight layout."""
import mmap, struct, json, hashlib
from pathlib import Path
BASE=Path(__file__).resolve().parent

def extract(image):
 with Path(image).open('rb') as f:
  d=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
  bs=1<<(d[0x61]+d[0x62]);first=d[0x40]*512;end=struct.unpack_from('<I',d,first+12)[0];records={}
  for off in range(first,end,512):
   e=d[off:off+512]
   if e[0]!=1 or e[0x10]==3:continue
   k=e[1:9].decode().strip()+'.'+e[9:12].decode()
   if struct.unpack_from('<H',e,0x11)[0]==0:records[k]=[struct.unpack_from('<I',e,12)[0],[]]
   records[k][1].extend([b for b in struct.unpack_from('<240H',e,32) if b!=0xffff])
  return {k:b''.join(d[b*bs:(b+1)*bs] for b in blocks)[:size] for k,(size,blocks) in records.items()}

def srt_header(s):
 h2=struct.unpack_from('<I',s,23)[0];dp,ds,sp,ss=struct.unpack_from('<4I',s,h2)
 h=s[sp:sp+92];id1,id2,cp=struct.unpack_from('<3H',h,2);maxpage=struct.unpack_from('<I',h,56)[0]
 s7p,s7s=struct.unpack_from('<2I',h,60);s8p,s8s=struct.unpack_from('<2I',h,76)
 chartabp=struct.unpack_from('<I',h,12)[0]
 r={'bytes':len(s),'id1':id1,'id2':id2,'codepage':cp,'maxpage':maxpage,'subheader_offset':sp,'srt7_offset':s7p,'srt7_bytes':s7s,'srt8_offset':s8p,'srt8_bytes':s8s,'description':s[dp:dp+ds].rstrip(b'\0').decode()}
 return r,sp,s7p,s8p,chartabp

def weight(s,cp):
 r,sp,s7p,s8p,ct=srt_header(s)
 if cp>>8==0:
  if cp==0:return (0,0,0,0)
  q=sp+ct+(cp-1)*5
 else:
  po=struct.unpack_from('<i',s,sp+s7p+((cp>>8)-1)*4)[0]
  if po==-1:return None
  q=sp+s8p+po+(cp&255)*5
 flags,pri,sec,ter=struct.unpack_from('<BHBB',s,q);return (flags,pri,sec,ter)

def main():
 a=extract(BASE/'fixture-default/gmapsupp.img');b=extract(BASE/'fixture-patched-writer/gmapsupp.img')
 assert set(a)==set(b)
 comp={k:{'default_bytes':len(a[k]),'patched_bytes':len(b[k]),'byte_equal':a[k]==b[k],'default_sha256':hashlib.sha256(a[k]).hexdigest(),'patched_sha256':hashlib.sha256(b[k]).hexdigest()} for k in sorted(a)}
 srtkey=next(k for k in a if k.endswith('.SRT'));sa,sb=a[srtkey],b[srtkey]
 preserved=[];new=[];fail=[]
 for ch in range(1,65536):
  if 0xd800<=ch<0xe000:continue
  wa,wb=weight(sa,ch),weight(sb,ch)
  if wa is not None:
   preserved.append(ch)
   if wa!=wb:fail.append(ch)
  else:
   new.append(ch)
   if wb!=(0,(ch+10690)&65535,0,0):fail.append(ch)
 assert not fail
 chars={c:{'default_weight':weight(sa,ord(c)),'patched_weight':weight(sb,ord(c))} for c in '民權和路台中臺市'}
 r={'state':'passed','scope':'actual original r4924 tiny OSM compile vs shadow SRTFile writer; no hardware or Garmin search execution',
 'components':comp,'only_srt_changed':all(v['byte_equal'] for k,v in comp.items() if not k.endswith('.SRT')),'srt_default':srt_header(sa)[0],'srt_patched':srt_header(sb)[0],
 'defined_bmp_weights_preserved':len(preserved),'previous_missing_valid_bmp_weights_materialized':len(new),'tested_chars':chars,'main_cjk_no_uint16_wrap':0x9fff+10690<=65535,
 'garmin_missing_page_policy_known':False,'garmin_search_fixed':False,'existing_partial_page_missing_weights_not_modified':True,'supplementary_characters_not_supported':True,
 'caution':'Same IDs used only for byte-comparison fixture. Deployment must use one new consistent sort ID for LBL/MDR/SRT and avoid overlapping maps; physical address search remains mandatory.'}
 (BASE/'writer-only-fixture-proof.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({k:v for k,v in r.items() if k not in ('components','tested_chars')},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
