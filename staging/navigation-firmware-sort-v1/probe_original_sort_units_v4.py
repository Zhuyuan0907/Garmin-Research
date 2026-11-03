#!/usr/bin/env python3
"""Finite original-instruction SRT parser and Unicode weight probes; no I/O/hooks."""
import datetime as dt, gzip, hashlib, json, struct, sys
from pathlib import Path
ROOT=Path('/root/garmin');sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'staging/navigation-search-encoding-v1'))
from analyze_native_sections import NativeImage, EXPECTED
from compare_fixture_components import extract
import unicorn
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import UC_CPU_ARM_1176,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_CPSR,UC_ARM_REG_PC
BASE=Path(__file__).resolve().parent
RET=0x09004000;RAM=0x09000000;STACK=0x09010000;DESC=RAM+0x100;ITER=RAM+0x300;RECORD=RAM+0x500;FLAG=RAM+0x600;STRING=0x09020000;SRT=0x09100000
CODE_PAGES=[0x1ab000,0x1ac000,0x1c8000,0x23c000,0x23d000,0x349000,0x35b000,0x373000,0x391000]

class Probe:
 def __init__(self,image,srt=None):
  self.u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);self.u.ctl_set_cpu_model(UC_CPU_ARM_1176)
  self.trace=[];self.ranges=[]
  for p in CODE_PAGES:
   self.u.mem_map(p,4096);raw=image.read(p,4096);self.u.mem_write(p,raw);self.u.mem_protect(p,4096,UC_PROT_READ|UC_PROT_EXEC)
   self.ranges.append({'address':hex(p),'bytes':4096,'sha256':hashlib.sha256(raw).hexdigest()})
  # Embedded UTF8 descriptor and tables, readonly exact stock bytes, for builtin controls.
  size=0x26000;self.u.mem_map(0x878000,size);self.u.mem_write(0x878000,image.read(0x878000,size));self.u.mem_protect(0x878000,size,UC_PROT_READ)
  self.u.mem_map(RAM,4096);self.u.mem_map(STACK,8192);self.u.mem_map(STRING,4096)
  self.u.mem_map(RET,4096);self.u.mem_write(RET,b'\x70\x47');self.u.mem_protect(RET,4096,UC_PROT_READ|UC_PROT_EXEC)
  if srt:
   n=(len(srt)+4095)&~4095;self.u.mem_map(SRT,n);self.u.mem_write(SRT,srt);self.u.mem_protect(SRT,n,UC_PROT_READ)
  self.u.hook_add(UC_HOOK_CODE,self.code)
 def code(self,u,address,size,_):
  self.trace.append({'pc':address,'bytes':bytes(u.mem_read(address,size)).hex(),'thumb':bool(u.reg_read(UC_ARM_REG_CPSR)&32)})
  if address==RET:u.emu_stop()
 def call(self,entry,args):
  start=len(self.trace)
  self.u.reg_write(UC_ARM_REG_CPSR,0x3f);self.u.reg_write(UC_ARM_REG_SP,STACK+0x1f00);self.u.reg_write(UC_ARM_REG_LR,RET|1)
  for r,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):self.u.reg_write(r,v)
  try:self.u.emu_start(entry|1,RET+2,timeout=1000000,count=20000)
  except Exception as e:
   receipt={'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'entry':hex(entry),'exception':repr(e),'pc':hex(self.u.reg_read(UC_ARM_REG_PC)),'last_instructions':self.trace[-32:],'device_io':False,'firmware_modified':False,'trace_instructions':len(self.trace)}
   (BASE/'probe-v4-failure-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
   raise
  tail=self.trace[start:];assert tail and tail[-1]['pc']==RET,(hex(entry),'did not return',tail[-1:])
  assert self.u.reg_read(UC_ARM_REG_SP)==STACK+0x1f00
  return self.u.reg_read(UC_ARM_REG_R0),tail
 def load(self,id1,id2):
  self.u.mem_write(DESC,struct.pack('<2I',SRT,2)+bytes(100));res,tr=self.call(0x23ce92,[DESC,id1,id2,0]);return res,tr
 def units(self,text,descriptor=DESC,strength=0):
  encoding='utf-16le' if descriptor==0x878ef4 else 'utf-8';terminator=b'\0\0' if encoding=='utf-16le' else b'\0'
  raw=text.encode(encoding)+terminator;self.u.mem_write(STRING,raw);self.u.mem_write(ITER,bytes(96))
  self.u.mem_write(ITER,struct.pack('<3I',descriptor,STRING,STRING));self.u.mem_write(ITER+12,bytes([strength]));self.u.mem_write(ITER+0x10,struct.pack('<I',STRING));self.u.mem_write(ITER+0x38,struct.pack('<I',STRING))
  records=[];weights=[];steps=0
  while bytes(self.u.mem_read(struct.unpack('<I',self.u.mem_read(ITER+0x10,4))[0],len(terminator)))!=terminator:
   ptr=struct.unpack('<I',self.u.mem_read(ITER+0x10,4))[0];res,tr=self.call(0x1ac3dc,[ITER,0,0,0]);assert res==0
   count=bytes(self.u.mem_read(ITER+0x15,1))[0];assert count<=5
   got=list(struct.unpack('<'+'I'*count,self.u.mem_read(ITER+0x18,4*count))) if count else []
   ptr_after=struct.unpack('<I',self.u.mem_read(ITER+0x10,4))[0];assert ptr_after>ptr
   records.append({'input_encoding':encoding,'input_bytes_hex':bytes(self.u.mem_read(ptr,ptr_after-ptr)).hex(),'units':got,'native_return':res,'instructions':len(tr),'cjk_special_branch_taken':any(x['pc']==0x1ac04e for x in tr),'page_reader_entered':any(x['pc']==0x1ac07a for x in tr)})
   weights+=got;steps+=1;assert steps<40
  return {'text':text,'input_encoding':encoding,'strength':strength,'primary_units':weights,'primary_big_endian_hex':b''.join(struct.pack('>H',v) for v in weights).hex() if strength==0 else None,'characters':records}


def main():
 image=NativeImage();fixture=ROOT/'staging/navigation-search-encoding-v1';blobs={}
 for name,folder in [('original_id4','fixture-default'),('materialized_id7052','fixture-patched-new-id')]:
  items=extract(fixture/folder/'gmapsupp.img');blobs[name]=next(v for k,v in items.items() if k.endswith('.SRT'))
 result={'started_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'stock_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'emulator':unicorn.__version__,'cpu_model':'ARM1176 (emulator setting, not physical CPU observation)','native_header_parser_entry':'0x23ce92','native_unicode_page_entry':'0x1ac008','native_weight_step_entry':'0x1ac3dc','real_hardware_or_query_caller':False,'policy_hooks':[],'device_io':False,'firmware_modified':False,'old_proofs_rerun':False,'parser_cases':[],'early_cjk_cases':[],'weight_cases':[]}
 traces={}
 for name,id1,id2,expected in [('original_id4',19,4,0),('materialized_id7052',19,7052,0),('materialized_id7052',19,7053,3),('materialized_id7052',18,7052,3),('materialized_id7052',19,4,0)]:
  p=Probe(image,blobs[name]);res,tr=p.load(id1,id2);assert res==expected,(name,id1,id2,res)
  desc=bytes(p.u.mem_read(DESC,108));case={'input':name,'input_srt_sha256':hashlib.sha256(blobs[name]).hexdigest(),'requested_id1':id1,'minimum_id2':id2,'native_return':res,'expected_return':expected,'instructions':len(tr),'descriptor_hex':desc.hex(),'codepage':struct.unpack_from('<H',desc,12)[0] if res==0 else None,'descriptor_flags':struct.unpack_from('<I',desc,16)[0] if res==0 else None}
  result['parser_cases'].append(case);traces['parser_'+str(len(result['parser_cases']))]=p.trace
 for c in '民權和路臺台中市':
  p=Probe(image);p.u.mem_write(RECORD,b'\xa5'*16);p.u.mem_write(FLAG,b'\xa5');res,tr=p.call(0x1ac008,[0xdead0000,RECORD,ord(c),FLAG]);flag=bytes(p.u.mem_read(FLAG,1))[0];assert res==0 and flag==1 and bytes(p.u.mem_read(RECORD,16))==b'\xa5'*16
  assert not any(x['pc'] in (0x1ac07a,0x1abc44,0x1c8782) for x in tr)
  result['early_cjk_cases'].append({'character':c,'codepoint':hex(ord(c)),'native_return':res,'flag':flag,'record_unchanged':True,'unmapped_descriptor_not_dereferenced':True,'instructions':len(tr)});traces['early_'+c]=p.trace
 for source in ['original_id4','materialized_id7052','stock_builtin_utf8']:
  p=Probe(image,blobs.get(source));desc=0x878ef4 if source=='stock_builtin_utf8' else DESC
  if source!='stock_builtin_utf8':res,tr=p.load(19,4 if source=='original_id4' else 7052);assert res==0
  for text in ['民權路','民和路','A民權路','B民和路','民權A路','民和B路','台中市','臺中市','中山路','A12','民權1路']:
   got=p.units(text,desc);got['source']=source;result['weight_cases'].append(got)
  traces['weights_'+source]=p.trace
 original={c['text']:c['primary_units'] for c in result['weight_cases'] if c['source']=='original_id4'}
 patched={c['text']:c['primary_units'] for c in result['weight_cases'] if c['source']=='materialized_id7052'}
 result['materialized_srt_does_not_change_tested_native_primary_units']=original==patched;assert original==patched
 result['input_srt_hashes']={n:hashlib.sha256(b).hexdigest() for n,b in blobs.items()};result['all_passed']=True;result['finished_utc']=dt.datetime.now(dt.timezone.utc).isoformat()
 result['code_pages']=p.ranges;result['limits']='Original function units with synthetic file-kind2 descriptor and caller iterator; actual IMG discovery/map choice, keyboard conversion, MDR fast indexes and UI search caller not executed. Header parser accepts the IDs in this memory-reader path, not proof the map will be chosen on hardware. CJK special path bypasses SRT pages regardless of populated candidate pages; no navigation root cause claimed.'
 (BASE/'original-sort-unit-proof-v4.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 with gzip.open(BASE/'original-sort-unit-trace-v4.json.gz','wt') as f:json.dump(traces,f,separators=(',',':'))
 print(json.dumps({'all_passed':True,'parser_cases':len(result['parser_cases']),'early_cjk_cases':len(result['early_cjk_cases']),'weight_cases':len(result['weight_cases']),'same_native_primary_units_with_candidate':original==patched,'device_search_verified':False},ensure_ascii=False))
if __name__=='__main__':main()
