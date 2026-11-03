#!/usr/bin/env python3
import sys,struct,json,hashlib,datetime
from pathlib import Path
ROOT=Path('/root/garmin');sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED,BASE as LOAD_BASE
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
BASE=Path(__file__).resolve().parent
im=NativeImage();cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
targets={0x440dc4c,0x440dc02,0x440dc3a,0x440dae8,0x44146e8};found=[];literalrefs=[]
for sect in im.copies:
 if sect['runtime_start'] in [0xf00000,0xffff0000]:continue
 raw=im.read(sect['load_start'],sect['size']);start=sect['runtime_start']
 for i in range(0,len(raw)-3,2):
  a=raw[i]|raw[i+1]<<8
  if a&0xf800!=0xf000:continue
  b=raw[i+2]|raw[i+3]<<8
  if b&0xf800!=0xf800:continue
  off=((a&0x7ff)<<12)|((b&0x7ff)<<1)
  if off&1<<22:off-=1<<23
  t=start+i+4+off
  if t not in targets:continue
  at=start+i;ctxstart=max(0,i-32);ctx=raw[ctxstart:i+20]
  found.append({'call_pc':hex(at),'load_address':hex(sect['load_start']+i),'target':hex(t),'conditional_section':sect['conditional'],'context':[{'pc':hex(x.address),'bytes':x.bytes.hex(),'op':x.mnemonic+' '+x.op_str} for x in cs.disasm(ctx,start+ctxstart)]})
for target in targets:
 needle=struct.pack('<I',target|1);off=0
 while True:
  pos=im.data.find(needle,off)
  if pos<0:break
  off=pos+1;la=LOAD_BASE+pos
  if la&3:continue
  try:rt=im.load_to_runtime(la,4)
  except ValueError:continue
  literalrefs.append({'target':hex(target|1),'load_ref':hex(la),'runtime_ref':hex(rt)})
proof={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stock_MAIN_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'raw_Thumb_direct_call_candidates':found,'aligned_pointer_literals':literalrefs,'selection_conditions_not_yet_verified':True,'actual_live_TWN_manager_selected':False,'actual_UTF8_MDR_street_query':False,'device_IO':False}
(BASE/'prefecture-call-candidates-v1.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'calls':[(x['call_pc'],x['target']) for x in found],'literalrefs':literalrefs}))
