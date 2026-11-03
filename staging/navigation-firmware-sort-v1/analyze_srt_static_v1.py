#!/usr/bin/env python3
"""Bounded static SRT inventory, real copy mappings and direct call candidates."""
import sys,struct,hashlib,json,datetime
from pathlib import Path
ROOT=Path('/root/garmin');sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
BASE=Path(__file__).resolve().parent

def main():
 im=NativeImage();cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB);cs.detail=False
 functions={'header_parser':(0x23ce92,0x23d1b4),'unicode_page':(0x1ac008,0x1ac10c),'weight_step':(0x1ac3dc,0x1ac77e),'primary_comparator':(0x1ac788,0x1ac906),'numeric_reader':(0x1abd44,0x1abe1a),'utf_decoder':(0x1ac10c,0x1ac1a0),'file_read':(0x1abc44,0x1abca2)}
 slices={name:{'start':hex(a),'end':hex(b),'sha256':hashlib.sha256(im.read(a,b-a)).hexdigest(),'instructions':[{'pc':hex(x.address),'mnemonic':x.mnemonic,'op_str':x.op_str,'bytes':x.bytes.hex()} for x in cs.disasm(im.read(a,b-a),a)]} for name,(a,b) in functions.items()}
 headers=[]
 for b in [0x878b1c,0x878f60]:
  hl=struct.unpack('<H',im.read(b,2))[0];h2=im.word(b+23);desc,descs,h3,h3s=struct.unpack('<4I',im.read(b+h2,16));h=im.read(b+h3,92);id1,id2,cp=struct.unpack_from('<3H',h,2);flags=struct.unpack_from('<I',h,8)[0]
  headers.append({'blob_address':hex(b),'main_load_same_as_runtime':True,'real_header_bytes':hl,'description':im.read(b+desc,descs).split(b'\0')[0].decode(),'header3_relative_offset':h3,'header3_length':struct.unpack_from('<H',h,0)[0],'sort_id1':id1,'sort_id2':id2,'codepage':cp,'raw_flags':hex(flags),'maxpage':struct.unpack_from('<I',h,56)[0],'blob_bytes':h3+h3s,'blob_sha256':hashlib.sha256(im.read(b,h3+h3s)).hexdigest()})
 targets={0x23ce92,0x1ac3dc,0x1ac788,0x1ac906};found=[];scanranges=[]
 for sect in im.copies:
  if sect['runtime_start'] in [0xf00000,0xffff0000]:continue
  raw=im.read(sect['load_start'],sect['size']);start=sect['runtime_start'];scanranges.append({'runtime_start':hex(start),'bytes':len(raw),'load_start':hex(sect['load_start']),'conditional':sect['conditional']})
  for i in range(0,len(raw)-3,2):
   first=raw[i]|raw[i+1]<<8
   if first&0xf800!=0xf000:continue
   second=raw[i+2]|raw[i+3]<<8
   if second&0xf800!=0xf800:continue
   offset=((first&0x7ff)<<12)|((second&0x7ff)<<1)
   if offset&(1<<22):offset-=1<<23
   target=start+i+4+offset
   if target not in targets:continue
   caller=start+i;la=sect['load_start']+i
   ins=list(cs.disasm(raw[max(0,i-20):i+24],caller-min(i,20)))
   found.append({'candidate_direct_call_pc':hex(caller),'load_address':hex(la),'target':hex(target),'context':[{'pc':hex(x.address),'mnemonic':x.mnemonic,'op_str':x.op_str,'bytes':x.bytes.hex()} for x in ins],'raw_branch_match_not_proof_query_caller':True})
 result={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stock_main_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'embedded_SRT_headers':headers,'stock_unicode_descriptor_address':'0x878ef4','stock_unicode_descriptor_flags':hex(im.word(0x878ef4+16)),'native_ranges':{'unified':['0x4e00','0x9fbb'],'extension_A':['0x3400','0x4dbf'],'extension_B':['0x20000','0x2a6d6']},'ranges_inclusive':True,'cjk_table_bypassed_before_descriptor_access':'0x1ac04e -> 0x1ac074','implicit_native_units':['base+(cp>>15)','0x8000+(cp&0x7fff)'],'implicit_unified_base':'0xfb40','implicit_extension_base':'0xfb80','native_stored_widths_if_flag14_set':[16,10,6,16,16],'startup_backed_raw_thumb_call_scan_ranges':scanranges,'candidate_direct_calls':found,'function_slices':slices,'actual_query_keyboard_MDR_chain_found':False,'device_IO':False,'firmware_modified':False,'limits':'Static instruction listing may decode inline literals as instructions. Raw Thumb call candidates need context validation, and no actual UI query caller chain has been proved. Native file-kind2 parser/weights were separately executed in finite probes.'}
 (BASE/'srt-static-proof-v1.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'embedded_headers':headers,'direct_call_candidates':[(x['candidate_direct_call_pc'],x['target']) for x in found]},ensure_ascii=False))
if __name__=='__main__':main()
