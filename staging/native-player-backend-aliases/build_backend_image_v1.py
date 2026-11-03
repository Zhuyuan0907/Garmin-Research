#!/usr/bin/env python3
"""Relink warm image with selected native route-entry barriers; no device package."""
import sys
sys.dont_write_bytecode=True
import json,hashlib,subprocess,importlib.util,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
oldbuild=ROOT/'staging/native-player-warm-retirement/build_warm_retirement_v1.py'
PREV=ROOT/'staging/native-player-route-entries'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 old=json.loads((ROOT/'staging/native-player-warm-retirement/build-v1.json').read_text())
 for p,h in old['source_sha256'].items():assert sha(ROOT/p)==h,p
 objects=[ROOT/p for p in old['reused_relocatable_objects']]
 assert len(objects)==28,len(objects)
 out=BASE/'build-v1';out.mkdir(exist_ok=False)
 ld=out/'warm-resident.ld';ld.write_text((PREV/'build-v2/warm-resident.ld').read_text().replace('KEEP(*(.text.rg_*))','KEEP(*(.text.rg_*)) KEEP(*(.text.ns_*)) KEEP(*(.text.pg_*)) KEEP(*(.text.al_*))').replace('__resident_code_end = .;', '__resident_regular_code_end = .;\n ASSERT(. <= 0x02fb4718,"Fixed clear veneer overlaps code")\n .ali_clear_fixed 0x02fb4718 : { KEEP(*(.ali_clear_fixed)) } :code\n __resident_code_end = .;'))
 derivation=json.loads((PREV/'route-entry-derivation-v2.json').read_text())
 prepared=json.loads((ROOT/'staging/native-player-provider-entries/provider-entry-source-v2.json').read_text())
 aliases=json.loads((BASE/'backend-alias-source-v1.json').read_text())
 deps={}
 for entries in(old['source_sha256'],derivation['source_sha256'],prepared['source_sha256'],aliases['source_sha256']):
  for path,h in entries.items():
   assert path not in deps or deps[path]==h,path
   deps[path]=h
 sources=[BASE/'backend_alias_entries_v1.c',BASE/'backend_original_entries_v1.S',ROOT/'staging/native-player-warm-retirement/mixer_source_warm_retirement_v1.c',ROOT/'staging/native-player-provider-entries/route_entries_provider_v1.c',PREV/'route_original_entries_v3.S',ROOT/'staging/native-player-sbc-retirement/native_stop_scoped_v1.c',BASE/'provider_entries_backend_v1.c',ROOT/'staging/native-player-provider-entries/provider_original_entries_v1.S']
 for p in [Path(__file__),PREV/'build-v2.json',ROOT/'staging/native-player-provider-entries/provider-entry-source-v2.json',BASE/'backend-alias-source-v1.json',ROOT/'staging/native-player-warm-retirement/build-v1.json',oldbuild,PREV/'route-entry-derivation-v2.json',ld,*sources,*objects]:deps[rel(p)]=sha(p)
 cmds=[]
 def run(args):
  r=subprocess.run(args,capture_output=True,text=True)
  dump(out/f'command-{len(cmds):02d}.json',dict(command=args,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));cmds.append(args)
  assert r.returncode==0,r.stderr[-3500:]
  return r.stdout
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-I'+str(ROOT/'staging/native-player-mixer-handoff'),'-I'+str(ROOT/'native/sbc-prototype')]
 new_objects=[]
 for p in sources:
  obj=out/(p.stem+'.o');run(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(obj)]);objects.append(obj);new_objects.append(obj)
 elf=out/'warm-player-EMULATION-ONLY.elf';flat=out/'warm-player-EMULATION-ONLY.bin'
 run(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie','-Wl,--no-undefined,--gc-sections,--build-id=none,-Map='+str(out/'warm.map'),'-Wl,-T,'+str(ld),*map(str,objects),'-lgcc','-o',str(elf)])
 assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
 spec=importlib.util.spec_from_file_location('warm_ELF32',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);e=m.ELF32(elf)
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
 blob=bytearray(flat.read_bytes());image=0x02d4bb74;ram=symbols['__resident_end']['value']-image
 struct.pack_into('<3I',blob,0,0xea000000|(((e.entry-(image+8))//4)&0xffffff),ram,len(blob));flat.write_bytes(blob)
 original=(ROOT/old['original_binary']).read_bytes()
 assert blob[12:len(original)]==original[12:]and len(blob)<ram<=0x300000
 assert old['protected_tail_start']==symbols['__resident_tail_start']['value']
 code=run(['arm-linux-gnueabi-objdump','-d','--disassemble=mw_attach_stage1',str(elf)])
 (out/'warm-attach-opcodes.txt').write_text(code)
 derivation=json.loads((PREV/'route-entry-derivation-v2.json').read_text());patches=[]
 for row in derivation['patches']:
  address=row['address'];size=row['patch_bytes'];aligned=(address%4==0)
  if row['name']=='allocate':
   # One register argument only. Eight bytes leave the internal loop at
   # original+8 and its back edge at original+10 in executable native code.
   assert size==8 and aligned and row['patch_direct_ARM_C_gate']
   prefix=bytes.fromhex('004b1847');endpoint=symbols['rg_allocate_gate']['value']
  else:
   prefix=bytes.fromhex('08b4014b1847c046'if aligned else '08b4004b1847')
   endpoint=symbols['rg_'+row['name']+'_entry']['value']
  after=prefix+struct.pack('<I',endpoint)
  after+=bytes.fromhex('c046')*((size-len(after))//2)
  assert len(after)==size
  patches.append(dict(row,after_hex=after.hex()))
 provider_patches=[]
 for row in prepared['selected_six_provider_API_barriers']:
  prefix=bytes.fromhex('004b1847'if row['address']%4==0 else '014b1847c046')
  after=prefix+struct.pack('<I',symbols['pg_'+row['name']+'_gate']['value'])
  assert len(after)==row['patch_bytes']
  provider_patches.append(dict(row,after_hex=after.hex()))
 alias_patches=[]
 for row in aliases['five_selected_backend_patches']:
  if row['name']=='clear':
   fixed=symbols['al_clear_fixed_entry']['value'];assert fixed==0x02fb4718 and fixed&0xffff==0x4718
   after=bytes.fromhex('004b')+struct.pack('<I',fixed)+bytes.fromhex('c046')
  else:
   prefix=bytes.fromhex('08b4014b1847c046'if row['address']%4==0 else '08b4004b1847')
   after=prefix+struct.pack('<I',symbols['al_'+row['name']+'_entry']['value'])
  assert len(after)==row['patch_bytes']
  alias_patches.append(dict(row,after_hex=after.hex()))
 for name in ['mw_attach_stage1','mw_attaches','mw_denials','mw_last_reason','ns_retire_step','ns_capture_registration','ns_bind_selected','ns_status','continuous_media_cancel_ready']:assert name in symbols,name
 manifest=dict(old,all_passed=True,ELF=rel(elf),ELF_sha256=sha(elf),symbols=symbols,source_sha256=deps,
  reused_relocatable_objects=[rel(p)for p in objects if p not in new_objects],combined_binary=rel(flat),combined_sha256=sha(flat),combined_file_bytes=len(blob),combined_ram_bytes=ram,
  extension_added_file_bytes=len(blob)-len(original),extension_added_RAM_bytes=ram-old['original_ram_bytes'],remaining_loader_capacity=0x300000-ram,
  pcm_pages=[symbols['pcm'+str(i)]['value']for i in range(4)],
  reader_patch=dict(old['reader_patch'],after_hex=(bytes.fromhex('004b1847')+struct.pack('<I',symbols['resident_loader_read_gate']['value'])).hex()),
  native_descriptor_patch=dict(old['native_descriptor_patch'],after_hex=(bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',symbols['nr_reply_dispatch']['value'])).hex()),
  selective_warm_Source_structural_admission=True,selected_native_route_entry_barriers=patches,selected_native_provider_entry_barriers=provider_patches,selected_native_backend_alias_barriers=alias_patches,three_original_mutexes_at_claim=True,durable_native_ownership=False,native_retirement_integrated_in_same_warm_image=True,native_STOP_DONE_or_claim_yield=False,guest_executed=False,device_IO=False)
 assert all(sha(ROOT/p)==h for p,h in deps.items())
 dump(BASE/'build-v1.json',manifest)
 print(json.dumps(dict(all_passed=True,file_bytes=len(blob),RAM_bytes=ram,tail=old['protected_tail_start'],device_IO=False)))
if __name__=='__main__':main()
