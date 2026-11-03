#!/usr/bin/env python3
"""Relink the current one-image player above ALL installed original voice RAM.
Reuse frozen relocatable objects; add compiled loader boundary. No VPM/device.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib,subprocess,importlib.util,struct
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
PREV=ROOT/'staging/native-player-loaded-single-image'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
IMAGE=0x02d4bb74
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 old=json.loads((PREV/'build-v3.json').read_text())
 for p,h in old['source_sha256'].items():assert sha(ROOT/p)==h,p
 objects=[ROOT/p for p in old['reused_relocatable_objects']]+sorted((PREV/'build-v3').glob('loaded-*.o'))
 assert len(objects)==27,len(objects)
 registry=ROOT/'evidence/firmware-analysis/tts-vpm-containers.json'
 voices=[]
 for r in json.loads(registry.read_text())['containers']:
  if not r['native_module_container']:continue
  p=ROOT/r['module']['extracted_binary'];blob=p.read_bytes()
  assert sha(p)==r['files']['DLLIMG.BIN']['sha256']
  ram,file=struct.unpack_from('<2I',blob,4)
  assert file==len(blob)and file<ram<=0x300000
  voices.append(dict(path=rel(p),sha256=sha(p),file_bytes=file,ram_bytes=ram))
 assert len(voices)==3
 base=(IMAGE+max(v['ram_bytes']for v in voices)+4095)&~4095
 out=BASE/'build-v1';out.mkdir(exist_ok=False)
 ldtext=(PREV/'build-v3/resident.ld').read_text().replace('. = 0x2f7d000;',f'. = {base:#x}; __resident_tail_start = .;')
 ldtext=ldtext.replace('KEEP(*(.text.resident_music_entry))','KEEP(*(.text.resident_music_entry)) KEEP(*(.text.resident_loader_read_gate)) KEEP(*(.text.stock_reader_tail_relocated))')
 ld=out/'reserved-tail.ld';ld.write_text(ldtext)
 deps=dict(old['source_sha256'])
 for p in [Path(__file__),PREV/'build-v3.json',registry,ld,*objects,BASE/'loader_tail_gate_v1.c',BASE/'stock_reader_tail_v1.S',*[ROOT/v['path']for v in voices]]:deps[rel(p)]=sha(p)
 commands=[]
 def run(cmd):
  r=subprocess.run(cmd,text=True,capture_output=True);dump(out/f'command-{len(commands):02d}.json',dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));commands.append(cmd)
  assert not r.returncode,r.stderr[-3000:]
  return r.stdout
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror']
 for p in [BASE/'loader_tail_gate_v1.c',BASE/'stock_reader_tail_v1.S']:
  obj=out/(p.stem+'.o');run(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(obj)]);objects.append(obj)
 elf=out/'reserved-tail-EMULATION-ONLY.elf';flat=out/'reserved-tail-EMULATION-ONLY.bin'
 run(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie','-Wl,--no-undefined,--gc-sections,--build-id=none,-Map='+str(out/'reserved-tail.map'),'-Wl,-T,'+str(ld),*map(str,objects),'-lgcc','-o',str(elf)])
 assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
 spec=importlib.util.spec_from_file_location('tail_ELF32',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);e=m.ELF32(elf)
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
 blob=bytearray(flat.read_bytes());ram=symbols['__resident_end']['value']-IMAGE
 struct.pack_into('<3I',blob,0,0xea000000|(((e.entry-(IMAGE+8))//4)&0xffffff),ram,len(blob));flat.write_bytes(blob)
 original=(ROOT/old['original_binary']).read_bytes()
 assert blob[12:len(original)]==original[12:]and len(blob)<ram<=0x300000
 stock=NativeImage();prefix=(symbols['stock_reader_tail_relocated']['value']&~1)-IMAGE
 assert blob[prefix:prefix+8]==stock.read(0x3b3294,8)
 patch=bytes.fromhex('004b1847')+struct.pack('<I',symbols['resident_loader_read_gate']['value'])
 code=run(['arm-linux-gnueabi-objdump','-d','--disassemble=resident_loader_read_gate',str(elf)])
 # GCC must actually tail-branch, no BL/BLX/push/pop or saved module frame.
 instructions=[l.split('\t')[-1]for l in code.splitlines()if '\t'in l and ':'in l]
 assert not any(x.strip().startswith(('bl ','blx ','push ','pop '))for x in instructions),code
 assert '__stock_reader_tail_relocated_from_arm' in code,code
 gate_info=out/'gate-opcodes.txt';gate_info.write_text(code);deps[rel(gate_info)]=sha(gate_info)
 patch_reply=bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',symbols['nr_reply_dispatch']['value'])
 manifest=dict(old,updated_utc=datetime.now(timezone.utc).isoformat(),ELF=rel(elf),ELF_sha256=sha(elf),symbols=symbols,source_sha256=deps,
  combined_binary=rel(flat),combined_sha256=sha(flat),combined_file_bytes=len(blob),combined_ram_bytes=ram,extension_base=base,
  extension_added_file_bytes=len(blob)-len(original),extension_added_RAM_bytes=ram-old['original_ram_bytes'],remaining_loader_capacity=0x300000-ram,
  pcm_pages=[symbols['pcm'+str(i)]['value']for i in range(4)],
  installed_original_voice_ranges=voices,protected_tail_start=base,protected_reader_limit=base-IMAGE,
  reader_patch=dict(address=0x3b3294,before_hex=stock.read(0x3b3294,8).hex(),after_hex=patch.hex()),
  native_descriptor_patch=dict(address=0x5756ac,before_hex=stock.read(0x5756ac,16).hex(),after_hex=patch_reply.hex()),
  gate_tail_branch_no_resident_return_frame=True,known_original_voice_file_and_RAM_below_tail=True,
  permanent_boot_scoped_reservation=True,live_patch_or_cache_or_safe_unload_or_warm_owner=False,
  guest_executed=False,device_IO=False,modified_VPM_generated=False,device_install_candidate=False)
 assert all(sha(ROOT/p)==h for p,h in deps.items())
 dump(BASE/'build-v1.json',manifest)
 print(json.dumps(dict(all_passed=True,tail=base,limit=base-IMAGE,file_bytes=len(blob),RAM_bytes=ram,gate_tail_branch=True,device_IO=False)))
if __name__=='__main__':main()
