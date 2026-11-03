#!/usr/bin/env python3
"""Single stock-address DLL image containing the current pause-capable player.
No VPM/install/guest is produced here. Frozen original object files are reused
only where ELF relocations can resolve their internal references afresh.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib,subprocess,struct,importlib.util
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
PREV=ROOT/'staging/native-player-remote-pause'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
IMAGE=0x02d4bb74
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def create(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 old=json.loads((PREV/'source-build-v2.json').read_text())
 remote=json.loads((PREV/'remote-build-v1.json').read_text())
 for manifest in (old,remote):
  for p,h in manifest['source_sha256'].items():assert sha(ROOT/p)==h,p
 assert sha(ROOT/old['ELF'])==old['ELF_sha256']
 original=ROOT/'evidence/firmware-analysis/voice-modules/Chinese_Big5_MeiLing/DLLIMG.BIN'
 raw=original.read_bytes();original_ram=struct.unpack_from('<I',raw,4)[0]
 extension_base=(IMAGE+original_ram+4095)&~4095
 out=BASE/'build-v1';out.mkdir(exist_ok=False)
 dependencies=dict(old['source_sha256'],**old['generated_sha256'],**remote['source_sha256'])
 for p in [Path(__file__),BASE/'resident_entry_v1.c',PREV/'source-build-v2.json',PREV/'remote-build-v1.json',original]:dependencies[rel(p)]=sha(p)
 # Remove VM-only absolute Source imports and PCM page addresses. The reader
 # obtains addresses from its owning translation unit after the final link.
 owned=(PREV/'owned_media_pause_v2.c').read_text()
 assert owned.count('#include "playback_imports.h"')==1
 owned=owned.replace('#include "playback_imports.h"','extern uint32_t resident_pcm_address(uint32_t);')
 assert owned.count('playback_pcm_pages[index]')==1
 owned=owned.replace('playback_pcm_pages[index]','resident_pcm_address(index)')
 (out/'owned_media_loaded_v1.c').write_text(owned)
 ingress=(PREV/'sbc_fifo_ingress_pause_v2.c').read_text().replace('"owned_media_pause_v2.c"','"owned_media_loaded_v1.c"')
 (out/'sbc_fifo_loaded_v1.c').write_text(ingress)
 owner=(ROOT/'staging/native-player-mixer-handoff/memory_output_session_owner_v4.c').read_text()
 owner=owner.replace('"../native-player-settings-scope/music-owner/memory_output_owner.c"',
                    '"'+str(ROOT/'staging/native-player-settings-scope/music-owner/memory_output_owner.c')+'"')
 owner+='\nuint32_t resident_pcm_address(uint32_t index)\n{ return index<4u?(uint32_t)(uintptr_t)buffers[index]:0u; }\n'
 (out/'memory_output_loaded_owner_v1.c').write_text(owner)
 (out/'source_imports_v1.h').write_text('''#include <stdint.h>
extern int aas_media_ingress(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern int mh_request_command(uint32_t);
#define NSG_SOURCE_INGRESS ((uintptr_t)&aas_media_ingress)
#define NSG_SOURCE_COMMAND ((uintptr_t)&mh_request_command)
''')
 for name in ('remote_pause_binding_v1.c','reply_pause_binding_v1.c'):
  s=(PREV/name).read_text()
  s=s.replace('"../../native/','"'+str(ROOT/'native')+'/')
  (out/name).write_text(s)
 (out/'remote_binding_v1.h').write_bytes((PREV/'remote_binding_v1.h').read_bytes())
 assembly=out/'stock_image.S'
 assembly.write_text('.section .stock_tts,"a",%progbits\n.incbin "'+str(original)+'"\n')
 ld=out/'resident.ld'
 ld.write_text(f'''ENTRY(resident_music_entry)
PHDRS {{ code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); }}
original_tts_entry = {IMAGE+60868:#x};
SECTIONS {{
 .stock_tts {IMAGE:#x} : {{ KEEP(*(.stock_tts)) }} :code
 . = {extension_base:#x};
 .entry : {{ KEEP(*(.text.resident_music_entry)) }} :code
 .text : {{ KEEP(*(.text.sbi_*)) KEEP(*(.text.ms_*)) KEEP(*(.text.mh_*))
  KEEP(*(.text.aas_*)) KEEP(*(.text.memory_output_release_session))
  KEEP(*(.text.mcs_pull_bridge)) KEEP(*(.text.mcs_native_ownership_snapshot))
  *(.text*) *(.rodata*) KEEP(*(.mh_offsets)) KEEP(*(.aas_offsets))
  KEEP(*(.resident_api)) }} :code
 __resident_code_end = .;
 . = ALIGN(4096);
 .data : {{ *(.data*) }} :state
 __resident_file_end = .;
 . = ALIGN(4096); __resident_bss_start = .;
 .bss (NOLOAD) : {{ *(.bss*) *(COMMON) }} :state
 . = ALIGN(4096);
 .pcm0 (NOLOAD) : {{ *(.pcm0) }} :state
 .pcm1 (NOLOAD) : {{ *(.pcm1) }} :state
 .pcm2 (NOLOAD) : {{ *(.pcm2) }} :state
 .pcm3 (NOLOAD) : {{ *(.pcm3) }} :state
 .mh_source_stack (NOLOAD) : {{ *(.mh_source_stack) }} :state
 .gather (NOLOAD) : {{ *(.gather) }} :state
 .queue_payload (NOLOAD) : {{ *(.queue_payload) }} :state
 __resident_bss_end = .; __resident_end = .;
 ASSERT(__resident_end-{IMAGE:#x} <= 0x300000,"Stock DLL capacity exceeded")
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*)
  *(.output_api) *(.owned_api) *(.queue_api) *(.worker_api) *(.mcs_output_api) }}
}}
''')
 commands=[]
 def run(cmd):
  r=subprocess.run(cmd,capture_output=True,text=True)
  create(out/f'command-{len(commands):02d}.json',dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));commands.append(cmd)
  assert not r.returncode,r.stderr[-4000:]
  return r.stdout
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie',
  '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror',
  '-I'+str(out),'-I'+str(ROOT/'staging/native-player-mixer-handoff'),'-I'+str(ROOT/'native/sbc-prototype')]
 objects=[];reused=[]
 for p in sorted((PREV/'source-build-v2').glob('*.o')):
  if p.name in ('02-sbc_fifo_ingress_pause_v2.o','15-memory_output_session_owner_v4.o'):continue
  # Actual list checked below instead of assuming filename ordering.
  if any(x in p.name for x in ('sbc_fifo_ingress_pause','memory_output_session_owner')):continue
  objects.append(p);reused.append(rel(p));dependencies[rel(p)]=sha(p)
 assert len(objects)==17,(len(objects),reused)
 files=[out/'sbc_fifo_loaded_v1.c',out/'memory_output_loaded_owner_v1.c',BASE/'resident_entry_v1.c',assembly,
  ROOT/'native/music-endpoint/endpoint.c',ROOT/'native/avdtp-gate/gate.c',ROOT/'native/avdtp-policy/policy.c',
  out/'reply_pause_binding_v1.c',out/'remote_pause_binding_v1.c',ROOT/'native/avdtp-reply/stock-relocated.S']
 for i,p in enumerate(files):
  dependencies[rel(p)]=sha(p);obj=out/f'loaded-{i:02d}-{p.stem}.o';objects.append(obj)
  run(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(obj)])
 elf=out/'resident-player-EMULATION-ONLY.elf';flat=out/'combined-EMULATION-ONLY.bin'
 run(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
  '-Wl,--no-undefined,--gc-sections,--build-id=none,-Map='+str(out/'resident.map'),'-Wl,-T,'+str(ld),*map(str,objects),'-lgcc','-o',str(elf)])
 assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
 spec=importlib.util.spec_from_file_location('loaded_ELF32',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);e=m.ELF32(elf)
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
 combined=bytearray(flat.read_bytes());ram=symbols['__resident_end']['value']-IMAGE
 assert len(combined)==symbols['__resident_file_end']['value']-IMAGE
 branch=0xea000000|(((e.entry-(IMAGE+8))//4)&0xffffff)
 struct.pack_into('<3I',combined,0,branch,ram,len(combined))
 flat.write_bytes(combined)
 assert combined[12:len(raw)]==raw[12:] and len(combined)<ram<=0x300000
 for name in ('aas_media_ingress','mh_request_command','nsg_native_callback','resident_player_api','resident_pcm_address'):
  assert extension_base<=symbols[name]['value']<symbols['__resident_end']['value']
 assert symbols['resident_entry_phase']['value']<symbols['__resident_bss_start']['value']
 pages=[symbols['pcm'+str(i)]['value']for i in range(4)]
 assert all(p%4096==0 for p in pages)and len(set(pages))==4
 stock=NativeImage();offset=symbols['stock_reply_relocated']['value']-IMAGE
 assert combined[offset:offset+16]==stock.read(0x5756ac,16)
 patch=bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',symbols['nr_reply_dispatch']['value'])
 for p in out.glob('*.h'):dependencies[rel(p)]=sha(p)
 dependencies[rel(ld)]=sha(ld)
 assert all(sha(ROOT/p)==h for p,h in dependencies.items())
 manifest=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),HWID=1352,software='8.00',MAIN_sha256=EXPECTED,
  ELF=rel(elf),ELF_sha256=sha(elf),symbols=symbols,source_sha256=dependencies,generated_sha256={},
  combined_binary=rel(flat),combined_sha256=sha(flat),combined_file_bytes=len(combined),combined_ram_bytes=ram,
  module_base=IMAGE,extension_base=extension_base,extension_added_file_bytes=len(combined)-len(raw),
  extension_added_RAM_bytes=ram-original_ram,remaining_loader_capacity=0x300000-ram,
  original_binary=rel(original),original_sha256=sha(original),original_file_bytes=len(raw),original_ram_bytes=original_ram,
  original_bytes_after_header_unchanged=True,pcm_pages=pages,reused_relocatable_objects=reused,new_compiles=len(files),
  no_absolute_VM_Source_imports=True,no_absolute_VM_PCM_pages=True,one_native_DLL_image=True,
  sole_passive_bootstrap='resident_music_entry',activation_performed_by_entry=False,original_forty_exports_preserved_at_build_only=True,
  native_descriptor_patch=dict(address=0x5756ac,before_hex=stock.read(0x5756ac,16).hex(),after_hex=patch.hex()),
  native_warm_activation_heap_menu_lifetime_pin_or_phone_verified=False,guest_executed=False,device_IO=False,
  modified_VPM_generated=False,device_install_candidate=False)
 create(BASE/'build-v1.json',manifest)
 print(json.dumps(dict(all_passed=True,file_bytes=len(combined),ram_bytes=ram,extension_base=extension_base,added_RAM_bytes=ram-original_ram,remaining_loader_capacity=0x300000-ram,guest_executed=False)))
if __name__=='__main__':main()
