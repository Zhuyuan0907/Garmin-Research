#!/usr/bin/env python3
"""NEW bounded pipeline image. Compile/static ELF only, no guest creation."""
import hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
OLD=ROOT/'staging/native-player-inline-fields/music-session'
FROZEN=ROOT/'staging/native-player-native-allocation/audio-session-static'
def sha(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
 return h.hexdigest()
def rel(path):return str(path.relative_to(ROOT))
def dump(path,value):
 with path.open('x')as f:json.dump(value,f,indent=2);f.write('\n')
def main():
 out=BASE/'build-v2';out.mkdir(exist_ok=False)
 snap=out/'source-snapshot';snap.mkdir()
 source=[Path(__file__).resolve(),BASE/'audio_session_driver_v4.c',BASE/'mixer_source_task_v2.c',BASE/'pcm_fifo_session_owner_v4.c',FROZEN/'runtime.c',FROZEN/'bounded_pull_entry.S',
  BASE/'music_session_guard_v4.c',BASE/'music_session_guard_v4.h',BASE/'native_context_v4.c',
  BASE/'pull_bridge_v4.S',BASE/'memory_output_session_owner_v4.c',
  ROOT/'staging/native-player-settings-scope/music-owner/memory_output_owner.c',
  ROOT/'native/music-continuous/memory_output.c',ROOT/'native/music-continuous/owned_media.c',
  ROOT/'native/sbc-prototype/memory_output.h',ROOT/'native/sbc-prototype/decoder.h',
  ROOT/'native/sbc-prototype/pcm_converter.h',ROOT/'native/sbc-prototype/media_queue.c',
  ROOT/'native/sbc-prototype/media_queue.h',ROOT/'native/sbc-prototype/media_worker.c',
  ROOT/'native/sbc-prototype/media_worker.h',
  ROOT/'native/ui-music-control-prototype/ui_music_control.c',
  ROOT/'native/ui-music-control-prototype/ui_music_control.h',
  ROOT/'native/ui-music-native-adapter/native_adapter.h',
  ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py']
 hashes={rel(p):sha(p)for p in source}
 for i,p in enumerate(source):(snap/f'{i:02d}-{p.name}').write_bytes(p.read_bytes())
 dump(out/'inputs.json',hashes)
 header=out/'playback_imports.h'
 header.write_text('#ifndef AAS_PLAYBACK_IMPORTS_H\n#define AAS_PLAYBACK_IMPORTS_H\n#include <stdint.h>\nstatic const uint32_t playback_pcm_pages[4]={0x07700000u,0x07701000u,0x07702000u,0x07703000u};\n#endif\n')
 ld=out/'audio-session.ld'
 ld.write_text('''ENTRY(aas_initialize)
SECTIONS {
 . = 0x07000000;
 .text : { KEEP(*(.text.mh_*)) KEEP(*(.mh_offsets)) KEEP(*(.text.aas_*)) KEEP(*(.text.memory_output_release_session)) KEEP(*(.text.mcs_pull_bridge)) KEEP(*(.text.mcs_native_ownership_snapshot)) KEEP(*(.aas_offsets)) *(.text*) *(.rodata*) }
 . = ALIGN(4096);
 .data : { *(.data*) }
 . = ALIGN(4096);
 .bss (NOLOAD) : { *(.bss*) *(COMMON) }
 .pcm0 0x07700000 (NOLOAD) : { *(.pcm0) }
 .pcm1 0x07701000 (NOLOAD) : { *(.pcm1) }
 .pcm2 0x07702000 (NOLOAD) : { *(.pcm2) }
 .pcm3 0x07703000 (NOLOAD) : { *(.pcm3) }
 .mh_source_stack 0x07800000 (NOLOAD) : { *(.mh_source_stack) }
 .ARM.attributes 0 : { *(.ARM.attributes) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) *(.output_api) *(.owned_api) *(.queue_api) *(.worker_api) *(.mcs_output_api) }
}
''')
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie',
  '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
  '-Wall','-Wextra','-Werror','-I',str(out),'-I',str(BASE),'-I',str(ROOT/'native/sbc-prototype')]
 files=[BASE/'audio_session_driver_v4.c',BASE/'mixer_source_task_v2.c',BASE/'pcm_fifo_session_owner_v4.c',FROZEN/'runtime.c',FROZEN/'bounded_pull_entry.S',
  BASE/'music_session_guard_v4.c',BASE/'native_context_v4.c',BASE/'pull_bridge_v4.S',
  BASE/'memory_output_session_owner_v4.c',ROOT/'native/sbc-prototype/media_queue.c',
  ROOT/'native/sbc-prototype/media_worker.c',ROOT/'native/ui-music-control-prototype/ui_music_control.c']
 objects=[];commands=[]
 def run(args):
  r=subprocess.run(args,text=True,capture_output=True)
  row=dict(command=args,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr)
  dump(out/f'command-{len(commands):02d}.json',row);commands.append(row)
  if r.returncode:raise RuntimeError(r.stderr[-3000:])
  return r.stdout
 for i,p in enumerate(files):
  obj=out/f'{i:02d}-{p.stem}.o';objects.append(obj)
  run(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(obj)])
 elf=out/'audio-session-EMULATION-ONLY.elf'
 run(['arm-linux-gnueabi-gcc','-nostdlib','-no-pie','-Wl,--gc-sections','-Wl,--no-undefined',
  '-Wl,-T,'+str(ld),'-Wl,-Map,'+str(out/'audio-session.map'),*[str(p)for p in objects],'-o',str(elf)])
 readelf=run(['arm-linux-gnueabi-readelf','-h','-s','-l',str(elf)])
 (out/'readelf.txt').write_text(readelf)
 spec=importlib.util.spec_from_file_location('aas_elf',source[-1])
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);e=m.ELF32(elf)
 undefined=[s['name']for s in e.symbols if s['name']and s['section_index']==0]
 assert not undefined,undefined
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 wanted=('aas_initialize','aas_register','aas_pcm_publish','aas_status','aas_stop','aas_pull','aas_session_id','aas_registration_seed',
  'mcs_pull_bridge','mcs_original_pull_thunk','memory_output_submit','memory_output_read',
  'continuous_media_read','media_queue_begin','media_queue_stop','memory_output_release_session','memory_output_bind_selected_session','mcs_capture_selected','mcs_native_ownership_snapshot',
  'aas_guard','aas_control','aas_offsets','memory_output_control','memory_output_slots',
  'mh_source_entry','mh_source_tcb','mh_boot_source','mh_request_command','mh_selector_bridge','mh_status','mh_offsets',
  'mcs_handoff_source_to_mixer','mcs_mixer_selector_begin','mcs_mixer_selector_after_original','source_stack','source_descriptor')
 for n in wanted:assert n in symbols,n
 for n in ('garmin_sbc_decode_frame','owned_media_consume','owned_packet_parse','owned_media_api',
           'media_worker_boot','source_worker_boot','memory_output_api','mcs_output_api'):
  assert n not in symbols,'unwanted retained subsystem '+n
 for i in range(4):
  s=next(s for s in e.sections if s['name']=='.pcm'+str(i))
  assert s['address']==0x07700000+i*4096 and s['size']==4096 and s['type']==8
  assert symbols['pcm'+str(i)]['value']==s['address']
 assert all(sha(ROOT/p)==h for p,h in hashes.items())
 generated={rel(header):sha(header),rel(ld):sha(ld)}
 manifest=dict(all_passed=True,validation='pure ARM ET_EXEC/GC/linker/input checks; no guest execution',
  source_sha256=hashes,generated_sha256=generated,ELF=rel(elf),ELF_sha256=sha(elf),
  symbols=symbols,undefined_symbols=[],raw_PCM_test_producer=True,frozen_FIFO_reader_retained=True,new_native_mixer_handoff_prototype=True,
  actual_compiled_submit_retained=True,original_MAIN_unchanged=True,complete_player_image=False,
  guest_executed=False,device_io=False,explicit_single_actor_resident_and_wake_fixture=True)
 dump(BASE/'build-v2.json',manifest)
 print(json.dumps(dict(all_passed=True,ELF=rel(elf),ELF_sha256=sha(elf),guest_executed=False)))
if __name__=='__main__':main()
