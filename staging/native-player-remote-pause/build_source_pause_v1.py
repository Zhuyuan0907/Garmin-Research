#!/usr/bin/env python3
"""NEW bounded pipeline image. Compile/static ELF only, no guest creation."""
import hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
HANDOFF=ROOT/'staging/native-player-mixer-handoff'
SYNC=ROOT/'staging/native-player-mixer-sync'
PREV=ROOT/'staging/native-player-sbc-sync'
SBC=ROOT/'sources/deep-research/sbc-2.1/sbc'
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
 archive=ROOT/'sources/deep-research/sbc-2.1.tar.xz'
 assert sha(archive)=='426633cabd7c798236443516dfa8335b47e004b0ef37ff107e0c7ead3299fcc2'
 import tarfile
 with tarfile.open(archive,'r:xz') as package:
  for p in [SBC/'sbc.c',*sorted(SBC.glob('*.h'))]:
   assert package.extractfile('sbc-2.1/sbc/'+p.name).read()==p.read_bytes()
 out=BASE/'source-build-v1';out.mkdir(exist_ok=False)
 snap=out/'source-snapshot';snap.mkdir()
 source=[Path(__file__).resolve(),BASE/'owned_media_pause_v1.c',HANDOFF/'audio_session_driver_v4.c',BASE/'mixer_source_pause_v1.c',BASE/'sbc_fifo_ingress_pause_v1.c',FROZEN/'runtime.c',FROZEN/'bounded_pull_entry.S',SBC/'sbc.c',ROOT/'native/sbc-prototype/decoder.c',ROOT/'native/sbc-prototype/pcm_converter.c',ROOT/'native/sbc-prototype/voice_media.c',PREV/'sbc_arena_runtime_v1.c',SYNC/'initializer_sync_bridge_v1.c',SYNC/'initializer_sync_bridge_v1.S',
  SYNC/'music_session_guard_sync_v1.c',HANDOFF/'music_session_guard_v4.h',HANDOFF/'native_context_v4.c',
  HANDOFF/'pull_bridge_v4.S',HANDOFF/'memory_output_session_owner_v4.c',
  ROOT/'staging/native-player-settings-scope/music-owner/memory_output_owner.c',
  ROOT/'native/music-continuous/memory_output.c',ROOT/'native/music-continuous/owned_media.c',
  ROOT/'native/sbc-prototype/memory_output.h',ROOT/'native/sbc-prototype/decoder.h',
  ROOT/'native/sbc-prototype/pcm_converter.h',ROOT/'staging/native-owned-media/owned_queue.c',
  ROOT/'native/sbc-prototype/media_queue.h',ROOT/'native/sbc-prototype/media_worker.c',
  ROOT/'native/sbc-prototype/media_worker.h',
  ROOT/'native/ui-music-control-prototype/ui_music_control.c',
  ROOT/'native/ui-music-control-prototype/ui_music_control.h',
  ROOT/'native/ui-music-native-adapter/native_adapter.h',
  ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',*sorted(SBC.glob('*.h')),ROOT/'sources/deep-research/sbc-2.1.tar.xz',ROOT/'staging/native-pcm-converter/pcm_converter_tables.h',ROOT/'staging/native-pcm-converter/coefficients.json']
 hashes={rel(p):sha(p)for p in source}
 for i,p in enumerate(source):(snap/f'{i:02d}-{p.name}').write_bytes(p.read_bytes())
 dump(out/'inputs.json',hashes)
 header=out/'playback_imports.h'
 header.write_text('#ifndef AAS_PLAYBACK_IMPORTS_H\n#define AAS_PLAYBACK_IMPORTS_H\n#include <stdint.h>\nstatic const uint32_t playback_pcm_pages[4]={0x07700000u,0x07701000u,0x07702000u,0x07703000u};\n#endif\n')
 ld=out/'audio-session.ld'
 ld.write_text('''ENTRY(aas_initialize)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); fifo PT_LOAD FLAGS(6); worker PT_LOAD FLAGS(6); packet PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x07000000;
 .text : { KEEP(*(.text.sbi_*)) KEEP(*(.text.ms_*)) KEEP(*(.text.mh_*)) KEEP(*(.mh_offsets)) KEEP(*(.text.aas_*)) KEEP(*(.text.memory_output_release_session)) KEEP(*(.text.mcs_pull_bridge)) KEEP(*(.text.mcs_native_ownership_snapshot)) KEEP(*(.aas_offsets)) *(.text*) *(.rodata*) } :code
 . = ALIGN(4096);
 .data : { *(.data*) } :state
 . = ALIGN(4096);
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 .pcm0 0x07700000 (NOLOAD) : { *(.pcm0) } :fifo
 .pcm1 0x07701000 (NOLOAD) : { *(.pcm1) } :fifo
 .pcm2 0x07702000 (NOLOAD) : { *(.pcm2) } :fifo
 .pcm3 0x07703000 (NOLOAD) : { *(.pcm3) } :fifo
 .mh_source_stack 0x07800000 (NOLOAD) : { *(.mh_source_stack) } :worker
 .gather 0x07900000 (NOLOAD) : { *(.gather) } :packet
 .queue_payload 0x07902000 (NOLOAD) : { *(.queue_payload) } :packet
 .ARM.attributes 0 : { *(.ARM.attributes) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) *(.output_api) *(.owned_api) *(.queue_api) *(.worker_api) *(.mcs_output_api) }
}
''')
 flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-pie',
  '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
  '-Wall','-Wextra','-Werror','-I',str(out),'-I',str(BASE),'-I',str(HANDOFF),'-I',str(SBC),'-I',str(ROOT/'staging/native-pcm-converter'),'-I',str(ROOT/'native/sbc-prototype')]
 files=[HANDOFF/'audio_session_driver_v4.c',BASE/'mixer_source_pause_v1.c',BASE/'sbc_fifo_ingress_pause_v1.c',FROZEN/'runtime.c',FROZEN/'bounded_pull_entry.S',SBC/'sbc.c',ROOT/'native/sbc-prototype/decoder.c',ROOT/'native/sbc-prototype/pcm_converter.c',ROOT/'native/sbc-prototype/voice_media.c',PREV/'sbc_arena_runtime_v1.c',SYNC/'initializer_sync_bridge_v1.c',SYNC/'initializer_sync_bridge_v1.S',
  SYNC/'music_session_guard_sync_v1.c',HANDOFF/'native_context_v4.c',HANDOFF/'pull_bridge_v4.S',
  HANDOFF/'memory_output_session_owner_v4.c',ROOT/'staging/native-owned-media/owned_queue.c',
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
  extra=[]
  if p.name=='sbc.c':extra=['-Wno-error=unused-parameter']
  if p.name=='voice_media.c':extra=['-DVOICE_MEDIA_CONVERT=1','-Dvoice_extension_submit_frame=owned_media_submit_frame','-Dvoice_extension_media_callback=owned_packet_parse','-Dvoice_extension_media_api=owned_packet_api','-Dvoice_media_stats=owned_packet_stats']
  run(['arm-linux-gnueabi-gcc',*flags,*extra,'-c',str(p),'-o',str(obj)])
 elf=out/'audio-session-EMULATION-ONLY.elf'
 run(['arm-linux-gnueabi-gcc','-nostdlib','-no-pie','-Wl,--gc-sections','-Wl,--no-undefined',
  '-Wl,-T,'+str(ld),'-Wl,-Map,'+str(out/'audio-session.map'),*[str(p)for p in objects],'-lgcc','-o',str(elf)])
 readelf=run(['arm-linux-gnueabi-readelf','-h','-s','-l',str(elf)])
 (out/'readelf.txt').write_text(readelf)
 spec=importlib.util.spec_from_file_location('aas_elf',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);e=m.ELF32(elf)
 undefined=[s['name']for s in e.symbols if s['name']and s['section_index']==0]
 assert not undefined,undefined
 symbols={s['name']:s for s in e.symbols if s['name']and s['section_index']!=0}
 wanted=('aas_initialize','aas_register','aas_packet_ticket','aas_media_ingress','sbi_receive_packet','sbi_capacity_wake','sbi_status','mh_remote_paused','mh_remote_pause_epoch','mh_remote_paused_reads','mh_remote_paused_bytes','mh_remote_pause_requests','mh_remote_resume_requests','mh_started','mh_stream_error','sbi_callbacks','sbi_accepted','sbi_capacity_posts','aas_status','aas_stop','aas_pull','aas_session_id','aas_registration_seed',
  'mcs_pull_bridge','mcs_original_pull_thunk','memory_output_submit','memory_output_read',
  'continuous_media_read','media_queue_begin','media_queue_stop','memory_output_release_session','memory_output_bind_selected_session','mcs_capture_selected','mcs_native_ownership_snapshot',
  'aas_guard','aas_control','aas_offsets','memory_output_control','memory_output_slots',
  'mh_source_entry','mh_source_tcb','mh_boot_source','mh_request_command','mh_selector_bridge','mh_status','mh_offsets',
  'mcs_handoff_source_to_mixer','mcs_mixer_selector_begin','mcs_mixer_selector_after_original','source_stack','source_descriptor','ms_initializer_sync_bridge','ms_before_original_sync','ms_validate_completed_sync','ms_original_sync_completed','ms_sync_entries','ms_sync_grants','ms_sync_reuses','ms_sync_rejections','ms_before_result')
 for n in wanted:assert n in symbols,n
 for n in ('mp_streams','mp_bad_packets','mp_select_stream','input_pcm','owned_media_api',
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
  symbols=symbols,undefined_symbols=[],raw_PCM_test_producer=False,compiled_SBC_RTP_decode_and_typed_FIFO_producer=True,compiled_compressed_fixture_or_bootstrap_packet=False,external_ingress_copy_and_Source_event_drain=True,capacity_source_POST=True,Stage1_without_anchor_or_mixer=True,original_SEP_registration_or_phone_ingress_verified=False,frozen_FIFO_reader_retained=True,new_native_mixer_handoff_prototype=True,
  actual_compiled_submit_retained=True,original_MAIN_unchanged=True,complete_player_image=False,compiled_Source_private_pause_preserves_FIFO=True,
  guest_executed=False,device_io=False,original_sync_not_executed_at_compile_time=True,conditional_CONFIG_handoff_before_sync=True,PLAY_closed_until_original_sync_return=True)
 dump(BASE/'source-build-v1.json',manifest)
 print(json.dumps(dict(all_passed=True,ELF=rel(elf),ELF_sha256=sha(elf),guest_executed=False)))
if __name__=='__main__':main()
