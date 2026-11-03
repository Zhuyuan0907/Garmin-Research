#!/usr/bin/env python3
"""Relink full owned-media/control workers inside stock TTS RAM; offline only.

Preserve original40 exports/code. No VPM/SIG change, executable hook install,
automatic task boot, native UI or package-acceptance claim.
"""
from datetime import datetime,timezone
import json
from pathlib import Path
import struct
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR
from build_native_sbc import LOCAL,run,sha
from emulate_native_memory_notice import check_manifest

OUT=ROOT/'staging/native-app-component-emulation'
API_NAMES=('owned_media_init','media_queue_begin','media_worker_boot','source_worker_boot',
 'source_worker_shutdown','media_worker_shutdown','media_worker_callback','garmin_sbc_reset',
 'garmin_sbc_decode_frame','source_publication_hook','source_completion_hook','playback_callback_hook')


def symbols(elf):
    result={}
    for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
        p=line.split()
        if len(p)==3:result[p[2]]={'address':int(p[0],16),'type':p[1]}
    return result


def build(row,manifests):
    original_path=ROOT/row['module']['extracted_binary'];original=original_path.read_bytes()
    assert sha(original_path)==row['files']['DLLIMG.BIN']['sha256']
    original_ram=row['module']['image_header_ram_bytes']
    base=(IMAGE+original_ram+4095)&~4095
    assert base>IMAGE+len(original) and base+0x28000<DESCRIPTOR
    build=OUT/Path(row['file']).stem;build.mkdir(parents=True,exist_ok=True)
    pcm_pages=[base+0x16000+i*4096 for i in range(4)]
    playback_header=build/'playback_imports.h'
    playback_header.write_text('static const uint32_t playback_pcm_pages[4] = {'+
        ','.join(hex(a)+'u' for a in pcm_pages)+'};\n')
    source_header=build/'source_worker_imports.h'
    # First pass determines the new consume address; it is not executed.
    # Keep the same literal-pool instruction shape in both link passes. A zero
    # placeholder becomes MOV-immediate and changes later symbol addresses.
    source_header.write_text('#define OWNED_CONSUME_RESUME 0x12345678\n')
    linker=build/'app_component.ld'
    linker.write_text(f'''ENTRY(native_app_component_entry)
original_tts_entry = {IMAGE+row['module']['first_branch_offset']:#x};
SECTIONS {{
 . = {base:#x};
 .text : {{ KEEP(*(.text.native_app_component_entry))
   KEEP(*(.app_component_api)) KEEP(*(.owned_api)) KEEP(*(.output_api))
   KEEP(*(.queue_api)) KEEP(*(.worker_api)) KEEP(*(.playback_api))
   KEEP(*(.coordinator_api)) KEEP(*(.source_worker_api)) KEEP(*(.extension_exports))
   *(.text .text.*) *(.rodata .rodata.*) }}
 __app_code_end = .;
 ASSERT(. <= {base+0x10000:#x}, "combined code exceeds64KiB")
 . = {base+0x10000:#x}; __app_zero_start = .;
 .bss (NOLOAD) : {{ __app_bss_start = .; *(.bss .bss.*) *(COMMON) __app_bss_end = .; }}
 ASSERT(. <= {base+0x15000:#x}, "combined BSS exceeds20KiB")
 . = {pcm_pages[0]:#x}; .pcm0 (NOLOAD) : {{ *(.pcm0) }}
 . = {pcm_pages[1]:#x}; .pcm1 (NOLOAD) : {{ *(.pcm1) }}
 . = {pcm_pages[2]:#x}; .pcm2 (NOLOAD) : {{ *(.pcm2) }}
 . = {pcm_pages[3]:#x}; .pcm3 (NOLOAD) : {{ *(.pcm3) }}
 . = {base+0x1a000:#x}; .gather (NOLOAD) : {{ *(.gather) }}
 . = {base+0x1b000:#x}; .queue_payload (NOLOAD) : {{
   __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .; }}
 . = {base+0x20000:#x}; .worker_stack (NOLOAD) : {{
   __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .; }}
 . = {base+0x24000:#x}; .source_stack (NOLOAD) : {{
   __source_stack_start = .; *(.source_stack) __source_stack_end = .; }}
 __app_zero_end = .; __app_end = .;
 __combined_ram_bytes = ABSOLUTE(. - {IMAGE:#x});
 ASSERT(__combined_ram_bytes <= 0x300000, "exceeds original DLL reservation")
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    commands=[];objects=[];sources=[]
    # Recompile verified source with original flags; preserve all old outputs.
    for command in manifests['owned']['commands']:
        if '-c' not in command:continue
        c=command.copy();src=Path(c[c.index('-c')+1]);obj=build/(src.stem+'.o')
        c[c.index('-o')+1]=str(obj);run(c);commands.append(c);objects.append(str(obj));sources.append(src)
    compiler='arm-linux-gnueabi-gcc'
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-Wall','-Wextra','-Werror','-I'+str(LOCAL),'-I'+str(build)]
    extra=(LOCAL/'app_component_entry.c',LOCAL/'playback_control.c',LOCAL/'playback_hook.S',
           LOCAL/'media_coordinator.c',LOCAL/'source_worker.c',LOCAL/'source_event_hooks.S')
    for src in extra:
        obj=build/(src.stem+'.o');c=[compiler,*flags,'-c',str(src),'-o',str(obj)]
        run(c);commands.append(c);objects.append(str(obj));sources.append(src)
    elf=build/'app-component-emulation.elf';flat=build/'app-component-emulation.bin'
    link=[compiler,'-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
      '-Wl,--gc-sections,--build-id=none,-Map='+str(build/'app_component.map'),
      '-Wl,-T,'+str(linker),*objects,'-lgcc','-o',str(elf)]
    run(link);commands.append(link);s=symbols(elf)
    consume=s['owned_media_consume']['address']
    source_header.write_text('#define OWNED_CONSUME_RESUME '+hex(consume+8)+'\n')
    c=[compiler,*flags,'-c',str(LOCAL/'source_event_hooks.S'),'-o',str(build/'source_event_hooks.o')]
    run(c);commands.append(c);run(link);commands.append(link);s2=symbols(elf)
    assert s2==s,'Address changed between import-resolution passes'
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    binary=flat.read_bytes();assert len(binary)==s['__app_code_end']['address']-base
    assert binary[consume-base:consume-base+8].hex()=='f3472de90050a0e1'
    assert [s['pcm'+str(i)]['address'] for i in range(4)]==pcm_pages
    assert s['__queue_payload_end']['address']-s['__queue_payload_start']['address']==16384
    for n in ('worker','source'):
        assert s['__'+n+'_stack_end']['address']-s['__'+n+'_stack_start']['address']==16384
    for name, value in s.items():
        if value['type'] not in ('T','t','B','b','R','r') or name=='original_tts_entry':
            continue
        if name in ('__source_stack_end','__app_zero_end','__app_end'):
            assert value['address']==base+0x28000, name
        else:
            assert base<=value['address']<base+0x28000, name
    combined=bytearray(original);combined.extend(bytes(base-IMAGE-len(original)));combined.extend(binary)
    ram=s['__combined_ram_bytes']['address'];disp=base-(IMAGE+8)
    assert disp%4==0 and -(1<<25)<=disp<1<<25
    struct.pack_into('<3I',combined,0,0xea000000|((disp//4)&0xffffff),ram,len(combined))
    assert combined[12:len(original)]==original[12:] and len(combined)<ram<=0x300000
    combined_path=build/'combined-voice-app-emulation.bin';combined_path.write_bytes(combined)
    deps=set(sources)|{LOCAL/'memory_output.h',LOCAL/'decoder.h',LOCAL/'media_worker.h',
      LOCAL/'media_queue.h',LOCAL/'pcm_converter.h',playback_header,source_header,linker,Path(__file__),original_path}
    for m in manifests.values():deps.update(ROOT/p for p in m['source_sha256'])
    mpaths=(ROOT/'staging/native-owned-media/manifest.json',ROOT/'staging/native-playback-control/manifest.json',
      ROOT/'staging/native-media-coordinator/manifest.json',ROOT/'staging/native-source-worker/manifest.json')
    deps.update(mpaths)
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
      'voice_package':row['file'],'original_binary':str(original_path.relative_to(ROOT)),
      'original_binary_sha256':sha(original_path),'original_file_bytes':len(original),'original_ram_bytes':original_ram,
      'original_arm_entry':IMAGE+row['module']['first_branch_offset'],
      'extension_base':base,'extension_bytes':len(binary),'extension_elf':str(elf.relative_to(ROOT)),
      'extension_elf_sha256':sha(elf),'extension_flat':str(flat.relative_to(ROOT)),'extension_flat_sha256':sha(flat),
      'combined_binary':str(combined_path.relative_to(ROOT)),'combined_sha256':sha(combined_path),
      'combined_file_bytes':len(combined),'combined_ram_bytes':ram,
      'reservation_start':IMAGE,'reservation_end':DESCRIPTOR,'reservation_bytes':0x300000,
      'remaining_reservation_bytes':0x300000-ram,'original_bytes_after_header_unchanged':True,
      'symbols':s,'private_api':list(API_NAMES),'pcm_pages':pcm_pages,
      'bss_bytes':s['__app_bss_end']['address']-s['__app_bss_start']['address'],
      'new_zero_span_bytes':s['__app_zero_end']['address']-s['__app_zero_start']['address'],
      'commands':commands,'attributes':attrs,'segments':segments,
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(deps)},
      'virtual_source_artifacts_changed':False,'tasks_auto_booted':False,'firmware_hooks_installed':False,
      'modified_vpm_generated':False,'signature_modified':False,'signature_acceptance_verified':False,
      'device_io':False,'device_install_candidate':False,
      'limitations':'Full prototype relinked after original TTS RAM within original fixed3MiB reservation, not free-RAM inference. Original bootstrap owns40 exports; separate private API only. Startup clears new BSS/PCM/queue/stacks, resets decoder but does not boot tasks/install hooks/register SEP/UI. Actual VPM mount/signature/full original speech/voice reload/unload/native loaded worker/event playback/phone/speaker/hardware remain unverified. No installable voice package produced.'}
    (build/'app_component.dis').write_text(run(['arm-linux-gnueabi-objdump','-d',str(elf)]))
    path=build/'manifest.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
    return {'manifest':str(path.relative_to(ROOT)),'code_bytes':len(binary),'combined_ram_bytes':ram,
            'remaining_reservation_bytes':0x300000-ram}


def main():
    stock=NativeImage()
    assert stock.word(0x23c4d8)==IMAGE and stock.word(0x23c4d4)==DESCRIPTOR and IMAGE+0x300000==DESCRIPTOR
    assert any(not r['conditional'] and r['runtime_start']<=IMAGE and DESCRIPTOR+52<=r['runtime_end'] for r in stock.zeros)
    manifests={k:check_manifest(ROOT/'staging'/p/'manifest.json') for k,p in
        (('owned','native-owned-media'),('playback','native-playback-control'),
         ('coord','native-media-coordinator'),('source','native-source-worker'))}
    rows=json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
    result=[build(r,manifests) for r in rows if r['native_module_container']]
    print(json.dumps({'voices':result,'device_io':False,'device_install_candidate':False}))


if __name__=='__main__':main()
