#!/usr/bin/env python3
"""Build SBC/FIR, queue/worker and owned PCM together; emulator-only backend."""
from datetime import datetime,timezone
import json
from build_native_sbc import ROOT,LOCAL,SOURCE,run,sha

BUILD=ROOT/'staging/native-owned-media'
BASE=0x08800000


def main():
    BUILD.mkdir(parents=True,exist_ok=True)
    baseline=json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    converter=json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    for m in (baseline,converter):
        for p,h in m['source_sha256'].items():
            if sha(ROOT/p)!=h:raise ValueError('Prerequisite source changed: '+p)
    compiler,flags=baseline['commands'][0][0],baseline['commands'][0][1:-4]
    # Preserve all existing sources/builds. Generate an auditable derivative
    #of the validated queue changing ONLY its output-capacity backend.
    original=(LOCAL/'media_queue.c').read_text()
    start=original.index('static int output_ready(void)')
    end=original.index('\n/* One serialized,',start)
    queue=BUILD/'owned_queue.c'
    queue.write_text(original[:start]+'extern int owned_media_output_ready(void);\n'
                     'static int output_ready(void) { return owned_media_output_ready(); }\n'+original[end:])
    linker=BUILD/'owned.ld'
    linker.write_text('''ENTRY(owned_media_init)
SECTIONS {
 . = 0x08800000;
 .text : { KEEP(*(.owned_api)) KEEP(*(.output_api)) KEEP(*(.queue_api)) KEEP(*(.worker_api))
           KEEP(*(.extension_exports)) *(.text .text.*) *(.rodata .rodata.*) }
 __output_code_end = .;
 ASSERT(. <= 0x08840000, "owned code exceeds limit")
 . = 0x08840000; __output_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __output_state_end = .;
 ASSERT(. <= 0x08846000, "owned state exceeds limit")
 . = 0x08848000; .pcm0 (NOLOAD) : { *(.pcm0) }
 . = 0x0884a000; .pcm1 (NOLOAD) : { *(.pcm1) }
 . = 0x0884c000; .pcm2 (NOLOAD) : { *(.pcm2) }
 . = 0x0884e000; .pcm3 (NOLOAD) : { *(.pcm3) }
 . = 0x08850000; .gather (NOLOAD) : { *(.gather) }
 . = 0x08860000;
 .queue_payload (NOLOAD) : { __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .; }
 . = 0x08870000;
 .worker_stack (NOLOAD) : { __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .; }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
''')
    sources=[SOURCE/'sbc/sbc.c',LOCAL/'decoder.c',LOCAL/'pcm_converter.c',LOCAL/'runtime.c',
             LOCAL/'memory_output.c',LOCAL/'owned_media.c',queue,LOCAL/'media_worker.c',LOCAL/'voice_media.c']
    commands,objects=[],[]
    for p in sources:
        obj=BUILD/(p.stem+'.o')
        extra=['-I'+str(LOCAL),'-I'+str((ROOT/converter['generated_header']).parent)]
        if p.name=='voice_media.c':extra+=['-DVOICE_MEDIA_CONVERT=1',
            '-Dvoice_extension_submit_frame=owned_media_submit_frame',
            '-Dvoice_extension_media_callback=owned_packet_parse',
            '-Dvoice_extension_media_api=owned_packet_api','-Dvoice_media_stats=owned_packet_stats']
        cmd=[compiler,*flags,*extra,'-c',str(p),'-o',str(obj)]
        run(cmd);commands.append(cmd);objects.append(str(obj))
    elf,flat=BUILD/'owned-armv6.elf',BUILD/'owned-armv6.bin'
    cmd=[compiler,'-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
         '-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'owned.map'),
         '-Wl,-T,'+str(linker),*objects,'-lgcc','-o',str(elf)]
    run(cmd);commands.append(cmd)
    undefined=run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    if undefined:raise ValueError('Undefined owned symbols: '+undefined)
    symbols={}
    for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
        parts=line.split()
        if len(parts)==3:symbols[parts[2]]={'address':int(parts[0],16),'type':parts[1]}
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    if 'Tag_CPU_arch: v6' not in attrs or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected owned ISA/runtime')
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    dependencies=[*sources,LOCAL/'media_queue.c',LOCAL/'memory_output.h',LOCAL/'decoder.h',
                  LOCAL/'pcm_converter.h',LOCAL/'media_queue.h',LOCAL/'media_worker.h',
                  ROOT/converter['generated_header'],ROOT/converter['coefficient_table'],
                  linker,ROOT/'scripts/build_native_owned_media.py']
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'load_base':BASE,
              'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),
              'flat_binary':str(flat.relative_to(ROOT)),'flat_binary_sha256':sha(flat),
              'flat_binary_bytes':flat.stat().st_size,'symbols':symbols,'commands':commands,
              'attributes':attrs,'segments':segments,
              'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in dependencies},
              'pcm_pages':[symbols['pcm'+str(i)]['address'] for i in range(4)],
              'pcm_slot_bytes':4096,'pcm_slots':4,'gather_page':symbols['gather']['address'],
              'payload_bytes':16384,'preallocated_stack_bytes':16384,
              'queue_derivative_only_changed_output_ready_function':True,
              'navigation_tts_output_imports_modified':False,
              'device_io':False,'device_install_candidate':False,
              'limitations':'Standalone SBC/FIR whole-packet owned PCM backend, not merged or installed. Existing queue source is retained; generated derivative only replaces its TTS ring readiness with private-buffer readiness. One producer owns experimental decoder/FIR/submit, at most15 frames per packet and4096 gather bytes. Native output requires original serialized actor/channel-list and allocation-boundary contracts, not cross-actor reservation/quiescence. Kernel worker/release wake support is linked but scheduling must be separately exercised. No actual native App/UI/SEP/SDP/phone/speaker/VPM acceptance or Google Maps.'}
    (BUILD/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str(BUILD/'manifest.json'),'flat_binary_bytes':flat.stat().st_size,
                      'device_io':False}))


if __name__=='__main__':main()
