#!/usr/bin/env python3
"""Build a bounded owned-PCM source prototype; no device installation."""
from datetime import datetime, timezone
import json
from build_native_sbc import ROOT, LOCAL, run, sha

BUILD = ROOT/'staging/native-memory-output'
BASE = 0x08600000
PCM_PAGES = [0x08604000+i*0x2000 for i in range(4)]


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    compiler, flags = baseline['commands'][0][0], baseline['commands'][0][1:-4]
    linker = BUILD/'output.ld'
    linker.write_text('''ENTRY(memory_output_submit)
SECTIONS {
 . = 0x08600000;
 .text : { KEEP(*(.output_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __output_code_end = .;
 ASSERT(__output_code_end <= 0x08602000, "output code exceeds two pages")
 . = 0x08602000;
 __output_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __output_state_end = .;
 ASSERT(__output_state_end <= 0x08602fc0, "output state exceeds guarded page")
 . = 0x08604000; .pcm0 (NOLOAD) : { *(.pcm0) }
 . = 0x08606000; .pcm1 (NOLOAD) : { *(.pcm1) }
 . = 0x08608000; .pcm2 (NOLOAD) : { *(.pcm2) }
 . = 0x0860a000; .pcm3 (NOLOAD) : { *(.pcm3) }
 /DISCARD/ : { *(.comment) *(.note*) }
}
''')
    sources = [LOCAL/'memory_output.c', LOCAL/'runtime.c']
    commands, objects = [], []
    for source in sources:
        obj = BUILD/(source.stem+'.o')
        command = [compiler, *flags, '-Wall', '-Wextra', '-c', str(source), '-o', str(obj)]
        run(command); commands.append(command); objects.append(str(obj))
    elf, flat = BUILD/'output-armv6.elf', BUILD/'output-armv6.bin'
    command = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
               '-nostdlib', '-static', '-no-pie',
               '-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'output.map'),
               '-Wl,-T,'+str(linker), *objects, '-lgcc', '-o', str(elf)]
    run(command); commands.append(command)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Undefined output symbols: '+undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3: symbols[parts[2]] = {'address': int(parts[0], 16), 'type': parts[1]}
    attrs = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attrs or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected output ISA/runtime')
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    if flat.stat().st_size > 8192: raise ValueError('Output code exceeds two pages')
    if [symbols['pcm'+str(i)]['address'] for i in range(4)] != PCM_PAGES:
        raise ValueError('Output guarded PCM page layout changed')
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'load_base': BASE,
              'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
              'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
              'flat_binary_bytes': flat.stat().st_size, 'symbols': symbols,
              'commands': commands, 'attributes': attrs, 'segments': segments,
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                               (*sources, LOCAL/'memory_output.h', linker,
                                ROOT/'scripts/build_native_memory_output.py')},
              'pcm_pages': PCM_PAGES, 'pcm_slot_bytes': 4096, 'pcm_slots': 4,
              'format': {'channels': 1, 'rate': 16000, 'bits': 16},
              'source_kind': 10, 'source_flags': 12, 'original_register': '0x270459',
              'original_reader': '0x48edf9', 'requires_loader_cleared_bss': True,
              'private_ticket_is_not_native_client_id': True,
              'source_channel_actor_and_list_exclusive_serialization_required': True,
              'pool_guard_is_admission_not_cross_actor_reservation': True,
              'post_selection_hook_installed': False,
              'native_callback_quiescence_module_unload_or_decoder_redirection_verified': False,
              'device_io': False, 'device_install_candidate': False,
              'limitations': 'Offline owned-PCM prototype with four static4096-byte buffers and private monotonic tickets. One native source is published at a time, original kind10/flags12 registration uses NULL metadata. Explicit guard and post-selector wrapper calls are required on a serialized actor controlling the channel list and native pool allocation boundary. Pool inspection is not reservation against other actors. Release state checks require reader return, native cleanup/prepared/method clear and source-list empty, but do not prove not-yet-entered callbacks are excluded across real tasks/IRQs or permit unload. No actual hook/message lifecycle/decoder-worker output redirection/capacity wakeup, accepted VPM/SEP/UI/phone/speaker/navigation coexistence. No device installation.'}
    (BUILD/'output.dis').write_text(run(['arm-linux-gnueabi-objdump', '-d', str(elf)]))
    (BUILD/'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'manifest': str(BUILD/'manifest.json'),
                      'flat_binary_bytes': flat.stat().st_size, 'device_io': False}))


if __name__ == '__main__':
    main()
