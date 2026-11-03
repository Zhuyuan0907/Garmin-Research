#!/usr/bin/env python3
"""Build an ARMv6 raw-notice observer prototype; do not install a hook."""
from datetime import datetime, timezone
import json
from build_native_sbc import ROOT, LOCAL, run, sha

BUILD = ROOT/'staging/native-memory-notice'
BASE = 0x08500000


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    compiler, flags = baseline['commands'][0][0], baseline['commands'][0][1:-4]
    linker = BUILD/'notice.ld'
    linker.write_text('''ENTRY(memory_notice_dispatch)
SECTIONS {
 . = 0x08500000;
 .text : { KEEP(*(.notice_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __notice_code_end = .;
 ASSERT(__notice_code_end <= 0x08501000, "observer code exceeds page")
 . = 0x08501000;
 __notice_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __notice_state_end = .;
 ASSERT(__notice_state_end <= 0x08501fc0, "observer state exceeds guarded page")
 /DISCARD/ : { *(.comment) *(.note*) }
}
''')
    sources = [LOCAL/'memory_notice_observer.c', LOCAL/'runtime.c']
    objects, commands = [], []
    for source in sources:
        obj = BUILD/(source.stem+'.o')
        command = [compiler, *flags, '-c', str(source), '-o', str(obj)]
        run(command); commands.append(command); objects.append(str(obj))
    elf, flat = BUILD/'notice-armv6.elf', BUILD/'notice-armv6.bin'
    command = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
               '-nostdlib', '-static', '-no-pie',
               '-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'notice.map'),
               '-Wl,-T,'+str(linker), *objects, '-lgcc', '-o', str(elf)]
    run(command); commands.append(command)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Undefined observer symbols: '+undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3: symbols[parts[2]] = {'address': int(parts[0], 16), 'type': parts[1]}
    attrs = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    # .ARM.attributes must remain available to audit the actual compiled ISA.
    if 'Tag_CPU_arch: v6' not in attrs: raise ValueError('Observer is not ARMv6')
    if 'INTERP' in segments or 'DYNAMIC' in segments: raise ValueError('Observer needs OS runtime')
    disassembly = run(['arm-linux-gnueabi-objdump', '-d', str(elf)])
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    if flat.stat().st_size > 4096: raise ValueError('Observer code exceeds guarded page')
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'load_base': BASE,
              'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
              'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
              'flat_binary_bytes': flat.stat().st_size, 'symbols': symbols,
              'commands': commands, 'attributes': attrs, 'segments': segments,
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                               (*sources, linker, ROOT/'scripts/build_native_memory_notice.py')},
              'stock_notice_dispatcher': '0x455b65', 'raw_notice_bytes': 20, 'journal_slots': 4,
              'uses_original_irq_save_restore': True, 'installed_hook': False,
              'pcm_recycling_or_native_client_registration_implemented': False,
              'device_io': False, 'device_install_candidate': False,
              'limitations': 'Standalone ARMv6 observer prototype, not merged into VPM or installed. Requires loader-cleared BSS and valid20-byte raw report frames at the original task interface. Always forwards original dispatcher/control and preserves its return; copies only configured channel/events to a bounded journal. Configuration epochs do not identify source stream generations. Disarm is not module/source callback quiescence. Journal overflow does not permit safe PCM recycle. Actual hook installation, whole native client dispatch, scheduling/lifetime, audio adapter/decoder/SEP/UI/phone/speaker and accepted package loading are unverified.'}
    (BUILD/'notice.dis').write_text(disassembly)
    (BUILD/'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'manifest': str(BUILD/'manifest.json'),
                      'flat_binary_bytes': flat.stat().st_size, 'device_io': False}))


if __name__ == '__main__':
    main()
