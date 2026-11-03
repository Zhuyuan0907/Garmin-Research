#!/usr/bin/env python3
"""Build a standalone queue ELF to integrate with preserving voices offline."""
from datetime import datetime, timezone
import json
from build_native_sbc import ROOT, LOCAL, run, sha

BUILD = ROOT/'staging/native-media-queue'


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    compiler = baseline['commands'][0][0]
    flags = baseline['commands'][0][1:-4]
    sources = [LOCAL/'media_queue.c', LOCAL/'runtime.c']
    linker = BUILD/'queue.ld'
    linker.write_text('''/* Emulator-only standalone companion, not a DLLIMG. */
ENTRY(media_queue_init)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); payload PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08300000;
 .text : { *(.text*) } :code
 .rodata : { KEEP(*(.queue_api)) *(.rodata*) } :code
 __queue_code_end = .;
 . = ALIGN(4096);
 __queue_state_start = .;
 .data : { *(.data*) } :state
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 __queue_state_end = .;
 . = ALIGN(4096)+4096;
 .queue_payload (NOLOAD) : { __queue_payload_start = .; *(.queue_payload) } :payload
 __queue_payload_end = .;
 ASSERT(__queue_payload_end-__queue_payload_start == 16384, "Queue payload size differs")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
''')
    objects, commands = [], []
    for source in sources:
        obj = BUILD/(source.stem+'.o')
        command = [compiler, *flags, '-c', str(source), '-o', str(obj)]
        run(command); objects.append(str(obj)); commands.append(command)
    elf, flat = BUILD/'queue-armv6.elf', BUILD/'queue-armv6.bin'
    command = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
               '-nostdlib', '-static', '-no-pie',
               '-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'queue.map'),
               '-Wl,-T,'+str(linker), *objects, '-lgcc', '-o', str(elf)]
    run(command); commands.append(command)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Unresolved queue symbols: '+undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3: symbols[parts[2]] = {'address': int(parts[0], 16), 'type': parts[1]}
    attributes = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attributes or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected queue target ISA/runtime')
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    manifest = {'updated_utc': datetime.now(timezone.utc).isoformat(),
                'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
                'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
                'flat_binary_bytes': flat.stat().st_size, 'load_base': 0x08300000,
                'symbols': symbols, 'commands': commands, 'attributes': attributes,
                'segments': segments, 'undefined_symbols': [],
                'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                                  [*sources, LOCAL/'media_queue.h', linker,
                                   ROOT/'scripts/build_native_media_queue.py']},
                'queue_slots': 4, 'packet_capacity_bytes': 4096,
                'payload_bytes': 16384, 'conservative_pcm_free_bytes': 8961,
                'irq_save': '0x21b6cc', 'irq_restore': '0x21b6dc',
                'payload_initialized_before_publication': True,
                'linux_runtime_required': False, 'device_io': False,
                'device_install_candidate': False,
                'limitations': 'Standalone companion ELF for emulation, not merged into a VPM or installed. Caller supplies compiled preserving media and reset functions; first initialization requires quiescence. Single-core metadata protection uses exact stock IRQ functions; payload copies and decoding run outside critical sections. One producer of the initialized stock PCM ring is an unverified real-device requirement. OS task/event wake, real navigation ownership, package acceptance, SEP registration and hardware playback are not provided.'}
    path = BUILD/'manifest.json'
    path.write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'manifest': str(path), 'queue_slots': 4, 'payload_bytes': 16384,
                      'device_io': False, 'device_install_candidate': False}))


if __name__ == '__main__': main()
