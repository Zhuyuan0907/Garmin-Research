#!/usr/bin/env python3
"""Build an emulator-only native event worker with a preallocated stack."""
from datetime import datetime, timezone
import json
from build_native_sbc import ROOT, LOCAL, run, sha

BUILD = ROOT/'staging/native-media-worker'


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    compiler, flags = baseline['commands'][0][0], baseline['commands'][0][1:-4]
    sources = [LOCAL/'media_queue.c', LOCAL/'media_worker.c', LOCAL/'runtime.c']
    linker = BUILD/'worker.ld'
    linker.write_text('''/* Emulator-only companion, not a DLLIMG or VPM. */
ENTRY(media_worker_init)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); payload PT_LOAD FLAGS(6); stack PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08300000;
 .text : { *(.text*) } :code
 .rodata : { KEEP(*(.queue_api)) KEEP(*(.worker_api)) *(.rodata*) } :code
 __queue_code_end = .;
 . = ALIGN(4096);
 __queue_state_start = .;
 .data : { *(.data*) } :state
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 __queue_state_end = .;
 . = ALIGN(4096)+4096;
 .queue_payload (NOLOAD) : { __queue_payload_start = .; *(.queue_payload) } :payload
 __queue_payload_end = .;
 . = ALIGN(4096)+4096;
 .worker_stack (NOLOAD) : { __worker_stack_start = .; *(.worker_stack) } :stack
 __worker_stack_end = .;
 ASSERT(__queue_payload_end-__queue_payload_start == 16384, "Payload size differs")
 ASSERT(__worker_stack_end-__worker_stack_start == 16384, "Stack size differs")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
''')
    objects, commands = [], []
    for source in sources:
        obj = BUILD/(source.stem+'.o')
        cmd = [compiler, *flags, '-c', str(source), '-o', str(obj)]
        run(cmd); commands.append(cmd); objects.append(str(obj))
    elf, flat = BUILD/'worker-armv6.elf', BUILD/'worker-armv6.bin'
    cmd = [compiler, '-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft',
           '-nostdlib', '-static', '-no-pie',
           '-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'worker.map'),
           '-Wl,-T,'+str(linker), *objects, '-lgcc', '-o', str(elf)]
    run(cmd); commands.append(cmd)
    undefined = run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    if undefined: raise ValueError('Undefined worker symbols: '+undefined)
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) == 3: symbols[parts[2]] = {'address': int(parts[0], 16), 'type': parts[1]}
    attrs = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    if 'Tag_CPU_arch: v6' not in attrs or 'INTERP' in segments or 'DYNAMIC' in segments:
        raise ValueError('Unexpected worker ISA/runtime')
    run(['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)])
    manifest = {'updated_utc': datetime.now(timezone.utc).isoformat(),
                'elf': str(elf.relative_to(ROOT)), 'elf_sha256': sha(elf),
                'flat_binary': str(flat.relative_to(ROOT)), 'flat_binary_sha256': sha(flat),
                'flat_binary_bytes': flat.stat().st_size, 'load_base': 0x08300000,
                'symbols': symbols, 'commands': commands, 'attributes': attrs, 'segments': segments,
                'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                                  [*sources, LOCAL/'media_queue.h', LOCAL/'media_worker.h', linker,
                                   ROOT/'scripts/build_native_media_worker.py']},
                'undefined_symbols': [], 'queue_slots': 4, 'packet_capacity_bytes': 4096,
                'payload_bytes': 16384, 'preallocated_stack_bytes': 16384,
                'conservative_pcm_free_bytes': 8961, 'linux_runtime_required': False,
                'kernel_context_builder': '0x358bf9', 'descriptor_registry': '0x2fbbbf',
                'event_post': '0x2fcf44', 'event_wait': '0x2fd035',
                'descriptor_word_1': 0, 'allocates_stack_or_task_wrapper': False,
                'device_io': False, 'device_install_candidate': False,
                'limitations': 'Standalone companion ELF, not merged into a DLLIMG/VPM. First initialization requires quiescence; only one boot is allowed. Stack/module are retained after shutdown. Consumer capacity notification must still be connected to the real audio consumer; navigation output ownership, cold PCM initialization, package acceptance, SEP/UI and hardware remain unverified.'}
    path = BUILD/'manifest.json'
    path.write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'manifest': str(path), 'preallocated_stack_bytes': 16384,
                      'device_io': False, 'device_install_candidate': False}))


if __name__ == '__main__': main()
