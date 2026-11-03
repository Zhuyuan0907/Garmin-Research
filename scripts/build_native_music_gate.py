#!/usr/bin/env python3
"""Build the exact-image preaccept wrapper; no installer or native binding."""
from datetime import datetime, timezone
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/native-music-gate'
BASE = 0x08d00000  # Synthetic placement, never an allocated device address.


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    linker = OUT / 'gate.ld'
    linker.write_text(f'''ENTRY(music_configuration_gate)
PHDRS {{ code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }}
SECTIONS {{
 . = {BASE:#x};
 .text : {{ *(.text .text.*) *(.rodata .rodata.*) }} :code
 __code_end = .;
 . = ALIGN(4096);
 __bss_start = .;
 .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }} :data
 __bss_end = .;
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    flags = ['-mcpu=arm1176jzf-s', '-marm', '-mfloat-abi=soft', '-Os',
        '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pie',
        '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
        '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror']
    sources = [ROOT/'native/avdtp-gate/gate.c', ROOT/'native/avdtp-policy/policy.c']
    objects = [OUT/'gate.o', OUT/'policy.o']
    elf, flat = OUT/'gate.elf', OUT/'gate.bin'
    commands = [['arm-linux-gnueabi-gcc', *flags, '-c', str(src), '-o', str(obj)]
        for src, obj in zip(sources, objects)]
    commands += [['arm-linux-gnueabi-gcc', '-mcpu=arm1176jzf-s', '-marm',
        '-mfloat-abi=soft', '-nostdlib', '-static', '-no-pie',
        '-Wl,--build-id=none,-Map='+str(OUT/'gate.map'), '-Wl,-T,'+str(linker),
        *map(str, objects), '-lgcc', '-o', str(elf)],
        ['arm-linux-gnueabi-objcopy', '-O', 'binary', str(elf), str(flat)]]
    for command in commands:
        run(command)
    assert not run(['arm-linux-gnueabi-nm', '-u', str(elf)]).strip()
    attributes = run(['arm-linux-gnueabi-readelf', '-A', str(elf)])
    segments = run(['arm-linux-gnueabi-readelf', '-l', str(elf)])
    assert 'Tag_CPU_arch: v6' in attributes
    assert 'INTERP' not in segments and 'DYNAMIC' not in segments and 'RWE' not in segments
    symbols = {p[2]:int(p[0], 16) for line in run(
        ['arm-linux-gnueabi-nm', '-n', str(elf)]).splitlines() if len(p := line.split()) == 3}
    assert len(flat.read_bytes()) == symbols['__code_end']-BASE
    assert symbols['__bss_start'] % 4096 == 0
    assert symbols['__bss_end']-symbols['__bss_start'] == 12
    deps = [Path(__file__), *sources, ROOT/'native/avdtp-gate/gate.h',
        ROOT/'native/avdtp-policy/policy.h', linker,
        ROOT/'sources/music-policy-reference/bluez-avdtp.h',
        ROOT/'sources/music-policy-reference/manifest.json']
    manifest = {
        'updated_utc':datetime.now(timezone.utc).isoformat(), 'base':BASE,
        'synthetic_link_address_not_device_allocation':True,
        'flat':str(flat.relative_to(ROOT)), 'flat_sha256':sha(flat),
        'flat_bytes':flat.stat().st_size, 'elf':str(elf.relative_to(ROOT)),
        'elf_sha256':sha(elf), 'symbols':symbols,
        'binding_bytes':12, 'code_RX_BSS_RW_separate_pages':True,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'commands':commands, 'attributes':attributes, 'segments':segments,
        'unresolved_symbols':[], 'Linux_runtime_dependencies':False,
        'stock_configuration_handler':0x574acc, 'stock_reply_helper':0x5756ac,
        'scope':'Compiled preaccept wrapper for exact HWID1352 8.00 MAIN. Caller invokes it under native AVDTP lock with pinned registered descriptors/capability pointers/callbacks. Claimed music endpoints require MediaTransport and advertised-subset audio/SBC. Reconfiguration for a claimed endpoint is deliberately rejected. Valid supported SetConfiguration and unclaimed valid endpoints enter the unchanged stock handler. Rejection uses the unchanged stock reply helper before state/callback/channel reservation. No native dispatcher binding, actual SEP/SDP registration, module installation/unload protocol, media callback or DAC/UI proof.',
        'pointer_allocation_lifetime_lock_and_ownership_are_caller_obligations':True,
        'device_io':False, 'firmware_modified':False, 'device_install_candidate':False,
    }
    (OUT/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),
        'code_bytes':manifest['flat_bytes'], 'binding_bytes':12,
        'ARM':'v6', 'device_install_candidate':False}))


if __name__ == '__main__':
    main()
