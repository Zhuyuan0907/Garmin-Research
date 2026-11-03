#!/usr/bin/env python3
"""Build the custom endpoint provider with frozen gate/policy sources."""
from datetime import datetime,timezone
import json
from pathlib import Path
from build_native_music_gate import run,sha,ROOT

OUT=ROOT/'staging/native-music-endpoint'
BASE=0x08e00000  # Offline-only placement, not an allocated device address.


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'endpoint.ld'
    linker.write_text(f'''ENTRY(music_endpoint_prepare)
PHDRS {{ code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }}
SECTIONS {{
 . = {BASE:#x};
 .text : {{ *(.text .text.*) *(.rodata .rodata.*) }} :code
 __code_end = .;
 . = ALIGN(4096); __bss_start = .;
 .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }} :data
 __bss_end = .;
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-Wall','-Wextra','-Werror']
    sources=[ROOT/'native/music-endpoint/endpoint.c',ROOT/'native/avdtp-gate/gate.c',
        ROOT/'native/avdtp-policy/policy.c']
    objects=[OUT/(p.stem+'.o') for p in sources]
    elf,flat=OUT/'endpoint.elf',OUT/'endpoint.bin'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(src),'-o',str(obj)] for src,obj in zip(sources,objects)]
    commands += [['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft',
        '-nostdlib','-static','-no-pie','-Wl,--build-id=none,-Map='+str(OUT/'endpoint.map'),
        '-Wl,-T,'+str(linker),*map(str,objects),'-lgcc','-o',str(elf)],
        ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for c in commands:run(c)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attributes=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attributes and all(k not in segments for k in ['RWE','INTERP','DYNAMIC'])
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines()
        if len(p:=line.split())==3}
    assert flat.stat().st_size==symbols['__code_end']-BASE
    assert symbols['__bss_start']%4096==0 and symbols['__bss_end']-symbols['__bss_start']==28
    deps=[Path(__file__),ROOT/'scripts/build_native_music_gate.py',linker,*sources,
        ROOT/'native/music-endpoint/endpoint.h',ROOT/'native/avdtp-gate/gate.h',ROOT/'native/avdtp-policy/policy.h']
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'base':BASE,
        'synthetic_link_address_not_device_allocation':True,
        'flat':str(flat.relative_to(ROOT)),'flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,
        'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),'symbols':symbols,'BSS_bytes':28,
        'code_RX_BSS_RW_separate_pages':True,'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'commands':commands,'attributes':attributes,'segments':segments,'unresolved_symbols':[],
        'Linux_runtime_dependencies':False,'original_endpoint_registration_API_recovered':False,
        'scope':'Custom compiled private-ABI endpoint provider, not recovered stock registration API. Original AVDTP/SDP boot initialization required. Native mutex protects creation, populated descriptor precedes state1, compiled preaccept gate claims endpoint, module-static44.1/48k SBC capabilities. Separate publication calls original Audio Sink SDP enable without nesting locks. Owned capability entry calls stock six-argument serializer with flags0x11, excluding the original GetCapabilities fixed HeaderCompression offer; normal unowned endpoints and negotiated GetConfiguration retain stock behavior. Caller installs dispatch, serializes publication, exclusively owns Audio Sink record and pins callback/module until reboot. No unregister/unload implementation, concurrency/device acceptance or physical proof.',
        'device_io':False,'firmware_modified':False,'device_install_candidate':False}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),
        'code_bytes':manifest['flat_bytes'],'BSS_bytes':28,'device_install_candidate':False}))


if __name__=='__main__':main()
