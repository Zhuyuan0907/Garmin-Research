#!/usr/bin/env python3
"""Build USB2 descriptor selection/configuration, preserving old AOA artifacts."""
from datetime import datetime,timezone
import json
from pathlib import Path
from build_native_aoa import ROOT,LOCAL,run,sha
OUT=ROOT/'staging/native-aoa-config'
BASE=0x08700000

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'usb_config.ld';linker.write_text(f'''ENTRY(aoa_usb_parse)
SECTIONS {{ . = {BASE:#x}; .text : {{ *(.text .text.*) *(.rodata .rodata.*) }}
__code_end = .; .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }}
/DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }} }}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
      '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
      '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror']
    elf=OUT/'usb_config.elf';flat=OUT/'usb_config.bin';obj=OUT/'usb_config.o'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(LOCAL/'usb_config.c'),'-o',str(obj)],
      ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
       '-Wl,--build-id=none,-Map='+str(OUT/'usb_config.map'),'-Wl,-T,'+str(linker),str(obj),'-lgcc','-o',str(elf)],
      ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for command in commands:run(command)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)]);segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines() if len(p:=line.split())==3}
    assert flat.stat().st_size==symbols['__code_end']-BASE
    primary=ROOT/'sources/native-aoa/source-snapshots.json';sources=json.loads(primary.read_text())
    for row in sources['files']:assert sha(ROOT/row['path'])==row['sha256']
    deps=[LOCAL/'usb_config.c',LOCAL/'usb_config.h',LOCAL/'aoa.h',Path(__file__),
          ROOT/'scripts/build_native_aoa.py',linker,primary]+[ROOT/row['path'] for row in sources['files']]
    m={'updated_utc':datetime.now(timezone.utc).isoformat(),'base':BASE,'synthetic_link_address_not_device_allocation':True,
      'flat':str(flat.relative_to(ROOT)),'flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,
      'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),'symbols':symbols,'commands':commands,
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},'attributes':attrs,'segments':segments,
      'unresolved_symbols':[],'Linux_runtime_dependencies':False,'device_io':False,
      'firmware_modified':False,'device_install_candidate':False,
      'scope':'New bounded USB2 FS/HS configuration parser and SET_CONFIGURATION child context. '
        'AOA FF/FF/00 default-alt interface only, excludes ADB/other interfaces, rejects ambiguity '
        'and malformed descriptors, copies selected plan. Config transfer preserves borrowed setup '
        'until terminal completion/cancel ack. No actual USB host, descriptor enumeration requests, '
        'interface ownership, bulk data transfer, current Pixel, TLS/channels/UI/video/audio. '
        'Context freshness/single actor/one child/same physical port binding are caller contracts.'}
    (OUT/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),'code_bytes':m['flat_bytes'],'device_io':False}))
if __name__=='__main__':main()
