#!/usr/bin/env python3
"""Build owned full-duplex bulk adapter; no real host backend or installer."""
from datetime import datetime,timezone
import json
from pathlib import Path
from build_native_aoa import ROOT,LOCAL,run,sha
OUT=ROOT/'staging/native-aoa-bulk';BASE=0x08800000
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'usb_bulk.ld';linker.write_text(f'''ENTRY(aoa_bulk_init)
SECTIONS {{ . = {BASE:#x}; .text : {{ *(.text .text.*) *(.rodata .rodata.*) }}
__code_end = .; .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }}
/DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }} }}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
      '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
      '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror']
    obj=OUT/'usb_bulk.o';elf=OUT/'usb_bulk.elf';flat=OUT/'usb_bulk.bin'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(LOCAL/'usb_bulk.c'),'-o',str(obj)],
      ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
       '-Wl,--build-id=none,-Map='+str(OUT/'usb_bulk.map'),'-Wl,-T,'+str(linker),str(obj),'-lgcc','-o',str(elf)],
      ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for command in commands:run(command)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)]);segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines() if len(p:=line.split())==3}
    assert flat.stat().st_size==symbols['__code_end']-BASE
    deps=[LOCAL/'usb_bulk.c',LOCAL/'usb_bulk.h',LOCAL/'usb_config.h',LOCAL/'aoa.h',Path(__file__),ROOT/'scripts/build_native_aoa.py',linker]
    m={'updated_utc':datetime.now(timezone.utc).isoformat(),'base':BASE,'synthetic_link_address_not_device_allocation':True,
      'flat':str(flat.relative_to(ROOT)),'flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,
      'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),'symbols':symbols,'commands':commands,
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},'attributes':attrs,'segments':segments,
      'unresolved_symbols':[],'Linux_runtime_dependencies':False,'device_io':False,
      'firmware_modified':False,'device_install_candidate':False,
      'scope':'New fixed RX/TX4096-byte owned full-duplex bulk adapter with terminal borrow contract. '
        'Short OUT retries remaining bytes only, short/zero IN valid; RX consumption gates reuse. '
        'Cancel/disconnect/error/timeouts retain both outstanding borrows until terminal callbacks. '
        'No real controller/USB/bus, cache maintenance, ZLP policy, framing/TLS/channels/phone/UI/installation. '
        'Single actor, one child, fresh/quiescent context and same-port unique session are caller contracts.'}
    (OUT/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),'code_bytes':m['flat_bytes'],'device_io':False}))
if __name__=='__main__':main()
