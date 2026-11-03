#!/usr/bin/env python3
"""Build a freestanding AOA negotiation core; synthetic link address, no install."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/native-aoa-host'
LOCAL=ROOT/'native/aoa-prototype'
BASE=0x08600000  # emulator-only; no claim this RAM is available on Garmin

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(command):
    return subprocess.run(command,check=True,capture_output=True,text=True).stdout

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'aoa.ld'
    linker.write_text(f'''ENTRY(aoa_init)
SECTIONS {{
 . = {BASE:#x};
 .text : {{ *(.text .text.*) *(.rodata .rodata.*) }}
 __code_end = .;
 .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }}
 /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }}
}}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
      '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
      '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
      '-Wall','-Wextra','-Werror']
    obj=OUT/'aoa.o'; elf=OUT/'aoa.elf'; flat=OUT/'aoa.bin'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(LOCAL/'aoa.c'),'-o',str(obj)],
      ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft',
       '-nostdlib','-static','-no-pie','-Wl,--build-id=none,-Map='+str(OUT/'aoa.map'),
       '-Wl,-T,'+str(linker),str(obj),'-lgcc','-o',str(elf)],
      ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for c in commands:run(c)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines()
             if len(p:=line.split())==3}
    assert len(flat.read_bytes())==symbols['__code_end']-BASE
    paths=[LOCAL/'aoa.c',LOCAL/'aoa.h',linker,Path(__file__)]
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),
      'base':BASE,'synthetic_link_address_not_device_allocation':True,
      'flat':'staging/native-aoa-host/aoa.bin','flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,
      'elf':'staging/native-aoa-host/aoa.elf','elf_sha256':sha(elf),'symbols':symbols,
      'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in paths},
      'commands':commands,'attributes':attrs,'segments':segments,
      'unresolved_symbols':[],'Linux_runtime_dependencies':False,
      'protocol_references':['https://source.android.com/docs/core/interaction/accessories/aoa',
        'https://source.android.com/docs/core/interaction/accessories/aoa2'],
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'New bounded AOA51/52/53 negotiation core. Controller borrows owned buffers, '
        'single actor, terminal completion/cancel ack required. Accessory ID recognition only; '
        'no USB controller/backend, configuration/interface/bulk transfer, TLS, AA channels, '
        'video, native UI or phone validation. Only protocol1/2 supported; session IDs must never '
        'be reused with outstanding callbacks. No real-time performance or Garmin RAM placement claim.'}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':'staging/native-aoa-host/manifest.json',
      'code_bytes':manifest['flat_bytes'],'ARM':'v6','device_install_candidate':False}))

if __name__=='__main__':main()
