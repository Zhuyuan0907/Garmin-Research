#!/usr/bin/env python3
"""Compile bounded ARMv6 framing, no TLS/host/installer or Linux dependencies."""
from datetime import datetime,timezone
import json
from pathlib import Path
from build_native_aoa import ROOT,run,sha
LOCAL=ROOT/'native/aa-framing';OUT=ROOT/'staging/native-aa-framing';BASE=0x08900000
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    linker=OUT/'framing.ld';linker.write_text(f'''ENTRY(aa_frame_init)
SECTIONS {{ . = {BASE:#x}; .text : {{ *(.text .text.*) *(.rodata .rodata.*) }}
__code_end = .; .bss (NOLOAD) : {{ *(.bss .bss.*) *(COMMON) }}
/DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }} }}
''')
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
      '-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
      '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror']
    obj=OUT/'framing.o';elf=OUT/'framing.elf';flat=OUT/'framing.bin'
    commands=[['arm-linux-gnueabi-gcc',*flags,'-c',str(LOCAL/'framing.c'),'-o',str(obj)],
      ['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
       '-Wl,--build-id=none,-Map='+str(OUT/'framing.map'),'-Wl,-T,'+str(linker),str(obj),'-lgcc','-o',str(elf)],
      ['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]]
    for cmd in commands:run(cmd)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)]);segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    symbols={p[2]:int(p[0],16) for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines() if len(p:=line.split())==3}
    assert flat.stat().st_size==symbols['__code_end']-BASE
    deps=[LOCAL/'framing.c',LOCAL/'framing.h',LOCAL/'COPYING',LOCAL/'provenance.json',Path(__file__),ROOT/'scripts/build_native_aoa.py',linker]
    provenance=json.loads((LOCAL/'provenance.json').read_text())
    for name,want in provenance['upstream_sources'].items():assert sha(ROOT/name)==want;deps.append(ROOT/name)
    m={'updated_utc':datetime.now(timezone.utc).isoformat(),'base':BASE,'synthetic_link_address_not_device_allocation':True,
      'flat':str(flat.relative_to(ROOT)),'flat_sha256':sha(flat),'flat_bytes':flat.stat().st_size,
      'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),'symbols':symbols,'commands':commands,
      'source_sha256':{str(p.resolve().relative_to(ROOT)):sha(p) for p in deps},'attributes':attrs,'segments':segments,
      'license':'GPL-3.0-or-later','upstream_provenance':provenance,
      'unresolved_symbols':[],'Linux_runtime_dependencies':False,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'Native bounded incremental wire parser, single-frame encoder and plaintext message reassembly. '
        'Opaque encrypted frames accepted by parser only; plaintext assembler refuses ciphertext without mutation. '
        'No fake decrypt, crypto, TLS/authentication, automatic outbound fragmentation, channel/Protobuf/H264/UI, '
        'real USB/current phone/Garmin loaded execution or installation. Caller-provided real memory pools, '
        'single actor/unique session/unborrowed init/nonoverlapping storage remain contracts; no real RAM allocation verified.'}
    (OUT/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),'code_bytes':m['flat_bytes'],
      'dependencies':len(m['source_sha256']),'device_io':False}))
if __name__=='__main__':main()
