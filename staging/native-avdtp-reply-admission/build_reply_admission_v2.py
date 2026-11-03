#!/usr/bin/env python3
"""Compile a private-ABI native TX/admission prototype, never install it."""
import sys,json,hashlib,subprocess,struct
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
LINK=0x08e00000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
    out=BASE/'build-v2';out.mkdir(exist_ok=False)
    sources=[ROOT/'native/music-endpoint/endpoint.c',ROOT/'native/avdtp-gate/gate.c',
             ROOT/'native/avdtp-policy/policy.c',BASE/'reply_admission_v2.c',ROOT/'native/avdtp-reply/stock-relocated.S']
    dependencies=[Path(__file__),*sources,ROOT/'native/music-endpoint/endpoint.h',ROOT/'native/avdtp-gate/gate.h',
                  ROOT/'native/avdtp-policy/policy.h',ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    hashes={rel(p):sha(p)for p in dependencies}
    snap=out/'source-snapshot';snap.mkdir()
    for i,p in enumerate(dependencies):(snap/f'{i:02d}-{p.name}').write_bytes(p.read_bytes())
    ld=out/'reply-admission.ld'
    ld.write_text('''ENTRY(nr_configuration_gate)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08e00000;
 .text : { *(.text .text.*) *(.rodata .rodata.*) } :code
 __code_end = .;
 . = ALIGN(4096); __bss_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
 __bss_end = .;
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
''')
    commands=[]
    def run(cmd):
        r=subprocess.run(cmd,text=True,capture_output=True)
        create(out/f'command-{len(commands):02d}.json',dict(command=cmd,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
        commands.append(cmd)
        assert r.returncode==0,r.stderr
        return r.stdout
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin',
           '-fno-stack-protector','-fno-pie','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
           '-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror']
    objects=[]
    for i,p in enumerate(sources):
        obj=out/f'{i:02d}-{p.stem}.o';objects.append(obj)
        run(['arm-linux-gnueabi-gcc',*flags,'-c',str(p),'-o',str(obj)])
    elf=out/'reply-admission-EMULATION-ONLY.elf';flat=out/'reply-admission.bin'
    run(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
         '-Wl,--no-undefined,--build-id=none,-Map='+str(out/'reply-admission.map'),'-Wl,-T,'+str(ld),
         *map(str,objects),'-lgcc','-o',str(elf)])
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    symbols={parts[2]:int(parts[0],16)for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines()
             if len(parts:=line.split())==3}
    assert flat.stat().st_size==symbols['__code_end']-LINK
    assert symbols['__bss_start']%4096==0 and symbols['__bss_end']-symbols['__bss_start']<4096
    stock=NativeImage();offset=symbols['stock_reply_relocated']-LINK
    assert flat.read_bytes()[offset:offset+16]==stock.read(0x5756ac,16)
    patch=bytes.fromhex('08b4024b9c4608bc6047c046')+struct.pack('<I',symbols['nr_reply_dispatch'])
    assert len(patch)==16
    assert all(sha(ROOT/p)==h for p,h in hashes.items())
    hashes[rel(ld)]=sha(ld)
    manifest=dict(all_passed=True,base=LINK,flat=rel(flat),flat_sha256=sha(flat),flat_bytes=flat.stat().st_size,
                  elf=rel(elf),elf_sha256=sha(elf),symbols=symbols,BSS_bytes=symbols['__bss_end']-symbols['__bss_start'],
                  source_sha256=hashes,patch=dict(address=0x5756ac,before_hex=stock.read(0x5756ac,16).hex(),after_hex=patch.hex()),
                  undefined_symbols=[],synthetic_link_address_not_device_allocation=True,
                  native_registration_or_real_media_admission_or_App_or_hardware=False,
                  guest_execution=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
    create(BASE/'build-v2.json',manifest)
    print(json.dumps(dict(all_passed=True,flat_bytes=manifest['flat_bytes'],BSS_bytes=manifest['BSS_bytes'],guest_execution=False,device_IO=False)))
if __name__=='__main__':main()
