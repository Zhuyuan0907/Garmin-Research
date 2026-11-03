#!/usr/bin/env python3
"""Build native source coordinator worker/events. Virtual imports; no install."""
from datetime import datetime, timezone
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from build_native_sbc import LOCAL, run, sha
from emulate_native_memory_notice import check_manifest

BUILD=ROOT/'staging/native-source-worker'
BASE=0x08c00000


def main():
    owned_path=ROOT/'staging/native-owned-media/manifest.json'
    coord_path=ROOT/'staging/native-media-coordinator/manifest.json'
    owned,coord=map(check_manifest,(owned_path,coord_path))
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    displaced=stock.read(0x3b9dfc,10)
    assert displaced.hex()=='f0b5050000202e0087b0'
    assert [(i.mnemonic,i.op_str) for i in md.disasm(displaced,0x3b9dfc)]==[
        ('push','{r4, r5, r6, r7, lr}'),('movs','r5, r0'),('movs','r0, #0'),
        ('movs','r6, r5'),('sub','sp, #0x1c')]
    consume=owned['symbols']['owned_media_consume']['address']
    flat_owned=(ROOT/owned['flat_binary']).read_bytes()
    raw=flat_owned[consume-owned['load_base']:consume-owned['load_base']+8]
    assert raw.hex()=='f3472de90050a0e1'
    assert [(i.mnemonic,i.op_str) for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(raw,consume)]==[
        ('push','{r0, r1, r4, r5, r6, r7, r8, sb, sl, lr}'),('mov','r5, r0')]
    BUILD.mkdir(parents=True,exist_ok=True)
    header=BUILD/'source_worker_imports.h'
    header.write_text('#define OWNED_CONSUME_RESUME '+hex(consume+8)+'\n')
    imports={n:coord['symbols'][n]['address'] for n in
        ('media_coordinator_init','media_coordinator_pump','media_coordinator_cancel','coordinator_state')}
    imports.update({n:owned['symbols'][n]['address'] for n in
        ('owned_media_control','memory_output_control')})
    linker=BUILD/'source_worker.ld'
    linker.write_text('ENTRY(source_worker_boot)\n'+
        '\n'.join('PROVIDE('+n+' = '+hex(a)+');' for n,a in imports.items())+'''
SECTIONS {
 . = 0x08c00000;
 .text : { KEEP(*(.source_worker_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __source_code_end = .;
 ASSERT(__source_code_end <= 0x08c02000, "source code exceeds two pages")
 . = 0x08c02000;
 __source_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __source_state_end = .;
 ASSERT(__source_state_end <= 0x08c02fc0, "source state exceeds guarded page")
 . = 0x08c04000;
 __source_stack_start = .;
 .source_stack (NOLOAD) : { *(.source_stack) }
 __source_stack_end = .;
 ASSERT(__source_stack_end == 0x08c08000, "source stack extent differs")
 /DISCARD/ : { *(.comment) *(.note*) }
}
''')
    compiler='arm-linux-gnueabi-gcc'
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-Wall','-Wextra','-Werror','-I'+str(LOCAL),'-I'+str(BUILD)]
    sources=(LOCAL/'source_worker.c',LOCAL/'source_event_hooks.S');commands=[];objects=[]
    for source in sources:
        obj=BUILD/(source.stem+'.o')
        command=[compiler,*flags,'-c',str(source),'-o',str(obj)]
        run(command);commands.append(command);objects.append(str(obj))
    elf,flat=BUILD/'source-worker-armv6.elf',BUILD/'source-worker-armv6.bin'
    command=[compiler,'-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib',
        '-static','-no-pie','-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'source_worker.map'),
        '-Wl,-T,'+str(linker),*objects,'-o',str(elf)]
    run(command);commands.append(command)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    symbols={}
    for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
        p=line.split()
        if len(p)==3:symbols[p[2]]={'address':int(p[0],16),'type':p[1]}
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    assert flat.stat().st_size<=8192
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'load_base':BASE,'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),
        'flat_binary':str(flat.relative_to(ROOT)),'flat_binary_sha256':sha(flat),
        'flat_binary_bytes':flat.stat().st_size,'symbols':symbols,'commands':commands,
        'attributes':attrs,'segments':segments,'absolute_private_imports':imports,
        'owned_elf_sha256_required':owned['elf_sha256'],'coordinator_elf_sha256_required':coord['elf_sha256'],
        'publication_entry':consume,'publication_displaced_hex':raw.hex(),'publication_resume':consume+8,
        'completion_entry':0x3b9dfc,'completion_displaced_hex':displaced.hex(),'completion_resume':0x3b9e07,
        'preallocated_stack_bytes':16384,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in
            (*sources,LOCAL/'memory_output.h',header,linker,Path(__file__),owned_path,coord_path)},
        'device_io':False,'device_install_candidate':False,
        'limitations':'Offline virtual private imports with emulator-only entry patches. Original kernel task/event integration; whole-packet after-return publication and full source-completion after-return notifications; fifth argument/result preserved. Durable private pending events persist through synchronous native calls. Modules/stack pinned; no accepted package/native UI/actual SEP/phone/speaker/IRQ/DAC/navigation/Android Auto/Google Maps or safe unload. Inherited arbitration/power/heap/physical inventory/peripheral frame fixtures remain; not seamless/realtime infinite playback.'}
    (BUILD/'source_worker.dis').write_text(run(['arm-linux-gnueabi-objdump','-d',str(elf)]))
    (BUILD/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str(BUILD/'manifest.json'),'bytes':flat.stat().st_size,'device_io':False}))


if __name__=='__main__':main()
