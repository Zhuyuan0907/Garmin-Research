#!/usr/bin/env python3
"""Compile source cancellation/next-block coordinator; no device install."""
from datetime import datetime, timezone
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from build_native_sbc import LOCAL, run, sha
from emulate_native_memory_notice import check_manifest

BUILD=ROOT/'staging/native-media-coordinator'
BASE=0x08b00000


def main():
    owned_path=ROOT/'staging/native-owned-media/manifest.json'
    owned=check_manifest(owned_path)
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    trace=list(md.disasm(stock.read(0x277674,34),0x277674))
    assert [(i.address,i.op_str) for i in trace if i.mnemonic=='bl']==[
        (0x27767e,'#0x3009a0'),(0x277686,'#0x277596'),(0x27768e,'#0x3008b0')]
    assert stock.word(0x358d34)==0xf09094 and stock.word(0x358d38)==0xf09090
    BUILD.mkdir(parents=True,exist_ok=True)
    names=('memory_output_control','memory_output_slots','memory_output_register',
           'memory_output_selection_guard','owned_media_control','owned_media_next',
           'owned_media_release','media_queue_stop')
    imports={n:owned['symbols'][n]['address'] for n in names}
    linker=BUILD/'coordinator.ld'
    linker.write_text('ENTRY(media_coordinator_init)\n'+
        '\n'.join('PROVIDE('+n+' = '+hex(a)+');' for n,a in imports.items())+'''
SECTIONS {
 . = 0x08b00000;
 .text : { KEEP(*(.coordinator_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __coordinator_code_end = .;
 ASSERT(__coordinator_code_end <= 0x08b02000, "coordinator code exceeds two pages")
 . = 0x08b02000;
 __coordinator_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __coordinator_state_end = .;
 ASSERT(__coordinator_state_end <= 0x08b02fc0, "coordinator state exceeds guarded page")
 /DISCARD/ : { *(.comment) *(.note*) }
}
''')
    compiler='arm-linux-gnueabi-gcc';source=LOCAL/'media_coordinator.c'
    flags=['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-Wall','-Wextra','-Werror','-I'+str(LOCAL)]
    obj=BUILD/'coordinator.o';commands=[]
    command=[compiler,*flags,'-c',str(source),'-o',str(obj)];run(command);commands.append(command)
    elf,flat=BUILD/'coordinator-armv6.elf',BUILD/'coordinator-armv6.bin'
    command=[compiler,'-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib',
        '-static','-no-pie','-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'coordinator.map'),
        '-Wl,-T,'+str(linker),str(obj),'-o',str(elf)]
    run(command);commands.append(command)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    symbols={}
    for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
        parts=line.split()
        if len(parts)==3:symbols[parts[2]]={'address':int(parts[0],16),'type':parts[1]}
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
        'owned_elf_sha256_required':owned['elf_sha256'],
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in
            (source,LOCAL/'memory_output.h',linker,Path(__file__),owned_path)},
        'original_remove_wrapper':'0x277674','original_queue_mutex_offset':'0x38',
        'original_remove_body':'0x277596','original_current_tcb_query':'0x358d24',
        'device_io':False,'device_install_candidate':False,
        'limitations':'Offline exact private owned-media ABI at virtual addresses. One actor captured from stock current-TCB helper owns pump/cancel. Pump selects/releases/registers/starts finite published PCM via stock source requests and frozen before-START reader hook. Cancel stops synthetic producer queue, waits owned producer idle/native cleanup, holds private native_calls through entire original mutex/list removal then owned-release; never-selected READY PCM registers/removes without reads to use characterized QUEUED release. Caller still polls pump; no autonomous coordinator worker/events/timer, infinite stream, global reservation/future callback quiescence or safe unload. Register/start failures retain state for reconciliation, not fully recovered. No actual loader/App/UI/SEP/SDP/phone/speaker/navigation/DAC/DMA/IRQ/Android Auto/Google Maps or installation.'}
    (BUILD/'coordinator.dis').write_text(run(['arm-linux-gnueabi-objdump','-d',str(elf)]))
    (BUILD/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str(BUILD/'manifest.json'),'flat_binary_bytes':flat.stat().st_size,
                      'device_io':False}))


if __name__=='__main__':main()
