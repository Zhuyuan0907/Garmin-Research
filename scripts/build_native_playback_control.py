#!/usr/bin/env python3
"""Build an exact-version before-START hook/rearm prototype; no installation."""
from datetime import datetime, timezone
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from build_native_sbc import LOCAL, run, sha
from emulate_native_memory_notice import check_manifest

BUILD = ROOT/'staging/native-playback-control'
BASE = 0x08a00000


def main():
    owned_path = ROOT/'staging/native-owned-media/manifest.json'
    owned = check_manifest(owned_path)
    stock = NativeImage()
    raw = stock.read(0x2f998e, 10)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    expected = [('push', '{r4, r5, lr}'), ('movs', 'r2, r0'), ('movs', 'r5, #0'),
                ('ldrsb', 'r0, [r2, r5]'), ('movs', 'r1, #0xff')]
    assert [(i.mnemonic, i.op_str) for i in md.disasm(raw, 0x2f998e)] == expected
    assert raw.hex() == '30b5020000255057ff21'
    BUILD.mkdir(parents=True, exist_ok=True)
    header = BUILD/'playback_imports.h'
    header.write_text('static const uint32_t playback_pcm_pages[4] = {'+
                      ','.join(hex(p)+'u' for p in owned['pcm_pages'])+'};\n')
    imports = {name: owned['symbols'][name]['address'] for name in
               ('memory_output_control', 'memory_output_slots', 'memory_output_after_selection')}
    linker = BUILD/'playback.ld'
    linker.write_text('ENTRY(playback_callback_hook)\n'+
        '\n'.join('PROVIDE('+n+' = '+hex(a)+');' for n,a in imports.items())+'''
SECTIONS {
 . = 0x08a00000;
 .text : { KEEP(*(.playback_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __playback_code_end = .;
 ASSERT(__playback_code_end <= 0x08a02000, "playback code exceeds two pages")
 . = 0x08a02000;
 __playback_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __playback_state_end = .;
 ASSERT(__playback_state_end <= 0x08a02fc0, "playback state exceeds guarded page")
 /DISCARD/ : { *(.comment) *(.note*) }
}
''')
    compiler = 'arm-linux-gnueabi-gcc'
    flags = ['-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
        '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
        '-Wall','-Wextra','-Werror','-I'+str(LOCAL),'-I'+str(BUILD)]
    sources = [LOCAL/'playback_control.c', LOCAL/'playback_hook.S']
    commands, objects = [], []
    for source in sources:
        obj = BUILD/(source.stem+'.o')
        command = [compiler,*flags,'-c',str(source),'-o',str(obj)]
        run(command);commands.append(command);objects.append(str(obj))
    elf, flat = BUILD/'playback-armv6.elf', BUILD/'playback-armv6.bin'
    command = [compiler,'-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib',
        '-static','-no-pie','-Wl,--gc-sections,--build-id=none,-Map='+str(BUILD/'playback.map'),
        '-Wl,-T,'+str(linker),*objects,'-o',str(elf)]
    run(command);commands.append(command)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    symbols = {}
    for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
        parts = line.split()
        if len(parts)==3:symbols[parts[2]]={'address':int(parts[0],16),'type':parts[1]}
    attrs = run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments = run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and 'INTERP' not in segments and 'DYNAMIC' not in segments
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    assert flat.stat().st_size <= 8192
    manifest = {'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'load_base':BASE,'elf':str(elf.relative_to(ROOT)),'elf_sha256':sha(elf),
        'flat_binary':str(flat.relative_to(ROOT)),'flat_binary_sha256':sha(flat),
        'flat_binary_bytes':flat.stat().st_size,'symbols':symbols,'commands':commands,
        'attributes':attrs,'segments':segments,'absolute_private_imports':imports,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in
            (*sources,LOCAL/'memory_output.h',header,linker,Path(__file__),owned_path)},
        'owned_elf_sha256_required':owned['elf_sha256'],
        'owned_artifact_private_abi_not_public_garmin_imports':True,
        'hook_address':'0x2f998e','displaced_thumb_hex':raw.hex(),'original_resume':'0x2f9999',
        'emulator_hook_only_not_loader_mounted_or_installed':True,
        'device_io':False,'device_install_candidate':False,
        'limitations':'Exact unchanged owned-media private ABI and HWID1352/software8.00 stock entry. New C/ARM shim aligns only its C call stack then replays displaced Thumb semantics/resumes original callback before START14. Before-start attachment and guarded ACTIVE->QUEUED rearm require serialized exclusive source ownership/pinned modules/PCM. Rearm does not clear native state or release PCM; state checks/IRQ exclusion do not prove future-callback quiescence or cross-channel reservation. Failure rejects owned START but retains native allocations pending explicit reconciliation; not complete cancellation. Hook exists only in emulator RAM, no accepted loader package/App/UI/SEP/SDP/phone/speaker/navigation/realtime/DAC/DMA/IRQ/safe unload/Google Maps.'}
    (BUILD/'playback.dis').write_text(run(['arm-linux-gnueabi-objdump','-d',str(elf)]))
    (BUILD/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str(BUILD/'manifest.json'),'flat_binary_bytes':flat.stat().st_size,
                      'device_io':False}))


if __name__ == '__main__':main()
