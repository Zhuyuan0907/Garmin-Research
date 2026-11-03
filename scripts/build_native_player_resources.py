#!/usr/bin/env python3
"""Relink corrected ResourceRef token player; borrowed stock icon, offline only."""
from datetime import datetime,timezone
import json
from pathlib import Path
import struct
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_loader import IMAGE, DESCRIPTOR
from build_native_sbc import run, sha
from build_native_app_component import symbols, API_NAMES
from build_native_voice_package_fixture import repack
from analyze_tts_vpm import parse_image

OUT=ROOT/'staging/native-player-resources'
FROZEN=ROOT/'staging/native-app-component-emulation/Chinese_Big5_MeiLing/manifest.json'
MENU=ROOT/'staging/native-player-menu/build.json'

def main():
    NativeImage();f=json.loads(FROZEN.read_text());menu=json.loads(MENU.read_text())
    for manifest in [f,menu]:
        for path,h in manifest['source_sha256'].items(): assert sha(ROOT/path)==h,path
    assert sha(ROOT/f['combined_binary'])==f['combined_sha256']
    OUT.mkdir(exist_ok=True)
    base=f['extension_base'];original=(ROOT/f['original_binary']).read_bytes()
    olddir=(ROOT/f['extension_elf']).parent
    for name in ['playback_imports.h','source_worker_imports.h']:
        (OUT/name).write_bytes((olddir/name).read_bytes())
    linker=OUT/'player_component.ld'
    text=(olddir/'app_component.ld').read_text().replace('ENTRY(native_app_component_entry)',
        'ENTRY(native_player_component_entry)\nPHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }')
    text=text.replace('KEEP(*(.text.native_app_component_entry))',
        'KEEP(*(.text.native_player_component_entry)) KEEP(*(.text.native_app_component_entry)) KEEP(*(.player_component_api))')
    text=text.replace('*(.text .text.*) *(.rodata .rodata.*) }',
        '*(.text .text.*) *(.rodata .rodata.*) } :code')
    text=text.replace('__app_bss_end = .; }','__app_bss_end = .; } :data')
    for name in ['pcm0','pcm1','pcm2','pcm3','gather']:
        text=text.replace('*(.'+name+') }','*(.'+name+') } :data')
    for name in ['queue_payload','worker_stack','source_stack']:
        text=text.replace('__'+name+'_end = .; }','__'+name+'_end = .; } :data')
    linker.write_text(text)
    commands=[];objects=[];seen=set();flags=None
    deps={ROOT/path for path in f['source_sha256']} | {
        FROZEN,MENU,Path(__file__).resolve(),linker,olddir/'app_component.ld'}
    for old in f['commands']:
        if '-c' not in old: continue
        source=Path(old[old.index('-c')+1])
        if source in seen: continue
        seen.add(source)
        command=[x.replace(str(olddir),str(OUT)) for x in old]
        run(command);commands.append(command);objects.append(command[command.index('-o')+1])
        if source.name=='app_component_entry.c': flags=command[1:command.index('-c')]
    assert flags
    extra=[ROOT/'native/player-menu-loaded/entry.c',ROOT/'native/player-resources/player_menu.c']
    for source in extra:
        obj=OUT/('player_'+source.stem+'.o')
        command=['arm-linux-gnueabi-gcc',*flags]
        if source.name=='player_menu.c':
            # The preserving component already provides the freestanding EABI
            # traps. Rename the standalone prototype's unused definitions;
            # do not edit its frozen source or allow duplicate definitions.
            command+=['-D__aeabi_idiv0=menu_unused_idiv0','-D__aeabi_ldiv0=menu_unused_ldiv0']
        command+=['-c',str(source),'-o',str(obj)]
        run(command);commands.append(command);objects.append(str(obj));deps.add(source)
    elf=OUT/'player-component-EMULATION-ONLY.elf'
    flat=OUT/'player-component-EMULATION-ONLY.bin'
    link=['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft',
        '-nostdlib','-static','-no-pie','-Wl,--gc-sections,--build-id=none,-Map='+str(OUT/'player.map'),
        '-Wl,-T,'+str(linker),*objects,'-lgcc','-o',str(elf)]
    run(link);commands.append(link);s=symbols(elf)
    header=OUT/'source_worker_imports.h'
    header.write_text('#define OWNED_CONSUME_RESUME '+hex(s['owned_media_consume']['address']+8)+'\n')
    hook=ROOT/'native/sbc-prototype/source_event_hooks.S'
    command=['arm-linux-gnueabi-gcc',*flags,'-c',str(hook),'-o',str(OUT/'source_event_hooks.o')]
    run(command);commands.append(command);run(link);commands.append(link)
    assert symbols(elf)==s,'Two-pass import resolution changed addresses'
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip()
    attrs=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attrs and not any(t in segments for t in ['RWE','INTERP','DYNAMIC'])
    run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)])
    code=flat.read_bytes();assert len(code)==s['__app_code_end']['address']-base<=65536
    combined=bytearray(original)+bytearray(base-IMAGE-len(original))+bytearray(code)
    entry=s['native_player_component_entry']['address'];disp=entry-(IMAGE+8)
    assert disp%4==0
    ram=s['__combined_ram_bytes']['address']
    struct.pack_into('<3I',combined,0,0xea000000|((disp//4)&0xffffff),ram,len(combined))
    assert combined[12:len(original)]==original[12:] and len(combined)<ram<=0x300000
    binary=OUT/'combined-voice-player-EMULATION-ONLY.bin';binary.write_bytes(combined)
    vpm,checks=repack((ROOT/f['voice_package']).read_bytes(),bytes(combined))
    package=OUT/'player-menu-EMULATION-ONLY.vpm';package.write_bytes(vpm)
    files,_=parse_image(vpm);assert files['DLLIMG.BIN']['content']==combined
    deps.update([OUT/'playback_imports.h',header,ROOT/'scripts/build_native_voice_package_fixture.py',
        ROOT/'scripts/build_native_app_component.py',ROOT/'scripts/analyze_native_sections.py'])
    manifest={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'extension_base':base,'extension_bytes':len(code),'extension_elf':str(elf.relative_to(ROOT)),
        'extension_elf_sha256':sha(elf),'extension_flat':str(flat.relative_to(ROOT)),
        'extension_flat_sha256':sha(flat),'combined_binary':str(binary.relative_to(ROOT)),
        'combined_sha256':sha(binary),'combined_file_bytes':len(combined),'combined_ram_bytes':ram,
        'original_binary':f['original_binary'],'voice_package':f['voice_package'],
        'original_bytes_after_header_unchanged':True,'reservation_start':IMAGE,'reservation_end':DESCRIPTOR,
        'remaining_reservation_bytes':0x300000-ram,'package':str(package.relative_to(ROOT)),
        'package_sha256':sha(package),'package_bytes':len(vpm),'package_checks':checks,
        'BSS_bytes':s['__app_bss_end']['address']-s['__app_bss_start']['address'],
        'symbols':s,'private_api':list(API_NAMES),
        'player_api':['native_player_menu_install','native_player_menu_activate'],
        'pcm_pages':f['pcm_pages'],'attributes':attrs,'segments':segments,'unresolved_symbols':[],
        'code_RX_data_RW_segments':True,'patch_plan':[],'VM_MAIN_patch_bytes':0,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(deps)},'commands':commands,
        'frozen_preserving_manifest_sha256':sha(FROZEN),'frozen_menu_manifest_sha256':sha(MENU),
        'device_io':False,'device_install_candidate':False,'real_package_acceptance_verified':False,
        'caption_auxiliary_word_initialized':True,'normal_Grid_state_updater_registered':True,
        'resource_ref_hash32_and_owned_ASCII_name_ABI':True,
        'borrowed_original_MainMenu_icon_hash':'0x8a56eac',
        'original_resource_catalog_boot_mapping_unverified':True,
        'updater_returns_enabled0_for_context13528000_otherwise_disabled4':True,
        'default_shared_ptr_and_caption_outputs_left_unchanged':True,
        'limits':'Local container/loader experiment preserves40 original voice exports and12 prior private APIs. '
            'Entry attempts private icon registration after the original TTS initializer returns. This timing '
            'is an experimental fixture, not verified UI-thread ownership. No MAIN patch, Audio Sink '
            'publication or music worker startup is part of this variant. Original music evidence remains '
            'separate. Borrowed stock MainMenu icon tokens; full GUI/SQL/touch chain, physical package/SIG acceptance, '
            'ID9 playback ownership/stop/repeated activation, safe unregister/reload/unload remain open. '
            'Keep callback/module resources pinned; never transfer EMULATION-ONLY package to navigator.'}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str((OUT/'manifest.json').relative_to(ROOT)),
        'code_bytes':len(code),'file_bytes':len(combined),'ram_bytes':ram,'device_io':False}))

if __name__=='__main__':main()
