#!/usr/bin/env python3
"""Build independent ARMv6 controller prep; run only host logic controls."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,subprocess

ROOT=Path(__file__).resolve().parents[2]
LOCAL=Path(__file__).resolve().parent
STAGE=ROOT/'staging/controller-gir-prep'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(command):
    return subprocess.run(command,check=True,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout

def main():
    STAGE.mkdir(parents=True,exist_ok=True)
    manifest_path=STAGE/'verification.json'
    assert not manifest_path.exists(),'Keep completed source/build verification frozen'
    previous_path=ROOT/'staging/native-player-mainmenu-native-prep/gui-static/native-gir-calls-and-controller-placement.json'
    previous=json.loads(previous_path.read_text())
    assert sha(previous_path)=='2430c1c474e82c91f72badac2a343482e61e0b29cbb2587361d4f73d4dbcb0c6'
    protected=dict(previous['verified_frozen_dependency_hashes'])
    protected.update(previous['source_sha256'])
    for p,digest in protected.items():assert sha(ROOT/p)==digest,p
    baseline=json.loads((ROOT/'staging/native-sbc/manifest.json').read_text())
    compiler=baseline['commands'][0][0]
    flags=['-std=c11','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-Os','-ffreestanding',
           '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
           '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections',
           '-fstack-usage','-Wall','-Wextra','-Werror','-I'+str(LOCAL)]
    sources=[LOCAL/'controller_gir_prep.c',LOCAL/'exact_abi.c']
    objects=[];commands=[]
    for p in sources:
        obj=STAGE/(p.stem+'-armv6.o');command=[compiler,*flags,'-c',str(p),'-o',str(obj)]
        run(command);commands.append(command);objects.append(obj)
    linker=STAGE/'controller-gir-prep.ld'
    linker.write_text('''/* Offline fixture only, not a Garmin loader map. */
ENTRY(cg_controller_prepare)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x0ea00000;
 .text : { *(.text*) } :code
 .rodata : { *(.rodata*) } :code
 . = ALIGN(4096);
 .data : { *(.data*) } :state
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
''')
    elf=STAGE/'controller-gir-prep-armv6.elf';flat=STAGE/'controller-gir-prep-armv6.bin'
    command=[compiler,'-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-nostdlib','-static','-no-pie',
             '-Wl,--gc-sections,--build-id=none,-Map='+str(STAGE/'controller-gir-prep.map'),
             '-Wl,-T,'+str(linker),*[str(p)for p in objects],'-o',str(elf)]
    run(command);commands.append(command)
    assert not run(['arm-linux-gnueabi-nm','-u',str(elf)]).strip(),'Undefined native symbols'
    attributes=run(['arm-linux-gnueabi-readelf','-A',str(elf)])
    segments=run(['arm-linux-gnueabi-readelf','-l',str(elf)])
    assert 'Tag_CPU_arch: v6' in attributes and 'INTERP'not in segments and 'DYNAMIC'not in segments
    command=['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)]
    run(command);commands.append(command)
    disassembly=run(['arm-linux-gnueabi-objdump','-d',str(elf)])
    (STAGE/'controller-gir-prep-disassembly.txt').write_text(disassembly)
    symbols={}
    for line in run(['arm-linux-gnueabi-nm','-n',str(elf)]).splitlines():
        fields=line.split()
        if len(fields)==3:symbols[fields[2]]=dict(address=int(fields[0],16),type=fields[1])
    assert 'cg_controller_prepare'in symbols and 'resident_started'in symbols
    # Leaf SP reader must not contain a prologue before it reads SP.
    spbody=disassembly.split('<cg_current_sp>:',1)[1].split('\n\n',1)[0]
    assert 'mov\tr0, sp' in spbody and 'push'not in spbody and 'sub\tsp'not in spbody
    host=STAGE/'host-controls-sanitized'
    command=['cc','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
             '-Wall','-Wextra','-Werror','-I'+str(LOCAL),str(sources[0]),str(LOCAL/'host_controls.c'),'-o',str(host)]
    run(command);commands.append(command)
    controls=[]
    for number in range(23):
        row=json.loads(run([str(host),str(number)]))
        assert row['passed'] and row['case']==number
        controls.append(row)
    for p,digest in protected.items():assert sha(ROOT/p)==digest,p
    used=[*sources,LOCAL/'controller_gir_prep.h',LOCAL/'exact_abi.h',LOCAL/'host_controls.c',
          LOCAL/'README.md',Path(__file__).resolve(),linker,previous_path,
          ROOT/'staging/native-sbc/manifest.json']
    imports=[
        ('cg_settings_set',0x2ca82d,'u32(key,constvoid*data,u32bytes,u32cache)','0 required;writes19B=1;readback stillrequired'),
        ('cg_settings_read',0x2cabbd,'u32(key,u32*out_data_pointer)','bytes4 required;data range andu32=1 checked'),
        ('cg_widget_init',0x395981,'void(void)','originalr0 unspecified/discarded'),
        ('cg_display_init',0x2db541,'void(void)','originalr0 unspecified/discarded'),
        ('cg_platform_hash',0x25dc81,'u32(void)','must equalreadonlyGIRword12'),
        ('cg_gir_register',0x41cc47,'u32(gir,u8*outkind)','1 required;nativeguard34F773C/rawcalls11C510/41CCD2'),
        ('cg_gir_catalog',0x41b15b,'u32(void)','originalvector34F7730;one24byterecord/source fieldschecked'),
        ('cg_static_fonts_init',0x4df249,'void(void)','originalr0 unspecified/discarded'),
        ('cg_external_fonts_init',0x4de237,'u32(u32mode)','explicitmode1;0 checked;notfontinventoryproof'),
        ('cg_menu_signals_init',0x4a388b,'void(void)','originalr0 unspecified/discarded'),
        ('cg_db_set_cell',0x316277,'void(menu,icon,cell,size)','r0 unspecified/discarded;selectedSQLrow/closedwrappers requireexternal runtimeobservation')]
    firmware_functions=json.loads((ROOT/'staging/native-player-independent-signal/mainmenu-controller-prerequisites-static.json').read_text())['functions']
    registration_literals=[]
    for entry in ['0x395980','0x2db540','0x4df248','0x4a388a']:
        f=firmware_functions[entry];r1=None
        for row in f['instructions']:
            if row['instruction'].startswith('ldr r1, [pc,') and 'literal_value'in row:r1=row
            if row.get('direct_call')=='0x3896f8' and r1:
                registration_literals.append(dict(containing_function=entry,call=row['address'],
                    callback_literal_producer=r1['address'],literal=r1['literal_value'],
                    purpose='Original3896F8 registration;fullcallbackABI/lifetime notclaimedhere'))
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=previous['MAIN_sha256'],
        target=dict(HWID=1352,software='8.00',cpu='ARM1176 ARMv6',float_ABI='soft'),
        source_sha256={str(p.relative_to(ROOT)):sha(p)for p in used},
        verified_protected_previous_source_hashes=protected,
        ELF=str(elf.relative_to(ROOT)),ELF_sha256=sha(elf),flat_binary=str(flat.relative_to(ROOT)),
        flat_binary_sha256=sha(flat),flat_binary_bytes=flat.stat().st_size,load_base=0x0ea00000,
        symbols=symbols,commands=commands,attributes=attributes,segments=segments,undefined_symbols=[],
        compiler=run([compiler,'--version']).splitlines()[0],host_logic_control_count=len(controls),host_logic_controls=controls,
        exact_native_imports=[dict(symbol=n,address=hex(p),declared_signature=s,return_contract=r)for n,p,s,r in imports],
        original_registration_callback_literal_evidence=registration_literals,
        configs=dict(bytes=68,result_bytes=80,magic=hex(0x13520800),explicit_flags=15,
            example_controller='9503F90,stack[9500040,9503F90]',stock_GIR='B800000;payloadlengthfromoriginalheader+20,directorybytesfrom+28',
            catalog_record_range='Caller mustdeclare guardednativeallocator span,not assume priorrawfixture pointers',
            settings_data_range='DeclaredsyntheticNORrecordpayloadspan18001000..18009000 forcurrentlowerfixture',
            lowerDB_provider='84C0000,explicitreadyinput menu+24,+28,DBword0',
            selected_cell=12,player_id=hex(0x7f135201),selected_size=0),
        behavior=dict(active_controller_stack_preserved=True,SP_reader_leaf_disassembly_checked=True,
            normal_SYSmode_and_IRQmarkerchecked=True,actualTCB_head_and_SPchecked_aftereachoriginalAPI=True,
            one_invocation_no_reset_retry_rollback_or_unload=True,partial_state_and_arguments_remain_resident=True,
            originalManager_or405340_called=False,lowerSQLprovider_inputs_explicit=True,
            completion_is_DB_OBSERVATION_NEEDED=True,DB_commit_fontinventory_nativeheap_mutex_or_UI_runtime_verified=False),
        stack_usage_files={str(p.relative_to(ROOT)):p.read_text()for p in STAGE.glob('*.su')},
        new_ARM_emulation_executed=False,device_io=False,sounds_emitted=False,frozen_source_modified=False,
        Linux_runtime_required=False,install_candidate=False,
        limits='Buildandhoststublogiccontrols only. Actualfirmwarecalls executeonlyinrootfuture nativekernel VM; currentTCB/SP/modechecks areimplementedbutnot ARM-runtimeverified. Callbackstocksem frames must derive from actualcomponent nestedcallSP,not olddirectAPI hardcodedSP. SettingsconditionalPOST, nativeheap/locks, font/GIR/SQLproviders/fullreadonly/wholemutablememory/owned/timed/frameguards stillroot scope. No acceptedVPM/SIG/deviceApp/render/touch/audio/directphone/safeunload proof.')
    manifest_path.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(manifest=str(manifest_path.relative_to(ROOT)),sha256=sha(manifest_path),
                         ARM_binary_bytes=flat.stat().st_size,host_controls=len(controls),protected_dependencies=len(protected))))

if __name__=='__main__':main()
