#!/usr/bin/env python3
"""Loaded player -> original general menu ctor with full scoped final guards.

No controller/root foreground/input/display or device installation claim.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_mainmenu_metadata import MetadataVM
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT,GIR
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mainmenu-full'
WRITERS=[dict(address='0x551c7f8',size=4,value='0x1',PC='0x385450'),
    dict(address='0x551c80c',size=4,value='0x1',PC='0x385450'),
    dict(address='0x551c800',size=4,value='0x1',PC='0x385450'),
    dict(address='0x551c804',size=4,value='0xc035f8',PC='0x26de42'),
    dict(address='0x551c808',size=4,value='0x3aaed08',PC='0x26de6c'),
    dict(address='0x551c804',size=4,value='0xc0fd70',PC='0x344e22'),
    dict(address='0x551c7fc',size=4,value='0x1',PC='0x385450')]

class ConstructorVM(MetadataVM):
    def __init__(self,stock,build):
        self.original_main_default_writes=[]
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if address==0x2ca82c and uc.reg_read(REGS[0])in [0x121e,0x121f]:
            key,pointer,length,cache=[uc.reg_read(r)for r in REGS]
            require(length==2,'Unexpected original Main default value width')
            self.original_main_default_writes.append(dict(key=hex(key),native_caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),
                bytes_from_original_default_calculation=bytes(uc.mem_read(pointer,length)).hex(),host_supplied_default_value=False))
        return super().observe(uc,address,size,data)

    def finish_constructor(self):
        base=0x5400000;before=self.initial_regions[base];expected=bytearray(before)
        require(self.conditional_region_writes==WRITERS,'Unexpected original general-menu initialized-data writer inventory')
        for row in WRITERS:
            p=int(row['address'],16);value=int(row['value'],16)
            expected[p-base:p-base+4]=struct.pack('<I',value)
        require(bytes(self.uc.mem_read(base,len(before)))==bytes(expected),
            'Whole general-menu conditional initialized data differs beyond exact original writers')
        self.initial_regions[base]=bytes(expected)
        try:snapshot=SelectionPlayerVM.finish(self)
        finally:self.initial_regions[base]=before
        snapshot.update(full_general_menu_conditional_region_matches_exact_native_writers=True,
            original_native_writer_events=WRITERS,host_rewrote_GUI_initialized_bytes=False)
        return snapshot

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True);build=json.loads((ROOT/BUILD).read_text());vm=ConstructorVM(NativeImage(),build)
    cases=[];database_sha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        vm.invoke(0x2cbd17,());vm.uc.mem_write(INPUT+0x400,struct.pack('<I',1))
        require(vm.invoke(0x2ca82d,(0x19b,INPUT+0x400,4,0))==0,'Original setting19B control write failed')
        require(vm.settings_catalog_fixture is None,'Lower settings inventory unexpectedly replaced')
        vm.invoke(0x395981,());vm.invoke(0x2db541,());registration=vm.register_stock_GIR()
        vm.external_IO_active=True;vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.invoke(0x4a388b,());vm.init_DB_fixture();vm.set_cell(12,PLAYER_ID,0)
        obj=vm.invoke(0x3954cc,(0x3f04,))
        print(json.dumps(dict(phase='loaded_player_original_general_MainMenu_ctor')),flush=True)
        value=vm.invoke(0x40434d,(obj,1));require(value==obj and vm.word(obj)==0xc03f98,'Original general menu ctor returned wrong object')
        rows=vm.grid_rows(obj+0x39b0);require(len(rows)==15,'Original embedded Grid does not contain15 rows')
        row=rows[11];caption=vm.wide(vm.invoke(0x3927f5,(int(row['address'],16)+0x1c,)))
        require(caption=='Pi 播放器'and row['widget']!='0x0','Loaded player caption/button absent from original general menu')
        record('loaded_compiled_player_is_present_in_original_general_menu_Grid_constructor',
            original_entry='0x40434c',object=hex(obj),returned=hex(value),vtable=hex(vm.word(obj)),
            embedded_Grid_row_count=15,loaded_player_caption=caption,loaded_player_row=row,
            host_seeded_player_catalog=False,original_controller_or_foreground_executed=False)
        require(len(vm.original_main_default_writes)==1 and vm.original_main_default_writes[0]['key']=='0x121e'and
            vm.original_main_default_writes[0]['native_caller']=='0x405314'and vm.visits[0x2c7de0]>0,
            'Original default calculation and setter branch differs')
        out=INPUT+0x500;vm.put(out,0);require(vm.invoke(0x2cabbd,(0x121e,out))==2,'Native default not readable from initialized settings')
        pointer=vm.word(out);actual=bytes(vm.uc.mem_read(pointer,2)).hex()
        require(actual==vm.original_main_default_writes[0]['bytes_from_original_default_calculation'],
            'Stored native default differs from original calculation')
        record('original_general_menu_computes_and_persists_121E_default_through_native_setter',
            original_default_entry='0x2c7de0',original_write=vm.original_main_default_writes[0],native_read_back_hex=actual,
            host_supplied_default_or_cursor=False,later_121F_branch_and_recreation_unverified=True)
        tree=vm.tree(obj)
        require(tree['frame']==[0,0,0,0]and tree['flags84_85']==[0,0]and not vm.audio and not vm.control_clicks,
            'Constructor unexpectedly established visible foreground or activated audio')
        record('general_menu_constructor_leaves_zero_frame_and_hidden_state_before_controller',
            native_frame=tree['frame'],native_visibility_flags=tree['flags84_85'],
            native_controller_root_foreground_GUI_thread_touch_display_unverified=True,audio_requests=[])
        vm.set_cell(*vm.database_before[11])
        require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==vm.database_before and
            all(s['closed']for s in vm.statements.values()) and sha(DATABASE)==database_sha,
            'In-memory DB restore, original SQL finalization or readonly backup guard failed')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM/40 exports changed')
        require(bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes,'Readonly stock GIR changed')
        for name in vm.raw_font_sources:require(sha(str(vm.backup_paths[name].relative_to(ROOT)))==hashlib.sha256(vm.raw_font_sources[name]).hexdigest(),
            'Raw font backup changed')
        vm.verify_storage_guards();vm.verify_descriptor_guards()
        require(not vm.invalid_accesses and not vm.pending_glyph_calls,'General ctor faulted or left incomplete glyph query')
        snapshot=vm.finish_constructor();vm.db.close()
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve()}
        paths.update(ROOT/p for p in build['source_sha256']);paths.update(vm.backup_paths[k]for k in vm.raw_font_sources)
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):paths.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,native_tree=tree,
            original_stock_GIR_registration=registration,original_main_default_writes=vm.original_main_default_writes,
            original_voice_RAM_and40_exports_unchanged=True,raw_font_backups_and_DB_unchanged=True,
            all_SQL_statements_closed_by_original_wrappers=True,retained_closed_SQL_history_count=len(vm.statements),
            full_scoped_general_MainMenu_constructor_final_guards_passed=True,
            general_MainMenu_controller_root_foreground_and_recreation_verified=False,
            accepted_modified_VPM_or_device_App_direct_audio_and_safe_lifetime_verified=False,
            consumer_metadata_reads=vm.consumer_metadata_reads,settings_native_entries=vm.settings_native_entries,
            device_io=False,sounds_emitted=False,
            limits='Stock40434C executes after original loader registers compiled player, native settings/signal initialization, stock GIR/fonts and explicit DB cell12 selection. Embedded15-row Grid contains Pi player; original2C7DE0/2CA82C persist121E default, native copy reads same. Exact seven native GUI data writer events and whole code/voice40/private12/player2/canary/DB/font/GIR guards pass. Lower storage/heap/kernel/GPS/boot boundaries remain fixtures; ctor Page has zero frame/hidden flags. No controller/root/foreground/touch/display/recreation/safe lifecycle/accepted loading/device App/audio proof.')
        path=ROOT/'evidence/firmware-analysis/native-mainmenu-constructor-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(paths))),flush=True)
    except Exception as error:
        (STAGE/'general-constructor-integration-failure.json').write_text(json.dumps(dict(error=str(error),completed_cases=cases,
            all_final_guards_passed=False,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            native_fatal_entries=vm.native_fatal_entries,conditional_writes=vm.conditional_region_writes,
            database_before=vm.database_before,database_current=list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')),
            SQL_closed_inventory={hex(p):s['closed']for p,s in vm.statements.items()}),ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),all_final_guards_passed=False)),flush=True);sys.exit(1)

if __name__=='__main__':main()
