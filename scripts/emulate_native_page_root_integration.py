#!/usr/bin/env python3
"""Scoped stock custom-Page root registration/getter and final guards.

The custom Page is hidden/offscreen after the stock transition. This is not
a general MainMenu, visible player App or physical GUI-loop/display proof.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_player_root_registration import RootVM,BUILD,STAGE
from probe_native_player_resources import GIR,INPUT
from emulate_native_player_menu_selection import DATABASE,sha
from emulate_native_player_page import PageVM
from emulate_native_vpm_filesystem import require

def inventory(vm,manager):
    head=vm.word(manager+0x1a0);node=vm.word(head);seen=set();rows=[]
    while node!=head:
        require(node and node not in seen and len(seen)<64,'Invalid manager root catalog list')
        seen.add(node);obj=vm.word(node+8)
        require(obj and vm.word(vm.word(node)+4)==node and vm.word(vm.word(node+4))==node,
            'Root catalog ownership links differ')
        rows.append(dict(node=hex(node),Page=hex(obj),shared_control=hex(vm.word(node+12)),
            category=vm.uc.mem_read(obj+0xcc,1)[0],vtable=hex(vm.word(obj))))
        node=vm.word(node)
    return rows

def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());database_sha=sha(DATABASE)
    vm=RootVM(NativeImage(),build);cases=[]
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        vm.invoke(0x395981,());vm.invoke(0x2db541,());registration=vm.register_stock_GIR()
        vm.external_IO_active=True;vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Original fonts failed')
        vm.init_DB_fixture();vm.supply_setting_record(1)
        page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,));manager=vm.invoke(0x393a2d,(0,))
        before=inventory(vm,manager)
        print(json.dumps(dict(phase='before_original_custom_Page_root_registration')),flush=True)
        returned=vm.invoke(0x38e697,(manager,page,0,0));roots=inventory(vm,manager)
        require(vm.word(page+0x48)==manager and any(r['Page']==hex(page)for r in roots),
            'Original manager does not own the custom Page in root catalog')
        record('original_custom_Page_root_registration_returns_and_manager_catalog_owns_Page',
            original_entry='0x38e696',Page=hex(page),Page_vtable=hex(vm.word(page)),
            manager=hex(manager),manager_vtable=hex(vm.word(manager)),catalog_before=before,catalog_after=roots,
            returned_r0_not_boolean_success_status=hex(returned),original_parent_assignment_verified=True,
            general_MainMenu_or_controller_executed=False)
        category=vm.uc.mem_read(page+0xcc,1)[0];out=INPUT+0x600
        vm.put(out,0);vm.put(out+4,0)
        vm.invoke(0x38cf81,(out,manager,category))
        actual=vm.word(out);matches=[r for r in roots if r['category']==category]
        require(matches and actual==int(matches[-1]['Page'],16),'Original category getter differs from independent catalog order')
        vm.invoke(0x3954f1,(out+4,))
        record('original_manager_root_category_getter_matches_native_catalog_last_entry',
            original_entry='0x38cf80',category=category,returned_Page=hex(actual),
            independent_catalog_last_matching_Page=matches[-1]['Page'],temporary_shared_holder_released=True,
            Page_module_fonts_or_roots_not_unloaded=True)
        tree=vm.tree(page)
        require(tree['frame']==[480,0,480,272] and tree['flags84_85']==[0,0],
            'Development hidden/offscreen Page condition changed; inspect before declaring visible UI')
        require(not vm.audio and not vm.control_clicks,'Root transition activated playback or a synthetic callback')
        require(not vm.invalid_accesses and not vm.pending_glyph_calls,'Root memory/glyph lookup incomplete')
        record('stock_transition_leaves_custom_Page_hidden_offscreen_no_player_audio_activation',
            native_frame=tree['frame'],native_visibility_flags=tree['flags84_85'],
            custom_Page_is_visible_foreground_player_App=False,host_supplied_Page_or_child_frames=False,
            audio_requests=[],kernel_scheduling_or_real_display_verified=False)
        require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==vm.database_before and
            not vm.statements and sha(DATABASE)==database_sha,'Root DB unchanged guard failed')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Root changed original voice RAM or40 exports')
        require(bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes,'Readonly GIR changed')
        for name in vm.raw_font_sources:require(sha(str(vm.backup_paths[name].relative_to(ROOT)))==hashlib.sha256(vm.raw_font_sources[name]).hexdigest(),
            'Raw font backup changed')
        # Exact two stock once writes are guarded by preserved PageVM.finish;
        # every other initialized byte/code/canary and inherited ownership rule
        # remains checked. Native root/font resources stay resident.
        snapshot=PageVM.finish(vm);vm.db.close()
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],
            ROOT/build['extension_elf'],ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',
            Path(__file__).resolve()}
        paths.update(ROOT/p for p in build['source_sha256']);paths.update(vm.backup_paths[k]for k in vm.raw_font_sources)
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name:
                p=Path(name).resolve()
                if p.is_file() and p.is_relative_to(ROOT/'scripts'):paths.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,native_tree=tree,
            original_stock_GIR_registration=registration,original_voice_RAM_and40_exports_unchanged=True,
            raw_font_backups_and_DB_unchanged=True,virtual_clock_ticks=vm.virtual_clock_ticks,
            original_transition_buffer_heap_requests=vm.transition_heap_requests,
            inherited_non_font_handle_release_and_font_resident_canary_rules_retained=True,
            full_scoped_custom_Page_root_final_guards_passed=True,full_general_MainMenu_integration=False,
            custom_Page_hidden_and_offscreen_after_stock_transition=True,
            real_kernel_GUI_thread_touch_display_or_package_acceptance_verified=False,
            device_io=False,sounds_emitted=False,actual_device_App_or_direct_phone_music_verified=False,
            limits='Stock custom Page5A2994 and manager38E696/38CF80 root catalog/getter verified under explicit boot/GIR/font/settings/heap/mutex/IRQ and advancing virtual clock fixtures. Stock software transition executes but custom Page remains hidden/offscreen, with no player activation. All scoped final code/voice/onceword/canary/font/DB guards pass; resources remain resident. General PageMainMenu40434C/controller405340, real boot/kernel/GUI/input/display, accepted package, visible player App, direct phone audio and safe lifecycle are open.')
        target=ROOT/'evidence/firmware-analysis/native-custom-page-root-emulation.json';require(not target.exists(),'Frozen proof exists; use new namespace')
        target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(evidence=str(target.relative_to(ROOT)),groups=len(cases),dependencies=len(paths),
            all_scoped_final_guards_passed=True,general_MainMenu_or_visible_player_App=False)),flush=True)
    except Exception as error:
        failure=dict(error=str(error),completed_cases=cases,all_final_guards_passed=False,recent=list(vm.recent),
            invalid_accesses=vm.invalid_accesses,roots=locals().get('roots'),
            actual=getattr(vm,'conditional_region_writes',None))
        (STAGE/'custom-page-root-integration-failure.json').write_text(json.dumps(failure,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),all_final_guards_passed=False)),flush=True);sys.exit(1)

if __name__=='__main__':main()
