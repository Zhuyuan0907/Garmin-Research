#!/usr/bin/env python3
"""Bounded, backup-only ABI placement note for native controller GUI prep.

This script reads exact firmware and frozen source/proof files. It never
constructs an emulator, calls guest code, modifies frozen evidence or accesses
devices. A proposed native API sequence is an explicit input, not stock boot.
"""
from datetime import datetime, timezone
from pathlib import Path
import ast
import hashlib
import json
import struct

from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from analyze_native_gui_foreground_boot import cfg, extract


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_method(path, classname, method):
    source = path.read_text()
    tree = ast.parse(source)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == classname)
    node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method)
    snippet = '\n'.join(source.splitlines()[node.lineno-1:node.end_lineno])+'\n'
    return dict(path=str(path.relative_to(ROOT)), class_name=classname, method=method,
                first_line=node.lineno, last_line=node.end_lineno, source=snippet,
                snippet_sha256=hashlib.sha256(snippet.encode()).hexdigest(), file_sha256=sha(path))


def classify(stock, pointer, length):
    copies = [r for r in stock.copies if r['runtime_start'] <= pointer and pointer+length <= r['runtime_end']]
    zeros = [r for r in stock.zeros if r['runtime_start'] <= pointer and pointer+length <= r['runtime_end']]
    assert len(copies)+len(zeros) == 1, hex(pointer)
    result = dict(address=hex(pointer), bytes=length, value_is_live_runtime_observation=False)
    if copies:
        load = stock.runtime_to_load(pointer, length)
        result.update(kind='file_backed_initialized_data', load_address=hex(load), file_initial_hex=stock.read(load,length).hex())
    else:
        result.update(kind='startup_zero_range', containing_range=zeros[0],
                      file_bytes_read_or_live_zero_value_inferred=False)
    return result


def main():
    target = ROOT/'staging/native-player-mainmenu-native-prep/gui-static/native-gir-calls-and-controller-placement.json'
    assert not target.exists(), 'Keep completed evidence immutable'
    stock = NativeImage()
    image = FileBackedRuntimeImage(stock)
    prior_path = ROOT/'staging/native-player-independent-signal/mainmenu-controller-prerequisites-static.json'
    prior = json.loads(prior_path.read_text())
    assert sha(prior_path) == '5881d18c9103b0b48636d53632bfc5b92667d119e04835a6c755aead5d76def5'
    signal_path = ROOT/'evidence/firmware-analysis/native-independent-signal-emulation.json'
    signal = json.loads(signal_path.read_text())
    assert sha(signal_path) == '0fe4fe2314f75932e68e6768517d1830ab5d2db8bb22b4d58c5f0c83d9d85582'
    assert signal['MAIN_sha256'] == EXPECTED and signal['all_passed'] and signal['case_count'] == 4
    frozen = dict(prior['verified_frozen_dependency_hashes'])
    for group in [prior['source_sha256'], signal['source_sha256']]:
        for path, expected in group.items():
            assert path not in frozen or frozen[path] == expected, path
            frozen[path] = expected
    for path, expected in frozen.items():
        assert sha(ROOT/path) == expected, path

    ranges = [(0x2cbd16,0x2cc2a4),(0x2ca82c,0x2caaea),(0x2cabbc,0x2cac22),
              (0x395980,0x3959c4),(0x2db540,0x2db584),(0x25dc80,0x25dc92),
              (0x41b198,0x41b1c2),(0x11c504,0x11c514),(0x41cc46,0x41ccd8),
              (0x41b15a,0x41b198),(0x4df248,0x4df27a),(0x4de236,0x4de2a0),
              (0x4de0e0,0x4de236),(0x4a388a,0x4a39f6),(0x316276,0x3162f2),
              (0x38d456,0x38d480),(0x390142,0x390184),(0x3ec540,0x3ec588),
              (0x3008a0,0x3008b0)]
    functions = {hex(a):cfg(image,a,[(a,b)]) for a,b in ranges}
    mixed_specs = [
        (0x3009a0,0x300a0c,{0x3009a6:(0x3009a8,'ARM'),0x3009b8:(0x3009bc,'Thumb'),
                           0x3009f6:(0x3009f8,'ARM'),0x300a00:(0x300a04,'Thumb')}),
        (0x3008b0,0x30092c,{0x3008b6:(0x3008b8,'ARM'),0x3008c8:(0x3008cc,'Thumb'),
                           0x300914:(0x300918,'ARM'),0x300920:(0x300924,'Thumb')})]
    for a,b,hops in mixed_specs:
        functions[hex(a)] = cfg(image,a,[(a,b)],modes=hops)
    rows = {int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    calls = {0x41b1ae:0x3008a0,0x41cc4e:0x41b198,0x41cc56:0x11c504,
             0x11c50c:0x3009a0,0x41ccce:0x3008b0,0x38d46c:0x3008a0,
             0x390150:0x3009a0,0x39017c:0x3008b0,0x2cbd6e:0x3ec540,
             0x3ec56e:0x3009a0,0x3ec578:0x300ae4}
    assert all(rows[pc]['direct_call'] == hex(target) for pc,target in calls.items())
    exact = {0x41cc46:'push {r4, r5, r6, r7, lr}',0x41cc4c:'sub sp, #0x1c',
             0x41cc54:'add r0, sp, #0x18',0x11c504:'push {r4, lr}',
             0x11c508:'movs r0, r1',0x11c50a:'str r1, [r4]',0x11c510:'movs r0, r4',
             0x41cccc:'ldr r0, [sp, #0x18]',0x41ccd4:'add sp, #0x1c',
             0x41b1b6:'str r0, [r1, #0x10]',0x3009ca:'str r2, [r0, #8]',
             0x3008f2:'str r1, [r0, #8]',0x3008f8:'str r2, [r1]'}
    assert all(rows[pc]['instruction'] == text for pc,text in exact.items())
    assert rows[0x41b1ac]['literal_value'] == '0x34f773c'
    assert rows[0x41b1b4]['address_value'] == '0x41b544'
    assert rows[0x38d472]['address_value'] == '0x38d860'
    assert rows[0x3009be]['literal_value'] == '0xf09090'
    for producer,transition_target in [(0x3009a4,0x3009a8),(0x3009f4,0x3009f8),
                                      (0x3008b4,0x3008b8),(0x300912,0x300918)]:
        assert int(rows[producer]['address_value'],16) == transition_target
    writers = prior['seven_original_conditional_GUI_writer_scope']['observed_in_older_full_ctor_proof']
    assert len(writers) == 7 and len({r['address'] for r in writers}) == 6

    snippets = [source_method(ROOT/path,cls,method) for path,cls,method in [
        ('scripts/probe_native_kernel_context.py','KernelContextVM','kernel_invoke'),
        ('scripts/emulate_native_player_menu.py','MenuVM','invoke'),
        ('scripts/probe_native_player_resources.py','ResourceVM','register_stock_GIR'),
        ('scripts/emulate_native_player_menu_selection.py','SelectionPlayerVM','set_cell'),
        ('scripts/emulate_native_player_menu_selection.py','SelectionPlayerVM','init_DB_fixture'),
        ('scripts/emulate_native_player_menu_loaded.py','LoadedPlayerVM','menu_pointer'),
        ('scripts/emulate_native_player_menu_loaded.py','LoadedPlayerVM','__init__'),
        ('scripts/emulate_native_task_runtime_full.py','FullTaskVM','verify_memory'),
        ('scripts/emulate_native_mainmenu_constructor.py','ConstructorVM','finish_constructor'),
        ('scripts/probe_native_dispatcher_condition.py','DispatcherVM','observe'),
        ('scripts/probe_native_task_mutex.py','NativeTaskMutexVM','observe')]]
    dependency_paths = {Path(__file__).resolve(),prior_path,signal_path,
                        ROOT/'evidence/firmware-analysis/main_02bd.bin',
                        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_gui_worker_boot.py',
                        ROOT/'scripts/analyze_native_gui_foreground_boot.py',
                        ROOT/'scripts/probe_native_mainmenu_controller_bootstrap.py'}
    dependency_paths.update(ROOT/r['path'] for r in snippets)
    C = 0x9503f90
    state = dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352,software='8.00'),static_only=True,new_emulation_executed=False,
        device_io=False,sounds_emitted=False,frozen_source_or_proof_modified=False,
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in sorted(dependency_paths)},
        verified_frozen_dependency_hashes=frozen,complete_bounded_local_CFG_count=len(functions),
        functions=functions,source_method_evidence=snippets,
        file_backed_or_zero_range_classification=[classify(stock,p,n) for p,n in [
            (0x34f773c,24),(0x34f9b28,24),(0x148e8ec,52),(0x148e69c,24),
            (0xf29540,8),(0xf2953c,4),(0xf2cbf4,4),(0xf06ef4,40),(0xf06f24,4)]],
        native_current_call_contract=dict(
            resume_prerequisite='Reproduce native background drain, idlePOST(controller,event1), exact controller savedPC2FD0AC WAIT returns1 first.',
            before_each_API='running_task == controller9503F90 and wordF09090 == controller; SP is controller stack top9503F90, prior API actually returned.',
            entry_frame='kernel_invoke(entry,args,stack=controller) supplies only explicit ABI registers,SP and LR10001;no fifth stackarguments used by this proposed sequence.',
            after_each_API='Require returned, running_task/readyhead controller, SP9503F90, original returnPC10000 and no pending native operations for controller.',
            block_contract='If idle endpoint reached, retain real suspended frame and argument storage; stop sequence until original API continuation returns. Never overwrite its frame with another API.',
            generic_invoke_invalid_here='MenuVM.invoke sets shared fixedSTACK and requires all ordinary counterszero;this violates active-current nativeTCB stack and retained background lock semantics.',
            source_conveniences_to_replace=['register_stock_GIR() uses invoke3times','set_cell() uses invoke once'],
            read_only_helpers_safe_as_host_inventory=['menu_pointer() only word(F11E04+8)','symbol() only manifest address','SQL SELECT for fixture inventory'],
            conditional_native_completion_not_proved_by_static_sequence=True),
        minimal_preparation_sequence=[
            dict(entry='0x2cbd17',args=[],checks='Cold settings only once;original52-byte condition token and five24-byte backend initializers execute natively;declare fictional lowerNOR storage.'),
            dict(entry='0x2ca82d',args=['0x19b','INPUT+400=9700420',4,0],checks='Only scratchu32=1 supplied;require0,retain actual lowerrecord and pointer readback;settings_catalog_fixture remainsNone.'),
            dict(entry='0x395981',args=[],checks='Widget registry34F9B60 native initializer.'),
            dict(entry='0x2db541',args=[],checks='Display list34A5614 native initializer.'),
            dict(entry='0x25dc81',args=[],checks='Native platform hash matches original readonly GIR word12.'),
            dict(entry='0x41cc47',args=['GIR=B800000','INPUT=9700020'],checks='Replace register_stock_GIR body: explicit bounded scratch,require1;original raw GIR lock/guard and catalog code.'),
            dict(entry='0x41b15b',args=[],checks='Catalog exactlyone24-byte live record;recordbyte0=outputkind,byte1=1,+12=GIR,+16=originaldirectorybytes;whole readonly GIR hash.'),
            dict(entry='0x4df249',args=[],checks='Original static font init;explicit external_IO_active source option retains readonly file fixtures.'),
            dict(entry='0x4de237',args=[1],checks='Original external font init require0;all requested original font files remainreadonly/closed.'),
            dict(entry='0x4a388b',args=[],checks='Original menu signals/subscriptions;observe guarded allocation lifetime and original native mutex calls.'),
            dict(entry='explicitlowerDBfixture',args=['menu=word(F11E04+8)','DB=84C0000'],checks='Host provider binds menu+24=DB,byte+28=1,DBword0=0;this is declared lowerfixture,not physical DB boot.'),
            dict(entry='0x316277',args=['menu','PLAYER_ID',12,0],checks='Replace set_cell: originalprepare/bind/step/finalize;require closedstatement inventory and selectedrow comparison,not emptyhistory.')],
        GIR_raw_backend=dict(pointer='0x34f773c',bytes=24,initializing_API='0x3008a0',
            initialize_call='0x41b1ae',normalized_return_caller='0x41b1b2',tag='0x41b544',
            tag_ascii=image.read(0x41b544,64).split(b'\0')[0].decode('ascii'),
            original_zero_body='3008A2/A4/A6/A8/AA/AC six4-byte zero stores;caller41B1B6 thenwrites tag+16.',
            cold_once='41B198 tests initializedF29540+4 bit0,uses385448;actualruntime onceguard must be observed.',
            raw_shape='Native24 bytes,not C++ wrapper;do notrequirevtable atpointer-4 orpointer-28.',
            fields=dict(owned_next=0,owned_previous=4,owner=8,waiter_head=12,tag=16,recursive_extra_acquisitions_u16=20,remaining_u16_not_interpreted=22),
            acquire=dict(outer_call='0x41cc56',guard_entry='0x11c504',raw_entry='0x3009a0',raw_call='0x11c50c',
                normalized_caller='0x11c510',LR='0x11c511',r0='34F773C',
                guard_r0='SP_registration+18',guard_r1='34F773C',guard_cell_write='11C50A storesr1->[r4]',
                guard_return='11C510 returnsguardcell inr0,not raw lockresult',
                SP_registration=hex(C-20-28),guard_cell=hex(C-20-28+24),raw_entry_SP=hex(C-20-28-8)),
            release=dict(raw_call='0x41ccce',normalized_caller='0x41ccd2',LR='0x41ccd3',raw_entry='0x3008b0',
                r0='word(sameguardcell) loaded41CCCC',raw_entry_SP=hex(C-20-28)),
            original_lock_body='3009CA assigns owner=wordF09090 and3009CC..DA links into owner+32;recursion incrementsushort+20;otherowner calls300D08.',
            original_release_body='3008F2 clears owner fordepth0/no waiter,3008F8/FE removes from ownedlist;doesnotclear backend+0/+4 stale links. Waiters insteadcall300BB8/358E70.',
            returned_endpoint_guard='Requireowner0/waiter0/depth0/tag41B544,originalcontroller ownedhead restored and no pending raw operation;do notrequire whole24 zeros/stale-link clearing.',
            exact_pointer_caller_pair_required=True,new_native_execution_not_performed=True),
        settings_scope=prior['settings_native_kernel_dependencies'],
        defer_manager_to_actual_Dispatcher=dict(
            do_not_controller_invoke='0x393a2d',backend='0x34f9b28',bytes=24,
            initialize='38D46C->3008A0,return38D470,tag38D860,onceF2CBF4.',
            original_ctor_lock='38D9D0->3009A0,return38D9D4;38DA0E->3008B0,return38DA12.',
            registry_check_lock='390150->3009A0,return390154;39017C->3008B0,return390180.',
            current_identity='Original38D9DA358D24 registers actualDispatcherTCB in34F9B40 inside405340;later4565CC390142 checks actualcurrent membership.',
            same_raw_shape_as_GIR=True,original_manager_frame_root_transition_unproven=True),
        minimal_explicit_guard_changes=dict(
            preparation_first_endpoint='Actualcontroller after APIs and explicit DBselection,BEFOREqueue/callbackbody;retain previous native five tasks/Thread/cleanupSignal.',
            code_and_readonly='Keep complete originalcodeimages,voice40,private12/player2,RXextension,GIR/font/DBbackup hashes and all heap/handle/descriptor/stackcanaries exactlyguarded.',
            normal_initialized_data='LoadedPlayerVM.initial_regions explicitlySKIPS F00000 copy. SettingsF06EF4..,F2953C/F29544 GIRonce and laterF2CBF4 aremutabledata,not covered by inherited whole-regionguard. Add boundeddeclared-input/native-writerjournal and relevant globals/TCB inventories;nevercallthem unchanged bythatguard.',
            zero_BSS='Five settingsbackends/new52token/GIRbackend,widget/display/font/menuSignal globals areoriginalzero-range data or guarded allocations;native writeeffects need typedshape/lifetime/ownedlist checks,not filebyte fantasies.',
            settings_retained_token='Settings52 bytes148E8EC includesaux148E908;must join existingGUI8805290 in exactTimerownedlist. Native3EC572/3EC57C lock/transfer,thenoriginal2CBD76/7A retagboth+16 to2CBF8C;no ret0constructor hook.',
            optional_initialized_GUI='Sevenevents below affect sixwords only in05400000;preparation/body journalphases separate. Requireactualeventorder/wholeexpectedregionagainstimmutableoriginal hostbaseline. Do notguestrestorebytes/resetwriterhistory.',
            seven_original_writer_events=writers,
            legacy_host_guard='OldConstructorVM.finish_constructor temporarilyreplaces hostinitial_regions[5400000] expectedbytes and restoreshostbaseline finally;that code doesnotwriteguest butmustnotbe invoked tofinish anactivekernel endpoint. Newscope spellsoutcomparison.',
            DB_selected_endpoint='OldFullTaskVM.verify_memory requires emptystatements plus baselineDB. Selectedrow/closednativeSQLhistory needs newexplicit endpointguard: selectedrow12,allotherssame,all statementsclosed,readonlybackuphash unchanged.',
            DB_restore='Whenactualcontrollerresumesaftercallback,restore row12 originalicon/size throughnative316277;requirefullDBbaselineagain. Do not restore byhostSQL/clearstatementhistory orcallgenericset_cell fromDispatcher.',
            no_new_alloc_fixedaddresses='Preparation adds originalcatalog/font/menuSignal allocations;derive newindependentSignal/holder/vector pointers fromnativeallocator/ctor results. Do notassume prior66913 S8809360/holder8809420/vector88094A0.',
            live_kernel='Reverify actualALL/ready/states/priorities/ownedheads/nativeframes/currentTCB and unchangedThreadtimednode/clock atdeclaredendpoint. SettingsconditionalPOST musthave actualconstructedtarget;noNULLpostallowance.',
            clock='Inherited353A9C virtualF09098+20 is lowerclockfixture,notphysicalIRQ;cannot silentlyadvance liveThreadtimeddeadline whileclaimingunchangedclock.',
            no_task_cleanup_safe_unload_foreground_or_device_proof=True),
        limits='21 complete bounded local CFGs,including2mixed-mode rawmutex wrappers;calleesare recordednotrecursivelyexecuted. The APIs/controllerplacement/stackarithmeticandguardproposal arestaticonly. Frozen66913 proves originalindependentSignal callbackentrybeforebody,notthisnewprep orMainMenubody/foreground/display/touch/acceptedpackage/directmusic/safeunload.')
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(target.relative_to(ROOT)),sha256=sha(target),
                         source_sha256=sha(Path(__file__).resolve()),CFG_count=len(functions),
                         own_dependencies=len(dependency_paths),verified_frozen_dependencies=len(frozen))))


if __name__ == '__main__':
    main()
