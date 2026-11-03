#!/usr/bin/env python3
"""Read exact parent sources and make offline native-controller input artifacts."""
from datetime import datetime,timezone
from pathlib import Path
import ast,hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_native_gui_foreground_boot import cfg,FileBackedRuntimeImage
from controller_gir_input_plan import make_config,input_layout,normalized_regions,gir_guard_formula,RAW_GIR_CALLS
STAGE=Path(__file__).parent
CONTRACT='staging/native-player-settings-vfp-context/gui-static/controller-gir-native-integration-contract.json'
V2='staging/controller-gir-prep-stock-v2/verification.json'
SETTINGS='evidence/firmware-analysis/native-settings-lazy-vfp-emulation.json'
MAPS='staging/native-player-settings-vfp-context/runtime/declared-mapping-preflight-v2.json'

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def source_class(module,name):
    path=ROOT/'scripts'/f'{module}.py';text=path.read_text();tree=ast.parse(text)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==name)
    methods={n.name:dict(first_line=n.lineno,last_line=n.end_lineno,
        source='\n'.join(text.splitlines()[n.lineno-1:n.end_lineno])+'\n')
        for n in cls.body if isinstance(n,ast.FunctionDef)}
    parent=None
    if cls.bases:
        base=cls.bases[0]
        if isinstance(base,ast.Attribute):
            imp=next(n for n in tree.body if isinstance(n,ast.Import) and any((a.asname or a.name)==base.value.id for a in n.names))
            target=next(a.name for a in imp.names if (a.asname or a.name)==base.value.id);parent=(target,base.attr)
        elif isinstance(base,ast.Name):
            same=any(isinstance(n,ast.ClassDef) and n.name==base.id for n in tree.body)
            if same:parent=(module,base.id)
            elif base.id!='object':
                imp=next(n for n in tree.body if isinstance(n,ast.ImportFrom) and any((a.asname or a.name)==base.id for a in n.names))
                target=next(a.name for a in imp.names if (a.asname or a.name)==base.id);parent=(imp.module,target)
    return dict(module=module,class_name=name,path=str(path.relative_to(ROOT)),first_line=cls.lineno,
                last_line=cls.end_lineno,file_sha256=sha(path.relative_to(ROOT)),methods=methods),parent

def main():
    target=STAGE/'observer-scopes-and-runnable-input-plan.json';binary=STAGE/'controller-gir-config-input.bin'
    if target.exists() or binary.exists():raise RuntimeError('Keep new input/static artifacts immutable')
    old=json.loads((ROOT/CONTRACT).read_text());v2=json.loads((ROOT/V2).read_text())
    proof=json.loads((ROOT/SETTINGS).read_text());mapping=json.loads((ROOT/MAPS).read_text())
    if not proof['all_passed'] or not proof['full_scoped_final_guards_passed']:raise RuntimeError('Native settings proof gate absent')
    protected=dict(old['verified_frozen_previous_source_hashes']);protected.update(old['source_sha256']);protected.update(proof['source_sha256'])
    for path,digest in protected.items():
        if sha(path)!=digest:raise RuntimeError('Frozen dependency changed: '+path)
    chain=[];current=('probe_native_settings_lazy_vfp_v2','LazySettingsVM')
    while current:
        row,current=source_class(*current);chain.append(row)
    sources={r['path']:r['file_sha256']for r in chain}
    for path in [CONTRACT,V2,SETTINGS,MAPS,'staging/native-player-settings-vfp-context/runtime-v2/terminal-metadata.json',
                 'staging/native-player-settings-vfp-context/runtime-v2/heap-settings-terminal-probe.json',
                 'staging/native-player-external-fonts/development-probe.json',
                 'scripts/analyze_native_sections.py','scripts/analyze_native_gui_foreground_boot.py',
                 v2['flat_binary'],v2['ELF'],str(Path(__file__).relative_to(ROOT)),
                 str(Path(__file__).with_name('controller_gir_input_plan.py').relative_to(ROOT))]:sources[path]=sha(path)
    spans=normalized_regions(mapping['memory_regions'])+[(0x18310000,0x18311000,3),(0x3ab1000,0x3ab2000,3)]
    plan=input_layout(spans)
    # Host-only pure layout controls. No Uc object, inherited VM or native API.
    controls=[]
    for name,regions,allocations,expected in [
        ('known_parent_mapping_admits_carve_and_free_config_page',spans,(),True),
        ('mapped_config_page_rejected',spans+[(0x18320000,0x18321000,3)],(),False),
        ('live_transition_allocation_in_component_page_rejected',spans,[(0xea10020,0xea100a0)],False),
        ('missing_component_parent_map_rejected',[r for r in spans if r[0]!=0xe800000],(),False)]:
        try:input_layout(regions,allocations);actual=True
        except ValueError:actual=False
        if actual!=expected:raise RuntimeError('Pure input layout control failed')
        controls.append(dict(name=name,passed=True,admitted=actual,firmware_executed=False))
    config=make_config();assert len(config)==76
    assert len(set([plan['config']['pointer'],plan['result']['pointer']]))==2
    stack=gir_guard_formula(0x9503f90)
    if stack['GIR_guard_cell']!=0x9503f50 or stack['raw_lock_entry_SP']!=0x9503f30:raise RuntimeError('Stack formula differs')
    binary.write_bytes(config)
    sources[str(binary.relative_to(ROOT))]=sha(binary.relative_to(ROOT))
    stock=NativeImage();image=FileBackedRuntimeImage(stock)
    new_functions={}
    for start,end in [(0x3730c6,0x3730ca),(0x5aed2c,0x5aed30),(0x11c9b8,0x11c9bc),
                      (0x3896f8,0x389724),(0x441368,0x4413c4),(0x44170c,0x441768),
                      (0x362a2c,0x362a90),(0x36294e,0x362a2c),
                      (0x140878,0x1408b0),(0x1408b0,0x1408c8)]:
        graph=cfg(image,start,[(start,end)])
        if not graph['local_CFG_complete']:raise RuntimeError('New local CFG incomplete '+hex(start))
        new_functions[hex(start)]=graph
    font_old=json.loads((ROOT/'staging/native-player-external-fonts/development-probe.json').read_text())
    assert font_old['completed'] and font_old['original_return']==0
    helper_scopes=[
        dict(index=1,entry='2CA82D',native_return_PC='EA10264',existing_dispatch=['JournalSettingsVM RAW_CALLS settings36','SettingsVM NOR26A43A/26A3E2/26A2D0','ConstructorVM only records keys121E/121F;19B falls through'],
            changes='Phase=settings or explicit new component phase; retain same bank journal without begin/reset. Keep settings_storage_active true,settings_catalog_fixture None. Audit19B native NOR event and original readback; stop if conditionalPOST targetF06F24 lacks actualTCB.'),
        dict(index=2,entry='2CABBD',native_return_PC='EA102DC',existing_dispatch=['JournalSettingsVM raw2CABFA/2CAC08 ->148E6CC','SettingsVM original lookup/read','GridVM 2CAB14 only hooks when settings_catalog_fixture non-None'],
            changes='No fallback settings record. Assert 4bytes/pointer in18001000..18009000/value1; output cell P+12 remains resident.'),
        dict(index=3,entry='395981',native_return_PC='EA10380',existing_dispatch=['BootstrapVM logs3896F8','GridVM.observe raw_allocate@3954E4/39544C','WidgetVM.invalid_memory maps recoveredBSS34F9B60','JournalSettingsVM F0 writes38971E into construction registry'],
            changes='Pre-map/provenance-ledger new Widget24 BSS before wholezone snapshots; preserve original12byte vector backing/list sentinel/native16-byte registration. Original3730C6/C8 are BX LR, not a host no-op.'),
        dict(index=4,entry='2DB541',native_return_PC='EA103DC',existing_dispatch=['BootstrapVM logs3896F8','GridVM raw_allocate@3954E4/39544C','WidgetVM invalid_memory BSS34A5614 already bootstrap page','JournalSettingsVM native F0 registration stores'],
            changes='Same native vector/list/backing guard as Widget; original5AED2C/2E are BX LR; no new raw semaphore caller.'),
        dict(index=5,entry='25DC81',native_return_PC='EA10438',existing_dispatch=['Unhooked original hash getter in known loaded code'],
            changes='Require actual returned40A730 equals readonly GIR+12; no new OS service/host hash result.'),
        dict(index=6,entry='41CC47',native_return_PC='EA104BC',existing_dispatch=['JournalSettingsVM init3008A0/caller41B1B2','NativeTaskMutexVM rejects rawcaller11C510 without newinstance table','GridVM raw allocation in88..8C'],
            changes='Add two exact instance RAW_GIR_CALLS, keep nativebody/owner/list/epilogue. Capture APIentryP, localP-48/guardP-24/rawlockP-56/unlockP-48. Native catalog vector cold gate must not be reset or seeded.'),
        dict(index=7,entry='41B15B',native_return_PC='EA10534',existing_dispatch=['Native getter/once guard385448','Bootstrap logs original3896F8 only if first catalog cold initialization'],
            changes='Actualvector34F7730 exactlyone24record; begin/end/cap in88..8C plus strict actual live raw allocation/canaries and whole record serialization. Getter itself has no lock.'),
        dict(index=8,entry='4DF249',native_return_PC='EA10654',existing_dispatch=['TextVM logs font initializer','Original14B4014 records/static callback registry','GridVM native registration allocation'],
            changes='Snapshot/map known startup-zero font records and vector14B6984; preserve original12FAB5 registry callback plus lifetime. Original r0 discarded.'),
        dict(index=9,entry='4DE237(1)',native_return_PC='EA106B4',existing_dispatch=['ExternalFontVM font lowerFILE_IO when external_IO_active','TextVM tracks14089A malloc prefix/388804 query/1408B0 releases','OuterVM <=4096 opaque handle allocation','HeapDescriptorVM native query/descriptor translation','HeapSettingsVM exact heap rawlock/native current+56','LazyVFPState first/samecontroller native handler if needed'],
            changes='Enable font lowerprovider explicitly; exact raw backup ledger and BSS destination provenance; journal hostinput separately from CPU stores. Keep fonts13 inventory (3embedded/8present/2missing), closedexternal_files and VPMfiles separate. Fontreturn0 not glyphsuccess. Stop any large non11A254 resource allocation/newownerFP scope.'),
        dict(index=10,entry='4A388B',native_return_PC='EA10724',existing_dispatch=['ContextVM shared_signal_entries and connection snapshots','GridVM raw_allocate','Original441368/44170C/362A2C/36270C/358B58 subscription chain','SelectionPlayerVM removes3954F0 free hook, executes nativeholder destructor','BootstrapVM actual3896F8 registration'],
            changes='Full live8x36 MenuSignal objects3471B58..3471C78/newconnection/holder/vectors/input lifetimes and native temporary destruction. No automatic use of signal_inventory requiring80-byte Signal type on these36-byte objects; serialize typed fields rather than fakevtable.'),
        dict(index=11,entry='316277',native_return_PC='EA107E8',existing_dispatch=['GridVM recordssetter','PageVM recordssetter','SelectionPlayerVM engine prepare/bind64/step/finalize/completion lowerfixtures','Unhooked original2361AE/23762C/2378AE/2376B8 wrappers'],
            changes='Admit only companion inputstores menu+24,+28/DBword0 atEA108B0/EA108B8; new actual selectedrow12+allotherrowsbaseline+every closedstatement guard. Do not use generic set_cell/lookup/finish or old empty-statements predicate.')]
    report=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        static_only=True,new_emulation_executed=False,device_io=False,sounds_emitted=False,frozen_source_modified=False,
        source_sha256=sources,verified_frozen_dependency_hashes=protected,
        frozen_dependency_count=len(protected),parent_class_chain=chain,
        actual_observe_dispatch=dict(chain='LazySettingsVM -> HeapSettingsVM -> JournalSettingsVM -> MainmenuSettingsPrepVM -> IndependentSignalVM -> SignalVM -> FullTaskVM -> NativeTaskMutexVM',
            explicit_bypass='NativeTaskMutexVM.observe calls DispatcherVM.observe directly at its tail; lower Owner/DispatcherOwner/Reacquire/TimerOwner/KernelContext/Roundtrip observe methods are bypassed in activekernel except per-task native handling above. DispatcherVM -> BootstrapVM -> PoolClockVM -> ControllerVM -> ConstructorVM -> MetadataVM -> SettingsVM -> HeapDescriptorVM -> ContextVM -> MainMenuVM -> ResourceCacheVM -> ResourceVM -> RenderingVM -> ExternalFontVM -> TextVM -> GridVM -> PageVM -> WidgetVM -> SelectionPlayerVM -> LoadedPlayerVM -> OuterVM -> SelectionVM -> RegistryVM -> VpmFilesystem.'),
        first_new_boundaries=[
            dict(order='before first native call',kind='component mapping admission',path='scripts/probe_native_mainmenu_controller.py',method='ControllerVM.__init__',line=22,
                fact='EA10000/EA11000 already lie in existingRW E800000..EFFFFFF transition input; repeatedmem_map will fail',
                remedy='Fresh new runner validates no liveallocation intersection, declares code/BSS as reserved span in existing unused mapping, loads exact inputflat/BSS4 once then RXprotecttextpage. Exclude reservedspan from future lowertransition allocations.'),
            dict(order='sixth original helper, before3009A0 body',kind='first known rejected native caller',path='scripts/probe_native_task_mutex.py',method='NativeTaskMutexVM.observe',line=166,
                original_chain='41CC46 ->41B198 initializesnativebackend/tag ->11C504 raw3009A0 LR11C511',
                upstream_gap_path='scripts/probe_native_heap_settings_boot.py',upstream_gap_method='HeapSettingsVM.__init__',upstream_gap_line=50,
                fact='Instance RAW_CALLS replaced by settings36; GIRpair absent. NativeTaskMutexVM allows only six knownC++/condition families and rejects11C510.',
                remedy='Newinstance RAW_CALLS.update(RAW_GIR_CALLS); do not modify old global/class table or raw guestbytes.'),
            dict(order='postprep final guards',kind='known old predicate rejects legal effects',path='scripts/emulate_native_task_runtime_full.py',method='FullTaskVM.verify_memory',line=145,
                fact='Wholeinitial_regions requires optionalGUI unchanged/conditionalwritesempty; line165 requires no SQLstatements andbaseline DB. v2/fonts/init and cellselection need newbounded scopes.')],
        runnable_config_input=dict(layout=plan,config_file=str(binary.relative_to(ROOT)),config_sha256=sha(binary.relative_to(ROOT)),
            config19_words=[hex(v)for v in struct.unpack('<19I',config)],result80_initialization='Native component zeros result; host onlydeclaresnewguardedstorageA5 beforecall',
            settings_gate=dict(proof=SETTINGS,sha256=sha(SETTINGS),all_passed=True,original_initializer_return0=True,
                first_samecontroller_FP_only=True,proof_requires_fresh_reproduction_by_root_newrun=True),
            mapping_basis='Frozen35parentconstructor regions plus sourceverified v2UND18310000/FPowner3AB1000 pages. Root must rescan actualcurrentregions/liveallocations and reject any conflict; thisstaticplan didnotmap/execute.',
            catalog_domain='Existing GridVM lowerC++ allocation88..8C input domain; actualreturnedallocation/capacity/canaries still mandatory. Not native18301000 heap/physicalmalloc.'),
        guard_formulas={k:hex(v) for k,v in stack.items()},raw_GIR_table=[dict(entry=hex(a),caller=hex(c),**{k:hex(v)if isinstance(v,int)else v for k,v in s.items()})for (a,c),s in RAW_GIR_CALLS.items()],
        original11_helper_observer_changes=helper_scopes,new_complete_bounded_CFG_count=len(new_functions),new_functions=new_functions,
        source_helper_host_controls=controls,
        exact_additional_resource_scopes=dict(
            BSS='Premap only knownstartup-zero provenance for wholezone snapshots; never clear existingmappednative data. Widget34F9B60(24),display34A5614(24),GIR34F7730(36),fontmetadata14B3C60(832)/builtincontext14B3FB8(92,original265F16 bzero5C)/records14B4014(10608)/vector14B6984(12),MenuSignals3471B58(288). Nativeconstructor output still required.',
            initialized_GUI='Keep continuous normalF0 bankjournal; optional054 wholeexpected comparison against frozenbaseline with phase-labeled actual sevenconditional writers, no guestrestore or baselinehistoryreset.',
            componentCPU='DeclaredBSS4/result80/actualcontrollerstack and onlythreeDBfixture inputstores. Resultinit usescompiledSTRD, so observeactualhookwidth4+4 or8 and preservebefore/value before implementing fullresultzone replay. Separate exactflat bytes/ARM disasm source from MAIN-origin CPU journal.',
            readonly_GIR='Full29146504 payloadsha f3bd416bcafd3e9ce9388fa674d29dd4da0d73223dab8a99ff79e9a2e47d3563,directory731912/platform40A730; keep payloadlive with catalog.',
            rawsems='GIR owner/waiter/depth0/tag41B544, full24equals actualnative lastunlockepilogue incl stale links. All ordinaryownedhead0; keep Timer dualtokens GUI6048E8/settings2CBF8C and Thread/node/time unchanged.',
            heap='Current GIR/widget/menu allocate inGrid88..8C; font opaque inputs080400..080F andresource09A domains, outside declarednative8KiB18301000. Retain exact whole8KiB recipe if actualunchanged; do not weaken just because newlowerfixture allocations exist. Nativephysicalallocator remains unproven.'),
        old_external_font_allocation_inventory=dict(source='staging/native-player-external-fonts/development-probe.json',
            exact_old_count=len(font_old['font_handles']),lengths=sorted({r['length']for r in font_old['font_handles']}),
            new_currentcontroller_font_allocations_not_executed=True),
        forbidden_legacy_calls=['register_stock_GIR() ->genericinvoke fixedSTACK','set_cell()/lookup() ->genericinvoke fixedSTACK',
            'finish()/verify_released() ->fixedSTACK/outputwrites/inventorychanges/frozendevelopmentartifactwrite',
            'Manager393A2C fromcontroller (identitybelongs actualDispatcher405340)'],
        remaining_uncertainty='Staticcontrolflow/observer routing predicts knownboundaries only; originalrecursivecallees may expose new exactcaller/provider/admission needs. Allhelpersactualreturns/font/SQL inventories/componentCPUjournal/foreground are pending rootnative runtime; flags15/inputconfig aredeclaredfixtures,not devicecapabilities.')
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(target.relative_to(ROOT)),sha256=sha(target.relative_to(ROOT)),
                         parentclasses=len(chain),directdeps=len(sources),frozensources=len(protected),newCFGs=len(new_functions),configsha=sha(binary.relative_to(ROOT)))))

if __name__=='__main__':main()
