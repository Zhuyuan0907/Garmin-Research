#!/usr/bin/env python3
"""Short static record only: no observer import, VM or guest execution."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,json

ROOT=Path(__file__).resolve().parents[3]
BASE='staging/native-player-dispatcher-native-body/'
OBSERVER=BASE+'gui-static/dispatcher_actor_observer.py'
AUDIT=BASE+'previous-audit.json'
EXPECTED='a323501d1af12aae3d4ed87822165b8ed6fea849fe767ba9ed08fdda0281ac5c'
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

def main():
    source=(ROOT/OBSERVER).read_text();tree=ast.parse(source);compile(source,OBSERVER,'exec')
    assert sha(OBSERVER)==EXPECTED
    forbidden={'emu_start','mem_write','reg_write','put','ret','invoke','kernel_invoke'}
    assert not [(n.func.attr,n.lineno) for n in ast.walk(tree) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Attribute) and n.func.attr in forbidden]
    registry=json.loads((ROOT/AUDIT).read_text())['protected_sources'];assert len(registry)==781
    bad=[p for p,h in registry.items() if sha(p)!=h];assert not bad,bad
    deps=[OBSERVER,str(Path(__file__).resolve().relative_to(ROOT)),AUDIT,
          'staging/native-player-dispatcher-fp/gui-static/dispatcher_actor_shapes.py',
          'staging/native-player-dispatcher-fp/gui-static/dispatcher-actor-guard-contract.json',
          'scripts/probe_native_dispatcher_body_fp.py','scripts/native_dispatcher_multiowner_vfp.py',
          'scripts/probe_native_cold_fp_controller.py','scripts/probe_native_dispatcher_condition.py',
          'scripts/probe_native_task_mutex.py','scripts/probe_native_heap_settings_boot.py',
          'scripts/probe_mainmenu_native_settings_journal.py','scripts/probe_native_controller_gir_component.py',
          'scripts/emulate_native_player_menu_loaded.py','evidence/firmware-analysis/main_02bd.bin']
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,
        observer_imported=False,VM_instantiated=False,guest_execution=False,device_IO=False,
        frozen_or_canonical_sources_modified=False,foreground_or_completion_proved=False,
        observer_source=OBSERVER,observer_sha256=EXPECTED,syntax_compile_passed=True,
        AST_no_guest_write_register_restore_stub_or_invoke_calls=True,
        source_sha256={p:sha(p) for p in deps},verified_protected_sources=registry,
        protected_registry=dict(path=AUDIT,sha256=sha(AUDIT),count=len(registry),changed_or_missing=bad),
        interface=dict(class_name='DispatcherActorObserverMixin',
            init='init_dispatcher_actor_observer() after existing super().__init__',
            hook='if dispatcher_body_active and observe_dispatcher_actor(uc,address,size,data): return; otherwise existing super().observe',
            root_fields=['dispatcher_body_active','dispatcher_task','dispatcher_callback_SP','manager_object'],
            partial_record='snapshot_dispatcher_actor_observer()',
            complete_scope='verify_dispatcher_actor_observer() only after actual60935C callback return; this is additional actor validation, never a replacement for root full guards'),
        entry_modes=dict(actual_callback='Thumb405340;D8804FB8/current same;SP actual8804F78/LR60935D',
            manager_allocate='ARM3954CC LR393A3F; originalThumb393A3A BLX;returnThumb393A3E',
            cleanup_allocate='ARM39544C LR389707;originalThumb389702 BLX;returnThumb389706',
            ARM_veneer_bytes='00c09fe51cff2fe1',
            correction='Initial unrun draft incorrectly requiredThumb for these ARM entries; final source fixes only the two exact allocator entry modes. Prior constructor-only preflight is a separate draft-source record.'),
        initialization=dict(exact_pairs=['3008A0/38D470','3008A0/392EFA'],
            parent_compatibility='Append existing backend_initializations and active_backend row. Existing observe_backend_write collects exact six nativezero stores;3008AE returnsFalse for parent completion. Actual continuations check native returnedSP/r0/whole24zero before original tag CPU hook.',
            tag='Future original38D474/392EFC store, never used as a synthesized entry observation; native after-store opcode/address/value/before bytes journaled.',
            manager='Native getter3954CC(E50) declaredlower raw allocation→392DE4 actualargument→393A46/F2CD0C native publish. No controller construction or guestslot write.'),
        raw=dict(exact_six_manager_pairs=True,current_TCB_pairs=['3009A0/1C0618','3008B0/1C0634'],
            shape='Frozen8275e21a helper; actual containing entrySP and original direct or register-bound indirect MAIN call; actualD/live24/tag/class/nonretainedtoken.',
            ledger='Append native_mutex_runs/task_mutex_ops[D] and local rawreturns. 300A0A/30092A returnFalse for NativeTaskMutexVM epilogue/r3/caller/owner/count consumption. Actual caller separately checks original result/sameSP.',
            stale_links='Whole native24 journal; preserve +0/+4 stale words; final manager owner/waiter/depth0 and tag/class checked.',
            controller_scope='No parent actor guard edited; additional heap/settings raw callers underD are still unadmitted boundaries.'),
        clock=dict(exact_entry='353A9C with onlyLR38D913/38D91F; fixed currentF09098=0',
            handled='True bypasses only parenthost+20; original read-only getter executes without register/PC return stub.',
            writers='Exact original38D918/38D91E actualr6=M+340 targetM+378/+37C value0; separate whole8 CPU before/value/opcode replay and actual after-store observation.'),
        cleanup=dict(exact_registration='3896F8 LR38D4B5;args34F9B40/20DC53/C7F980',
            before='Snapshot actual nonzero-or-zero head3AAEC70 and full bounded reachable live16 nodes; no observer BSS mapping/clearing.',
            new_node='Original39544C(16) actual return389706, exact live raw16 allocation/canary; no live-node reuse.',
            ordered_stores=['38970E callback','389710 object','389714 argument','38971C actualoldhead','38971E publishnewhead'],
            after='Original getter6E0C08 must returnhead; actualoldhead validated before38971A read. CPU-only chronological journals and pure ordered-chain checks;actual3896F8 return0 at38D4B4.',
            lifetime='Every previousnode16 immutable/live; processcleanup differs from kernelFP/heapexitlisteners. Registration is not safe cleanup/unload.'),
        root_actor_wiring_review=dict(path='scripts/probe_native_dispatcher_body_fp.py',sha256=sha('scripts/probe_native_dispatcher_body_fp.py'),
            reviewed='Only constructor→init, exact firstentry stop-before-mixin/resume activation, pre-Signal whole body-zone capture, own hook ordering, and native-pending delegation; no execution and no new whole-run closure.',
            observed_source='Root declares34F9000/3AAE000 startupzero mappings withoutreset, initializesmixin aftersuper; stops405340 before activatingmixin; secondresume makesactualbodyactive; helper True returnsbeforeparent, False delegatesparent; coldprefix immediatelyserialized before live histories append.',
            no_static_wiring_blocker_remaining=True),
        remaining_boundaries=['Original font/cache/GIR D actor extensions remainunadmitted',
            'Unknown353A9C/cleanup3896F8 caller stops rather than genericstub',
            'FullM/page/widget/initializedGUI journals and inheritedsevenwriter guard remainroot responsibility',
            'MultiownerFP actualintegration/final inventories/scheduling/controllerWAIT return must be actualnewrun evidence',
            'No foreground/touch/deviceApp/acceptedmodifiedpackage/safeunload proof'])
    target=ROOT/BASE/'gui-static/dispatcher-actor-observer-integration-review.json'
    with target.open('x') as out:json.dump(doc,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps(dict(path=str(target.relative_to(ROOT)),sha256=sha(str(target.relative_to(ROOT))),
        observer_sha256=EXPECTED,protected_count=len(registry),direct_dependencies=len(deps))))

if __name__=='__main__':main()
