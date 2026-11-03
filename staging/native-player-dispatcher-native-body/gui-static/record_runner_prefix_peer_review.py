#!/usr/bin/env python3
"""Read-only runtime-record/schema and bounded MAIN review; no VM import."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
BASE='staging/native-player-dispatcher-native-body/'
RUNTIME=BASE+'runtime/'
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def read(p):return json.loads((ROOT/p).read_text())
def save(name,doc):
    p=STAGE/name
    with p.open('x') as out:json.dump(doc,out,ensure_ascii=False,indent=2);out.write('\n')
    return dict(path=str(p.relative_to(ROOT)),sha256=sha(str(p.relative_to(ROOT))))

def main():
    inputs=read(RUNTIME+'inputs-before-run.json');meta=read(RUNTIME+'terminal-metadata.json')
    prefix=read(meta['cold_prefix']);terminal=read(meta['probe'])
    assert meta['session_id']==67576 and meta['terminal_exit_code']==1
    assert sha('scripts/probe_native_dispatcher_body_fp.py')==meta['runner_sha256']=='a0315eadfe40ab66ea8e601c236d9c358731ed1513983a3a2e2bc88c9b05a4e0'
    assert sha(meta['GUI_observer'])==meta['GUI_observer_sha256']=='a323501d1af12aae3d4ed87822165b8ed6fea849fe767ba9ed08fdda0281ac5c'
    assert sha(meta['runner_snapshot'])==meta['runner_sha256']
    assert sha(meta['cold_prefix'])==meta['cold_prefix_sha256']==terminal['cold_prefix_evidence_sha256']
    protected=read(BASE+'previous-audit.json')['protected_sources'];assert len(protected)==781
    bad=[p for p,h in inputs['source_sha256'].items() if sha(p)!=h];assert not bad,bad
    assert all(sha(p)==h for p,h in protected.items())
    boot=prefix['cold_boot']['whole_boot_zones'];extra=prefix['extra_zones']
    assert len(boot)==5 and len(extra)==22 and len(prefix['component_calls'])==11
    comparisons=[]
    for zone in extra:
        later=terminal['journal_zones'][str(int(zone['start'],16))]
        n=len(zone['stores']);assert zone['stores']==later['stores'][:n]
        comparisons.append(dict(start=zone['start'],prefix_events=n,later_events=len(later['stores']),
            prefix_is_unchanged_initial_segment=True))
    assert boot==terminal['cold_boot_zones']
    assert prefix['component_calls']==terminal['component_calls']
    assert prefix['whole_cache_journal']==terminal['whole_cache_journal']
    assert prefix['cold_lazy_handler_rows']==terminal['cold_lazy_handler_rows']
    cache_cpu=sum(e['events'] for e in prefix['whole_cache_journal'] if e['metadata']['kind']=='exact_original_MAIN_CPU_store')
    cache_raw=sum(1 for e in prefix['whole_cache_journal'] if e['metadata']['kind']=='raw_exact_backup_file_input')
    assert cache_cpu==prefix['native_cache_CPU_store_count']==prefix['memory']['native_cache_CPU_store_count']==356834
    assert cache_raw==112
    failure_path=BASE+'prefix-verifier-v1-failure/failure.json';failure=read(failure_path)
    assert failure['verifier_assertion_failed'] and not failure['positive_proof_written']
    paths=[str(Path(__file__).resolve().relative_to(ROOT)),'scripts/probe_native_dispatcher_body_fp.py',
        meta['GUI_observer'],'scripts/seal_native_dispatcher_body.py','scripts/verify_native_dispatcher_prefix.py',
        'scripts/native_dispatcher_multiowner_vfp.py','scripts/probe_native_multiowner_vfp.py',
        'scripts/probe_native_cold_fp_controller.py','scripts/native_cold_fp_guard_copies.py',
        'scripts/probe_native_heap_settings_boot.py','scripts/probe_native_task_mutex.py',
        'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin',
        'scripts/verify_native_dispatcher_prefix_v2.py','evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json',
        RUNTIME+'inputs-before-run.json',RUNTIME+'terminal-metadata.json',meta['probe'],meta['cold_prefix'],
        meta['runner_snapshot'],BASE+'previous-audit.json',failure_path,
        BASE+'prefix-verifier-v1-failure/source-at-verification.py',
        BASE+'prefix-verifier-v1-failure/actual-assertion-trace.txt']
    base=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_review_and_supplied_record_crosscheck_only=True,
        guest_execution=False,VM_imported_or_instantiated=False,device_IO=False,
        frozen_sources_proofs_contracts_or_canonical_modified=False,
        source_sha256={p:sha(p) for p in paths},verified_runtime_source_dependencies=inputs['source_sha256'],
        protected_registry=dict(path=BASE+'previous-audit.json',sha256=sha(BASE+'previous-audit.json'),
            count=781,changed_or_missing=bad),verified_protected_sources=protected)
    peer=save('runner-prefix-peer-review-a0315e.json',dict(base,
        reviewed_runner_sha256=meta['runner_sha256'],reviewed_mixin_sha256=meta['GUI_observer_sha256'],
        prefix_isolation=dict(source='scripts/probe_native_dispatcher_body_fp.py:218',
            implementation='221 JSON encode/decode deep-copies result with5boot/22component/initializedGUI/SQL/font/FP prefix summaries.222-224 add still-live component/cache lists;225 synchronous exclusive-file JSON dump finishes before229 begin_body_observer. The file is isolated; the in-memory prefix variable itself is not a full deep copy of added lists.',
            record_crosschecks=dict(boot5_equal_later_cold_zones=True,component11_equal_later_records=True,
                cache8401_rows_equal_at_current_boundary=True,cold_FP_rows_equal_later_prefix_copy=True,
                component22_stores_preserve_initial_segment=comparisons),
            immutable_file_sha256=sha(meta['cold_prefix']),
            prefix_flags=dict(completed=prefix['completed'],cold_prefix_full_guards_passed=prefix['cold_prefix_full_guards_passed'],
                body_full_guards_passed=prefix['body_full_guards_passed'])),
        sealer=dict(source='scripts/seal_native_dispatcher_body.py:14',
            checks='Every executed-input source hash; runner/snapshot/input/probe runner hash equality; terminal-exit==completed?0:1;prefixhash; independent ownsealer/source/FP/GUI hashes. Actualexec exit supplied byroot and metadata captured67576/1.',
            schema_matches_current_terminal=True,FP_rows='Native bridge starts a separate rows list; post_cold_FP_rows=1 refers to newD row, not the retained first/same-controller priorrow.',
            limits='completed would mean this bounded attempt returned;body_full_guards_passed and physicalApp/directmusic/package_acceptance stayFalse.'),
        verifier=dict(source='scripts/verify_native_dispatcher_prefix.py',sha256=sha('scripts/verify_native_dispatcher_prefix.py'),
            boot_and_component_field_schema_matches=True,cache_raw_path_and_kind_schema_matches=True,
            blocking_finding=dict(line=61,code='cpu==prefix[native_cache_CPU_store_count]==356833',
                actual_per_run_CPU_events=cache_cpu,actual_prefix_field=prefix['native_cache_CPU_store_count'],
                actual_memory_field=prefix['memory']['native_cache_CPU_store_count'],raw_backup_chunks=cache_raw,
                effect='Rejects this valid independently replayed prefix because it hardcodes the priorrun event count.',
                next_unique_source='Require independent cpu==both actualcurrent fields; raw==actualproven chunks and scenario-specific inventories. Preserve failedoldsource/process artifacts. No guest rerun or normalization of guest evidence.'),
            actual_failure=failure,
            verification_status='Version1 assertion failed and is preserved; the separately sourced version2 independent verifier subsequently passed this scoped prefix.',
            version2=dict(source='scripts/verify_native_dispatcher_prefix_v2.py',sha256=sha('scripts/verify_native_dispatcher_prefix_v2.py'),
                proof='evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json',proof_sha256=sha('evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json'),
                CPU_store_events=356834,raw_backup_chunks=112,scope='Supplied independently replayed cold prefix only; later Dispatcher body remains incomplete.')),
        actor_wiring=dict(source='scripts/probe_native_dispatcher_body_fp.py:135',
            firstentry_stop='Root returns before activating/calling mixin; nextresume ofsamePC enablesmixin once.',
            handled_entries='True only adds native init/raw/clock entry observation and skips oldhook; old3008AE/300A0A/30092A consumers remainFalse delegated.',
            corrected_ARM_allocator_gates='Exact3954CC/39544C requireARM; returnsThumb. Both actualmanager andcleanup records successfully reached laterbody in67576.',
            no_new_source_wiring_blocker_observed=True),
        actual_terminal=dict(session=67576,authoritative_exit=1,completed=terminal['completed'],
            cold_prefix_full_guards_passed=terminal['cold_prefix_full_guards_passed'],body_full_guards_passed=terminal['body_full_guards_passed'],
            callback_entry_seen=terminal['callback_entry_seen'],callback_return_seen=terminal['callback_return_seen'],
            error=terminal['error'],FP='One realfirst C→D native save/exceptionreturn/retry. NoDrestore and noD→C returnsequence observed.',
            manager_observed='2 init+tag continuations,2 of6 managerraw continuations,2 clockread/stores,13 oldcleanupnodes+newnode append and native managercache publication; fullactor verifier not reached.'),
        claims=dict(full_Dispatcher_body_verified=False,foreground_verified=False,full_multiowner_scheduling_verified=False,
            physical_App_or_direct_music_or_modified_package_acceptance_verified=False)))
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    ranges=[(0x405386,0x405396),(0x39720C,0x397226),(0x396B3E,0x396BAE),
            (0x369438,0x36946A),(0x3697B8,0x3697F4),(0x39799E,0x3979BC)]
    evidence=[]
    for lo,hi in ranges:
        ins=list(md.disasm(stock.read(lo,hi-lo),lo));assert ins[-1].address+ins[-1].size==hi
        evidence += [dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in ins]
    literals={hex(a):hex(stock.word(a)) for a in [0x396E78,0x396E7C,0x3979BC,0x369768,0x369758,0x3698D4,0x3698D8]}
    assert literals['0x396e78']==literals['0x3979bc']=='0x2d1654c'
    data=stock.read(0x3979C0,64);tag=data.split(bytes([0]),1)[0].decode('ascii')
    boundary=save('native-396b4e-next-actor-boundary.json',dict(base,runner_prefix_peer_review=peer,
        evidence_kind='Exact bounded MAIN and supplied67576 terminal record; no new guest execution',
        observed_registers=terminal['registers'],observed_actor='actualDispatcher8804FB8/current same',
        actual_FP_owner='0x8804fb8',raw_mutex_owner_tag_class='Not serialized for2D1654C. FPowner is not rawmutexowner; no runtimezero/tag/initialized assertion.',
        chain=['405390 original39720C','397214 original396B3E','396B4A original3009A0 beforebody, rejectedguard'],
        caller_shape=dict(function='0x396b3e',caller_function='0x39720c',caller_return='0x397218',
            entry_SP_derived='0x8804f40',push_bytes=12,local_bytes=12,raw_SP='T-24=0x8804f28',
            raw_entry='0x3009a0',raw_call='0x396b4a',continuation='0x396b4e',LR='0x396b4f',
            pointer='0x2d1654c',native_epilogue='0x300a0a',
            unlock_call='0x396b9e',unlock_continuation='0x396ba2',unlock_LR='0x396ba3',unlock_SP='T-24',
            output_byte='Afterunlock396BA6 writes registerbyte stack(T-16) to actualcaller outputR5=Touter-16. Boundto originalDstack;unknown value nothostsupplied.'),
        original_initializer=dict(entry='0x39799e',call='0x3979a2',raw_init='0x3008a0',continuation='0x3979a6',LR='0x3979a7',
            pointer='0x2d1654c',tag='0x3979c0',tag_ascii=tag,tag_store='0x3979aa',SP='ctor entrySP-8',
            next='3E98AC nonzero conditionally calls396D6E. Full hardware/bus init is not proven and must not be inferred from tag or return.',
            execution_in67576='No corresponding nativeinit row serialized; initialization/nativeowner status remainsunknown.'),
        nested_required_scopes=dict(slot=0,slot_table='0x2d1f9d0',stride=32,backend='0x2d1f9d4',
            lock=dict(function='0x36944a',call='0x369458',continuation='0x36945c',LR='0x36945d',SP='captured36944A entrySP-16 =0x8804f18 on this path'),
            unlock=dict(function='0x3697b8',call='0x3697c6',continuation='0x3697ca',LR='0x3697cb',SP='captured3697B8 entrySP-8 =0x8804f20 on this path'),
            record_writer='36945E sets slotrecord+1C to1;3697C2 clears to0 beforeunlock. Whole32record must be preserved/journaled, not just24backend.',
            callback_table='0x2d1fa30',callbacks='369438 loads table+16 and tailBX ifnonzero;3697CC loads table+0 and BLX ifnonzero. Require originalcurrent actualcallback provenance ifpresent; absence must beactualread.',
            no_callback='Original3697CC starts status8 and returns8 ifcallback0; this is originalabsence branch, not a hostsuccessfulstub.'),
        next_strict_input_observations=['Capture actual2D1654C whole24/tag/class/owner before newadmission and originalinit provenance or explicit fresh startupzero input qualifier.',
            'Capture2D1F9D0 whole32 slot0+2D1FA30 callbacktable24 and source/initialized/zero provenance; do not assume nulls or patch callbacks.',
            'Extend only exactactualD rawpairs with containingfunctionSP/nativepending epilogue/actualcaller checks and ordinaryowned/waiter/depth histories.',
            'Declare new 0x2D16000/0x2D1F000 pages only within verified startupzero range without resetting existing bytes; replay exact writes and preserve all cold prefix/old owned semaphores/TCB108.',
            'Unknowncallback or396D6E path remains a newboundary, not a firmwarefault or fullhardwareclosure.'],
        exact_literals=literals,exact_original_instruction_evidence=evidence,
        root_or_manager_or_callback_completed=False))
    print(json.dumps(dict(peer=peer,boundary=boundary,cold_cache_CPU_events=cache_cpu)))

if __name__=='__main__':main()
