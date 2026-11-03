#!/usr/bin/env python3
"""Compile/AST/source-hash contract only; no runtime helper import or VM."""
from pathlib import Path
from datetime import datetime, timezone
import ast, hashlib, json, py_compile, struct

ROOT=Path('/root/garmin')
BASE='staging/native-player-dispatcher-native-body/fp-static/'
SOURCE='scripts/native_dispatcher_multiowner_vfp.py'
SOURCE_HASH='5dbe3df3dc3f220dd658d6c25408b1292025a5009338cc89faafc74b671aeff8'
OUT=BASE+'native-dispatcher-vfp-integration-contract-5dbe3df3dc3f.json'
PINNED={
 SOURCE:SOURCE_HASH,
 'scripts/probe_native_multiowner_vfp.py':'8fc0a2bcf6319f9a2b5a00c15c1f9c213b1717f6c55105b0785433e594a4cab4',
 'scripts/verify_native_multiowner_vfp_micro.py':'9f83f16fc7ab6800a524d6a5a73949dfe439e903b23ce55ea9f71f9b530abf3e',
 'scripts/probe_native_lazy_vfp.py':'ece96af88a411bbaca92715c45595a20d59b0f26e928f5961f9026f6acf3ca24',
 'scripts/probe_native_cold_fp_controller.py':'0c4f4bb7e0077da701da225c183c262fa14346685dd605994438bd3edac1be3c',
 'scripts/native_cold_fp_guard_copies.py':'b6849ca9dc226078ac83754ea9bb02acae60a8cae13a3f6da95f8c1ba278079b',
 'evidence/firmware-analysis/main_02bd.bin':'10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8',
 'staging/native-player-dispatcher-fp/fp-static/native-multiowner-vfp-observer-contract.json':'142ee737b8f7dd75e24fc52e6f96d1a17aba40c5c20b932b38634ec574efb419',
 'staging/native-player-dispatcher-fp/fp-static/native-vfp-retry-and-control-branch-clarification.json':'ed5ac88a1a7578829e961b6f9ef867a170b74d5788a1db6398277ff23c1984c8',
 'staging/native-player-dispatcher-fp/fp-static/multiowner-vfp-helper-peer-review-8fc0a2bcf631.json':'49a54639b4bb639b4d9b8247cb48bc7a4654d3e894b0a2f35bcb92994cf6cb67',
 'evidence/firmware-analysis/native-cold-fp-controller-emulation.json':'be78a70d2be6b94b0d8fecb6973f805dfe85b2618b1986b3ccae98b1d53ce5a0',
}

def sha(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def require(value,message):
 if not value:raise AssertionError(message)

def main():
 require(not (ROOT/OUT).exists(),'Unique contract already exists')
 for p,h in PINNED.items():require(sha(p)==h,'Pinned source changed '+p)
 s=(ROOT/SOURCE).read_text();tree=ast.parse(s)
 forbid=('emu_start','emu_stop','mem_write','reg_write')
 require(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in forbid for n in ast.walk(tree)), 'New source contains forbidden mutation/execution call')
 cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='NativeDispatcherMultiOwnerVFPState')
 require([ast.unparse(n) for n in cls.bases]==['MultiOwnerVFPState'],'Inherited exact observer changed')
 methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
 delegates={}
 for name in ['__init__','enter','observe','journal','verify']:
  node=methods[name]
  calls=[ast.unparse(n.func) for n in ast.walk(node) if isinstance(n,ast.Call)]
  require('super().'+name in calls,'Frozen exact guards bypassed in '+name)
  delegates[name]=dict(line=node.lineno,end_line=node.end_lineno,delegates_to_frozen_method=True,
                      source_sha256=hashlib.sha256(ast.get_source_segment(s,node).encode()).hexdigest())
 bridge=ast.get_source_segment(s,methods['validate_parent_store'])
 require('self._active_store' in bridge and 'self.journal(' not in bridge,'Parent bridge consumes helper coverage')
 py_compile.compile(str(ROOT/SOURCE),cfile=str(ROOT/(BASE+'native_dispatcher_multiowner_vfp.pyc')),doraise=True)
 main_bytes=(ROOT/'evidence/firmware-analysis/main_02bd.bin').read_bytes()
 def raw(a,n):return main_bytes[a-0x50000:a-0x50000+n]
 require(raw(0x358d24,16).hex()=='002003490968002901d1024800687047','Original current getter CFG differs')
 require(struct.unpack('<2I',raw(0x358d34,8))==(0xf09094,0xf09090),'Getter literals differ')
 require(raw(0x20ec84,4).hex()=='262805fa','Original handler getter BLX differs')
 deps=dict(PINNED)
 for p in ['scripts/probe_native_settings_lazy_vfp_v2.py','scripts/probe_native_heap_settings_boot.py','scripts/probe_native_task_mutex.py','scripts/analyze_native_sections.py',str(Path(__file__).resolve().relative_to(ROOT))]:deps[p]=sha(p)
 previous_proof='evidence/firmware-analysis/native-multiowner-vfp-fragment-controls.json'
 pp=json.loads((ROOT/previous_proof).read_text());require(pp['all_passed'] and pp['case_count']==5 and pp['original_fragment_controls'],'Frozen micro scope differs')
 deps[previous_proof]=sha(previous_proof)
 snippet="""def journal_zone_write(self, uc, access, address, size, value, data):
    lazy = getattr(self, 'lazy', None)
    if self.zone_active and isinstance(lazy, NativeDispatcherMultiOwnerVFPState):
        row = lazy.validate_parent_store(uc, access, address, size, value, data)
        if row is not None:
            zone = next((z for low, z in self.zone_rows.items()
                         if low <= address and address+size <= low+z['bytes']), None)
            require(zone is not None and len(zone['stores']) < 20000,
                    'Native FP parent store crossed zone/budget')
            zone['stores'].append(dict(row, phase=self.phase))
            return
    return super().journal_zone_write(uc, access, address, size, value, data)
"""
 doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,source_sha256=deps,
  source=SOURCE,source_hash=SOURCE_HASH,source_exclusive_to_static_agent=True,
  pure_compile_passed=True,AST_no_guest_execute_or_memory_or_register_write_calls=True,
  helper_imported_or_instantiated_by_review=False,guest_executed=False,device_io=False,sounds_emitted=False,
  frozen_source_proof_or_canonical_modified=False,assertions_passed=True,
  subclass='NativeDispatcherMultiOwnerVFPState',frozen_parent='MultiOwnerVFPState',delegated_exact_guard_methods=delegates,
  constructor_signature='NativeDispatcherMultiOwnerVFPState(uc, stock, running_task, live, stack_top, tasks, prior_lazy, exclusive=False)',
  parent_journal_bridge_snippet=snippet,
  hook_order_contract=dict(bridge='Pure validation and returned row only; it does not alter push.seen, VSTM coverage, control.seen or helper zones.',
    own_hook='Inherited constructor registers the subclass journal hook once for each nonoverlapping helper zone; inherited journal records/consumes exact coverage once.',
    parent='Append returned row to matching parent zone plus phase; enforce complete zone containment/budget. Call inherited parent only on None. Never call helper.journal manually.',
    old_phase='Until the complete cold/component endpoint, retain prior LazyVFPState and frozen two-push path. Swap self.lazy after helper construction; parent observe then calls the new observer.',
    active_scope='Bridge all active original FP stores, including initial/nested pushes, metadata/pool owner stores, VSTM and control STM. It does not generally admit every8-byte store.'),
  construction_preconditions=dict(endpoint='Full frozen11-helper cold-controller endpoint has returned to actual controller; complete parent whole guards still pass before new helper.',
    owner='OWNER3AB1038=C9503F90, F09094=0, F09090==running_task==C, enabledFPEXC40000000, accessCPACR bitsF00000.',
    prior='Same UC and guardedUNDtop, prior_lazy.activeNone, nonempty complete first/same-controller rows with ownerC. Their canonical observer-row hash remains unchanged during new helper verify.',
    inputs='Exactly C plus actual Dispatcher TCBs. C has M9400900/pool9500000 from original cold descriptor. Actual D/M/pool must be read from original native builder inventory, not synthesized from the micro fixture.',
    pools='Both slots0, originalM40 live, pool320FF and base+320 strictly below supplied minimum_live_SP; inherited constructor preserves initialTCB108, exactM40 and nonoverlapping whole-zone histories.',
    live='live(pointer,length) must admit declared actual resident backing for TCB108, originalM40, pool320, and future native clone40 within original stack/pool.',
    no_live_input_patch='No source code path writes any live TCB, owner, metadata, allocator header, context or FP bank. Only inherited architectural UND entry writes CPU exception banked state.'),
  getter_contract=dict(entry='Original handler20EC84 BLX358D24; actualThumbUND getter entry LR20EC88; its actualARMUND return at20EC88 hasr0==running_task.',
    native_bytes_hex=raw(0x358d24,24).hex(),marker='F09094 nonzero returns0; exact zero marker required before admission/active stores/retry.',
    native_ready='F09090 value must equal task identified by actual native restore destination. Callback must not fall back to ready head.',
    checks='Original getter bytes/literals unchanged; observer records entry and actual returnedr0. No host invocation of current getter.'),
  runtime_code_mapping=dict(admitted_runtime_start_addresses=['0x50000','0x4400000','0x5400000'],
    mapping='Fault admission resolves unique complete4-byte runtime code copy to exact load origin and compares guest bytes before inheritedenter. Adapter changes only file addressing; inheriteddecode still resolves each writer and exactopcode.',
    excluded='InitializedF00000 data, vector-copy region, zero-filled storage and compiled companion instructions are not native FP fault/store admission targets.',
    copied_code='Copied440/540 payloads are conditional original code. Actual loaded guest bytes must match; static mapping is not evidence that hardwarestartup selected a copy.',
    double_mapping='Copiedcode load addresses are outside admitted runtime code ranges; frozen decoder load-address reads remain load-domain reads.'),
  added_store_constraints=dict(active='All frozen exactpush/VSTM/control/readback/nativeallocation/clone/TCB108/wholezone guards remain delegated. Extra validation also checks poolheader/cursor, clone chunks/writablebyte and publications against pending typed history.',
    outside_active_rejected=['ownerword4','C/D TCB+28 word4','originalM40','pool320 including nativeclone/current slot/trailing64','wholeguardedUND4096'],
    outside_active_preserved='Original unchanged store instructions in remaining helper zones (TCB fields and ownerpage other fields) remain chronological CPU history with actual_running_task, ready_head and IRQmarker. Independent full task/actor guard must still validate their semantics.',
    VSTM='New helper retains1/2/4/8 byte exactpayload tile support; sealed micro actually observed8-byte callbacks. Parent bridge masks width and accepts only pending original128-byte VSTM ranges.',
    nested_push='Every native UND push remains exactPC/mode/SP/register/address/coverage. Required originals20EBE0,20EC78,F6EDC(req148),6E0830,F6E14,F6EDC(req40) follow existing contract; bridge supports both ARM and Thumb.'),
  minimum_parent_guard_changes=[
   'Retain old first/same-controller rows separately and journal existing ownerC as the new baseline. Do not reset owner or slots to reproduce the micro firstowner case.',
   'Full parent controller pool must allow only replayed originalheader/context stores; move controllerFF64 boundary tobase+256. Parent originalGUI leading64 predicate must move only actualDispatcher boundary tobase+256 after nativefirstsave/clone; retain Thread nativeleading64 unchanged.',
   'Extend/declare required full parent typedmetadata/pool zones without overlap; newhelper owns independent fullTCB108/M40/pool320/ownerpage/UND journals. Replay parentoldbaseline to final, and helperpostcomponent baseline to final separately.',
   'Replace cold M+28==0/all256FF predicates with observed nativefirstsave/clone history after stores; retainM/namecanaries, oldreadonlyM40, exactclone40, allocatorbudget256/trailing64 and actualstackframe bounds.',
   'Do not reuse first-ownerOWNER==controller final predicate after actualDfault. Compare owner with observed nativehistory and actualrunning/current at eachfault; metadata pointerchange remains only observed originalF6E40 publication.',
   'Keep ALL/ready/ownedmutex/lifetime/current restored-frame checks and Threadtimednode20/kernelclock unchanged. Replay context-frame stores from originalkernel separately; this FPhelper does not validate ordinarytask-store semantics.',
   'Parent final multiowner claim requires actualCtoD firstsave/noDrestore, subsequentDtoC saveD/clone40/restoreC and laterCtoD restoreD. Helper.verify validates each completedtrap, not existence of a complete native scheduler roundtrip.'
  ],
  three_stage_expected=dict(first_D=dict(old_owner='C',new_owner='D',save_C=True,restore_D=False,D_slot_before=0,retry_bank='actualfaultbank'),
    return_C=dict(old_owner='D',new_owner='C',save_D=True,clone_D_metadata40=True,restore_C=True,retry_bank='savedCbank'),
    later_D=dict(old_owner='C',new_owner='D',save_C_existing=True,restore_D=True,retry_bank='savedDbank'),
    same_owner='NoVLDM evenvalidslot; actualfaultbank preserved. No manualbank/task/wake manipulation to force these stages.'),
  new_runtime_or_actual_Dispatcher_body_success_claimed=False,
  physical_App_direct_phone_music_package_acceptance_verified=False)
 with (ROOT/OUT).open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps(dict(artifact=OUT,sha256=sha(OUT),source_sha256=SOURCE_HASH,assertions_passed=True,pure_compile_passed=True,guest_executed=False)))

if __name__=='__main__':main()
