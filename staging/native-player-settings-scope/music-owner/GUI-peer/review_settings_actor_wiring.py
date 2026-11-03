#!/usr/bin/env python3
"""Pure file/AST/MAIN instruction review; never instantiate a VM or run guest."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage

OUT = ROOT / 'staging/native-player-settings-scope/music-owner/GUI-peer/settings-actor-wiring-review.json'
RUNNER = 'scripts/probe_native_dispatcher_settings.py'
HELPER = 'staging/native-player-settings-scope/gui-static/settings_actor_observer.py'
CONTRACT = 'staging/native-player-settings-scope/gui-static/settings-actor-observer-contract.json'
SEALER = 'scripts/seal_native_settings_attempt.py'
REGISTRY = 'staging/native-player-settings-scope/previous-audit.json'
EXPECTED = {
    RUNNER: 'cbd72f3786b058d38894ae1339d47fd49f1367c4850c208a8dfd40aeebd32312',
    HELPER: '009cee2eee03684a2a95a70d92cada3e9dba94795bfc4a0270dc74262bd32513',
    CONTRACT: '48a1095ffac9db683b871134550d2b11e830f365566b185cd5ef4c6399585754',
    SEALER: 'f2e8014d99d74ebf8d504ba2f2eb9f69958261cea667b041c6ef6e59b5cdc088',
    REGISTRY: 'dd3f1c3ea6743f6801d9bbb3edff3e0556dbfc1332243c6ee149b86999664f39',
}

def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()

def main():
    assert not OUT.exists(), 'Preserve peer record'
    for path, expected in EXPECTED.items():
        assert sha(path) == expected, path
    contract = json.loads((ROOT / CONTRACT).read_text())
    protected = json.loads((ROOT / REGISTRY).read_text())['protected_sources']
    assert len(protected) == 1078
    deps = dict(protected)
    for path, expected in contract['dependency_sha256'].items():
        assert sha(path) == expected, path
        if path in deps:
            assert deps[path] == expected, path
        deps[path] = expected
    for path in [RUNNER, HELPER, CONTRACT, SEALER, REGISTRY,
                 'scripts/probe_native_player_mainmenu.py',
                 'scripts/native_dispatcher_multiowner_vfp.py',
                 'scripts/probe_native_kernel_context.py',
                 str(Path(__file__).resolve().relative_to(ROOT))]:
        digest = sha(path)
        if path in deps:
            assert deps[path] == digest, path
        deps[path] = digest
    for path, expected in deps.items():
        assert sha(path) == expected, path
    runner = (ROOT / RUNNER).read_text()
    helper = (ROOT / HELPER).read_text()
    raw = (ROOT / 'scripts/probe_native_task_mutex.py').read_text()
    parent = (ROOT / 'staging/native-player-decoder-scope/gui-static/decoder_actor_observer_v2.py').read_text()
    inventory = (ROOT / 'scripts/probe_native_player_mainmenu.py').read_text()
    sealer = (ROOT / SEALER).read_text()
    for source in [runner, helper, raw, parent, inventory, sealer]:
        ast.parse(source)
    checks = []
    def check(name, condition, evidence):
        assert condition, name
        checks.append(dict(name=name, passed=True, evidence=evidence))
    order = [runner.index(p) for p in ["result['cold_prefix_full_guards_passed']=True",
        "dump(STAGE/'cold-prefix-sealed.json',prefix)", 'vm.begin_body_observer(D)',
        'vm.capture_decoder_inputs()', 'vm.capture_dispatcher_settings_inputs()',
        'S=vm.kernel_invoke(0x3954cc,(80,))', 'vm.kernel_invoke(0x57458d,(S,))',
        'vm.kernel_invoke(0x4b571d,(S,0x405341))', 'vm.kernel_invoke(0x5d28ff,(D,S))',
        'vm.resume_same_native_work(WAIT,callback_only=True)',
        'vm.resume_same_native_work(vm.uc.reg_read(UC_ARM_REG_PC)|1)']]
    check('cold_prefix_capture_publication_and_same_PC_resume_order', order == sorted(order),
          dict(source=RUNNER, lines=[218,221,227,230,231,232,234,235,238,240,245,253]))
    check('declared_new_page_and_preserve_existing_mapping',
          '0x3aaf000]:' in runner and 'if not any(lo<=page and page+4095<=hi' in runner
          and 'existing_mapped_bytes_reset=False' in runner,
          dict(source=RUNNER, lines=[46,47,49,52]))
    check('seven_body_whole_zones_and_live_D_metadata',
          'self.dispatcher_task==0x8804fb8 and dm==0x8800fe0 and ds==0x8801024' in runner
          and '(0x3aaf000,4096)]:' in runner,
          dict(source=RUNNER, lines=[58,64]))
    check('actual_D_callback_SP_LR_and_original_return_frame',
          'self.running_task==self.dispatcher_task==self.word(0xf09090)' in runner
          and 'uc.reg_read(UC_ARM_REG_LR)==0x60935d' in runner
          and 'uc.reg_read(UC_ARM_REG_SP)==0x8804f78' in runner
          and 'uc.reg_read(UC_ARM_REG_SP)==self.dispatcher_callback_SP' in runner,
          dict(source=RUNNER, lines=[138,139,144,145]))
    check('capture_whole_backend_against_original_ctor_and_last_native_unlock',
          "words[2:]==[0,0,TAG,0]" in helper and "uses[-1]['operation']=='unlock'" in helper
          and "raw==struct.pack('<6I'" in helper and 'released_plus0_plus4_links_preserved=True' in helper,
          dict(source=HELPER, lines=[81,84,97,101,121]))
    forbidden = {'reg_write','mem_write','mem_map','mem_unmap','context_restore',
                 'emu_start','emu_stop','kernel_invoke','invoke','ret','put','configure_native_kernel_inventory'}
    forbidden_calls = [dict(line=n.lineno, method=n.func.attr) for n in ast.walk(ast.parse(helper))
                       if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and n.func.attr in forbidden]
    check('new_helper_has_no_guest_mutator_or_VM_execution_calls', not forbidden_calls,
          dict(source=HELPER, inspected_methods=sorted(forbidden), AST_calls=forbidden_calls))
    check('raw_entry_only_interception_and_native_epilogue_delegation',
          "if (address,caller) in PAIR:" in helper and 'self._ss_begin_raw(uc,address,caller);return True' in helper
          and 'return super().observe_dispatcher_actor(uc,address,size,data)' in helper
          and "if address in [0x300a0a,0x30092a]:" in raw and 'row = pending.pop()' in raw
          and "row.update(native_body_returned=True,original_return_branch_reached=True" in raw,
          dict(helper_lines=[292,293,295], original_epilogue_source='scripts/probe_native_task_mutex.py',
               epilogue_lines=[198,200,202,219], native_epilogues=['0x300a0a','0x30092a']))
    check('raw_actual_caller_SP_result_and_owner_closure',
          "row['native_body_returned'] and row.get('original_return_branch_reached')" in helper
          and "sp==int(row['entry_SP'],16)" in helper
          and "uc.reg_read(UC_ARM_REG_R0)==row['original_return']" in helper
          and "self.word(GET+8)==self.dispatcher_task" in helper,
          dict(source=HELPER, lines=[195,198,201,203]))
    check('ARM_memzero_exact_frame_sequential_page_stores_and_return',
          'self._da_actor(uc,thumb=False);sfs=self._ss_frame(0x26DCE8)' in helper
          and 'sp==zero[\'entry_SP\']-4' in helper and 'address==PAGE+4*zero[\'page_zero_events\']' in helper
          and "zero['page_zero_events']==518" in helper and 'uc.reg_read(UC_ARM_REG_R0)==BASE+0xB10' in helper,
          dict(source=HELPER, lines=[154,158,159,254,265,266]))
    check('default_admission_requires_actual_absent_wrapper_and_R6_zero_R0_FFFFFFFF',
          'uc.reg_read(UC_ARM_REG_R6)==0' in helper
          and "default['native_wrapper_return']==0xFFFFFFFF" in helper
          and 'uc.reg_read(UC_ARM_REG_R0)==0xFFFFFFFF' in helper,
          dict(source=HELPER, lines=[140,147,149]))
    check('containing_native_push_frames_and_callsite_mode_verified',
          "sp==frame['SP']-72" in helper and "sp==wrapper['SP']-24" in helper
          and "self._da_original_call(uc,address,lr)" in helper and "self._da_actor(uc,thumb=False)" in helper,
          dict(source=HELPER, lines=[139,246,253,260]))
    check('inherited_no_record_fixture_is_explicit_and_unchanged',
          'if address==0x2cab14 and self.settings_catalog_fixture is not None:' in inventory
          and 'self.visits[address]+=1;self.ret(0);return' in inventory
          and contract['qualification']['native_lower_storage_hardware_proven'] is False,
          dict(original_fixture='scripts/probe_native_player_mainmenu.py:74',
               branch='non19B IDs including100D return host no-record0; original wrappers/defaults execute'))
    check('whole_new_zones_have_before_value_and_final_replay_guards',
          "expected[p:p+n].hex()==s['before_hex']" in helper
          and "require(actual==expected,'Whole settings24/page4096 differs from CPU store history')" in helper
          and "require(actual==expected,'Whole native body zone differs from original CPU history')" in runner,
          dict(helper_lines=[311,315,318], runner_lines=[171,174]))
    check('initialized_bank_beforebytes_saved_and_prefix_detached_before_body',
          "result['initialized_data_journal']['before_hex']=vm.mutable_bank_before.hex()" in runner
          and 'result=json.loads(json.dumps(result))' in runner
          and 'mutable_bank_initial_before_hex=vm.mutable_bank_before.hex()' in runner,
          dict(source=RUNNER, lines=[218,222,265]))
    check('completed_scope_retains_false_foreground_fullbody_and_physical_claims',
          "result['body_full_guards_passed']=False" in runner
          and contract['qualification']['fullbody_proven'] is False
          and contract['qualification']['foreground_proven'] is False,
          dict(source=RUNNER, line=259, qualification=contract['qualification']))
    check('sealer_binds_actual_terminal_receipt_and_all_inputs_exclusively',
          "assert 'session_id' not in actual and actual['exit_code'] in (0, 1)" in sealer
          and 'assert sha(runner) == sha(snapshot)' in sealer
          and "assert actual['exit_code'] == (0 if probe['completed'] else 1)" in sealer
          and "with out.open('x')" in sealer,
          dict(source=SEALER, lines=[20,25,27,29,58]))
    image = NativeImage()
    modes = {True: Cs(CS_ARCH_ARM, CS_MODE_THUMB), False: Cs(CS_ARCH_ARM, CS_MODE_ARM)}
    pcs = [(0x26DCE8,True),(0x26DCF0,True),(0x26DCF4,True),(0x26DD22,True),
           (0x26DD38,True),(0x26DD3A,True),(0x26DD3C,True),(0x2CABBC,True),
           (0x2CABF6,True),(0x2CABFE,True),(0x2CAC04,True),(0x2CAD0A,True),
           (0x2CAD32,True),(0x40434C,True),(0x405340,True),(0x4053B4,True),
           (0x35B4F4,False),(0x35B4F8,False),(0x35B50C,False),(0x35B510,False),
           (0x35B520,False),(0x35B524,False),(0x35B528,False),(0x35B530,False)]
    opcodes=[]
    for pc,thumb in pcs:
        ins = next(modes[thumb].disasm(image.read(pc,4),pc,count=1))
        opcodes.append(dict(PC=hex(pc),Thumb=thumb,opcode_hex=bytes(ins.bytes).hex(),
                            instruction=ins.mnemonic+' '+ins.op_str))
    decoded = {int(r['PC'],16): r for r in opcodes}
    check('default_original_MAIN_R6_source_not_R0_and_BGT_signed_absence',
          decoded[0x26DCF0]['opcode_hex']=='0026' and decoded[0x26DD38]['opcode_hex']=='0028'
          and decoded[0x26DD3A]['opcode_hex']=='00dc' and decoded[0x26DD3C]['opcode_hex']=='3e63',
          [decoded[p] for p in [0x26DCF0,0x26DD38,0x26DD3A,0x26DD3C]])
    backing = [r for r in image.zeros if r['runtime_start']<=0x3AAF000
               and 0x3AAF000+4096<=r['runtime_end']]
    check('whole_new_page_has_exact_original_startupzero_backing', len(backing)==1, backing)
    # All read-only dependencies must still match after the bounded analysis.
    for path, expected in deps.items():
        assert sha(path)==expected, path
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        status='pure_static_exact_source_peer_no_concrete_blocker_identified',
        source_sha256=deps, protected_registry=REGISTRY, protected_files_verified=1078,
        dependency_files_verified=len(deps), assertions=checks, assertions_passed=len(checks),
        concrete_blockers=[], exact_target=dict(model='Taiwan nuvi2565RT',HWID=1352,software='8.00',
            MAIN='evidence/firmware-analysis/main_02bd.bin',MAIN_sha256=sha('evidence/firmware-analysis/main_02bd.bin')),
        original_instruction_evidence=opcodes,
        source_contract=dict(runner_sha256=sha(RUNNER),helper_sha256=sha(HELPER),
            contract_sha256=sha(CONTRACT),sealer_sha256=sha(SEALER)),
        execution=dict(read_only_source_review=True,new_compile=False,VM_instantiated=False,
            guest_execution=False,emulator_run=False,root_session_polled=False,device_io=False,
            audio_or_service_operations=False,existing_source_metadata_proof_or_canonical_modified=False,
            new_files_only=True),
        observations=dict(raw_lock_entry='0x3009a0',raw_lock_continuation='0x2cabfa',
            raw_unlock_entry='0x3008b0',raw_unlock_continuation='0x2cac08',
            raw_SP='actual2CABBCentrySP-24',raw_tag='0x2cbf6c',raw_pointer='0x148e6cc',
            SFS_frame='20-byte PUSH +52-byte locals =72 bytes',
            ARM_memzero='entry SP-4;708 words total,190 in prior3AAEpage,518 in new3AAFpage',
            default='R0FFFFFFFF follows absent wrapper;R6=0 stores to3AAF838;26DD3A is BGT'),
        limits=dict(no_native_runtime_result_supplied=True,not_a_host_control_suite=True,
            inherited_2CAB14_host_absent_inventory=True,native_storage_hardware_proven=False,
            page_mapping_is_declared_fixture_not_physical_RAM_proof=True,
            root_runtime_may_reach_new_unknown_boundary=True,full_foreground_font_cache_lifecycle=False,
            native_music_owner_session_source9_channel8=False,physical_App_or_modified_package_acceptance=False,
            direct_phone_A2DP_and_speaker=False))
    with OUT.open('x') as handle:
        json.dump(result,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps(dict(path=str(OUT.relative_to(ROOT)),sha256=sha(str(OUT.relative_to(ROOT))),
                         assertions_passed=len(checks),dependencies=len(deps),protected=len(protected))))

if __name__=='__main__':
    main()
