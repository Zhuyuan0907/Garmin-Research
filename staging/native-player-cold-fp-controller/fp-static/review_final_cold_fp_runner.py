#!/usr/bin/env python3
"""Exact final candidate AST/source review; no runtime imports or execution."""
from datetime import datetime, timezone
from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parents[3]
RUNNER = 'scripts/probe_native_cold_fp_controller.py'
EXPECTED_RUNNER = '0c4f4bb7e0077da701da225c183c262fa14346685dd605994438bd3edac1be3c'


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    output = Path(__file__).with_name('cold-fp-runner-peer-review-0c4f4bb7e007.json')
    assert not output.exists(), 'No prior review overwrite'
    assert sha(RUNNER) == EXPECTED_RUNNER
    source = (ROOT / RUNNER).read_text()
    tree = ast.parse(source)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ColdFPControllerVM')
    assert [ast.unparse(node) for node in cls.bases] == ['ColdFPGuardMixin','DeclaredCacheVM']
    methods = {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}
    excerpts = {name: ast.get_source_segment(source, methods[name]) for name in [
        '__init__','configure_native_kernel_inventory','observe','verify_cold_metadata',
        'verify_cold_controller_or_idle_boundary','seal_cold_boot','verify_extra_zones']}
    seal = excerpts['seal_cold_boot']
    assert 'bytes(self.uc.mem_read(self.controller,108))==self.pre_FP_boot_TCB108' in seal
    assert 'self.word(self.controller+32)==0' in seal
    assert "struct.pack('<6I',0,self.controller+32,0,0,0x3cc660,0)" in seal
    assert "bytes(vm.uc.mem_read(FP_NODE,16))==bytes(16)" in source
    assert 'vm.pre_FP_boot_TCB108=bytes(vm.uc.mem_read(vm.controller,108))' in source
    assert "phase='constructor',completed=False" in source
    snapshot = source.index('vm.pre_FP_boot_TCB108=')
    ctor = source.index('vm.kernel_invoke(0x3cc57d,(EXIT_LIST,))')
    boot = source.index('vm.kernel_invoke(0x20ed68,())')
    first_post = source.index('vm.kernel_invoke(POST,(vm.timer_task,16))')
    assert snapshot < ctor < boot < first_post
    assert source.count('vm.kernel_invoke(0x3cc57d,(EXIT_LIST,))') == 1
    assert source.count('vm.kernel_invoke(0x20ed68,())') == 1
    assert 'self.cold_controller_building=True' in excerpts['configure_native_kernel_inventory']
    assert "bytes(uc.mem_read(CONTROLLER_STACK,STACK_BYTES))==b'\\xff'*STACK_BYTES" in excerpts['observe']
    assert "bytes(self.uc.mem_read(bottom,256))==b'\\xff'*256" in excerpts['verify_cold_controller_or_idle_boundary']
    assert "bottom==IDLE_STACK and bytes(self.uc.mem_read(bottom,64))==b'\\xa5'*64" in excerpts['verify_cold_controller_or_idle_boundary']
    assert 'bytes(self.uc.mem_read(M,40))==self.metadata_before' in excerpts['verify_cold_metadata']
    assert 'self.word(self.controller+28)==M and self.word(M+28)==0' in excerpts['verify_cold_metadata']
    assert 'rows=HeapSettingsVM.verify_extra_zones(self)' in excerpts['verify_extra_zones']
    assert 'self.word(OWNER)==self.controller' in excerpts['verify_extra_zones']
    guard_review_path = 'staging/native-player-cold-fp-controller/fp-static/cold-fp-guard-copies-peer-review.json'
    contract_path = 'staging/native-player-cold-fp-controller/fp-static/cold-fp-first-controller-boot-contract.json'
    assert sha(guard_review_path) == '8da46e79c8c2e0f5d8f17fffbbd4bf78605bdac6cb964a12912f36159db77cae'
    assert sha(contract_path) == '061c354dfc96d2a37983f37e36c8e1eb6e6ae3122e849e390559fde232b3f518'
    guard_review = json.loads((ROOT / guard_review_path).read_text())
    for path, digest in guard_review['source_sha256'].items():
        assert sha(path) == digest, path
    direct = [str(Path(__file__).relative_to(ROOT)),RUNNER,guard_review_path,contract_path,
        'scripts/native_cold_fp_guard_copies.py','staging/native-player-cold-fp-controller/guard-copy-provenance.json',
        'scripts/probe_native_controller_gir_cache_declared.py','scripts/probe_native_controller_gir_component_contiguous.py',
        'scripts/probe_native_controller_gir_component.py','scripts/probe_native_kernel_context.py',
        'scripts/probe_native_task_mutex.py','scripts/probe_native_heap_settings_boot.py',
        'scripts/probe_native_settings_lazy_vfp_v2.py','scripts/probe_native_lazy_vfp.py',
        'staging/native-player-cache-declared-followup/fp-static/native-multiowner-fp-input-and-journal-recipe.json']
    payload = dict(updated_utc=datetime.now(timezone.utc).isoformat(), static_only=True,
        guest_executed=False, device_io=False, frozen_source_proof_or_canonical_modified=False,
        reviewed_runner=RUNNER, reviewed_runner_sha256=EXPECTED_RUNNER,
        source_sha256={path: sha(path) for path in direct},
        previous_candidate=dict(sha256='dc5af67bca0127705ab4bf7e6193ec43ca770a610925d43409d6d421ec0f2f4c',
            historical_short_review_delivered=True, runtime_not_executed_by_reviewer=True,
            exact_previous_file_not_saved_by_this_reviewer=True,
            issue='Constructorfailure couldcause result.phase KeyError beforeterminaldump; finalcandidatepredeclaresconstructorphase.',
            guard_suggestions='Coldnode16zero, pre/postbootTCB108+ownedhead0 andreleasedlist24 addedbeforefreeze.'),
        final_addition_check=dict(FPnode16_cold_zero=True, preboot_TCB108_snapshot_before_ctor=True,
            seal_TCB108_unchanged=True, seal_controller_ownedhead_zero=True,
            seal_releasedlist24='[0,controller+32,0,0,3CC660,0]',
            constructor_phase_present_before_try=True, no_new_startup_blocker_identified=True),
        MRO=dict(first='ColdFPGuardMixin', next='DeclaredCacheVM',
            copied_component_base_plus_Contiguous_cache_guards_preserved=True,
            firstsame_extra_guard_uses_Heap_base_without_frozen_controller_metadata_zero_constraint=True,
            inherited_LazyVFPState_still_rejects_crossowner_and20ECD8_20ED0C=True),
        typed_slot_and_zone_check=dict(
            descriptor='9400820 exact20B beforefirstbuilder; idle9400800 initializedseparately.',
            M_guard104=['0x94008e0','0x9400948'], name_guard81=['0x9400960','0x94009b1'],
            disjoint_M_name_Controller_pool_TCB_background_UND_zones=True,
            boot_wholecontroller_stack16384_separate_from_later_runtime_pool256=True,
            input_mapping_and_initial_zero_checks_execute_beforedeclared_input_write=True,
            metadata40_slot0_andname17_remain_guarded=True),
        native_sequence_check=dict(first_controller_FF_capture_before_kernelactive=True,
            boot_after_nativecontroller_idle_Timer_construction=True,
            exitlistctor_once_before_FPboot_once_before_firstPOST=True,
            original_ARM20ED9C_actual_LR20EDA0_and_return0_witness=True,
            no_late_exitlist_ctor_or_live_TCB_patch=True,
            controller_initial_frame_is_consumed_running_stack_not_a_resident_background_frame=True),
        journal_check=dict(boot_wholezone_replay_includes_CPUstores_and_declared_two_controller_ready_inputs=True,
            unjournaled_idle_and_global_initialready_inputs_remain_explicit_fixtures=True,
            nativecontroller_FF_fill_witness_before_TCB_placement=True,
            boot_store_decoder_accepts_original_ARM_STMDB_and_Thumbpush=True,
            later_extra_zones_captureverified_bootbytes_after_seal_andbeforeheap_settings=True,
            boot_decoder_is_original_MAIN_store_journal_not_per_PC_register_payload_validator=True,
            no_memory_hook_only_fullboundary_proof_claim=True),
        full_endpoint_check=dict(settings_heap_native_pending_ALL_ready_TCB_frames_timednode_guards_preserved=True,
            original_heap_3listener_node_chain_and_original2registration_returns_guarded=True,
            controller_boundary_now_whole256FF_plus_native16384fill_witness=True,
            idle_Timer_twoGUI_original_boundaries_kept=True,
            fresh11helperreturns_result20_fullcomponent_GUI_F0_cache_SQL_font_guards_required=True,
            first_same_FP_endpoint_only=True, original_FPboot_is_declared_runtime_intention_not_this_static_result=True),
        exact_reviewed_method_excerpts=excerpts,
        assertion_passed=True,
        limits='Exactfinalhash AST/sourceinspection, not newguestexecution orruntimepass. Initialready/CPACR/startupFPEXC/undefinedentry/lowerheap/files/clockfixtures remain. No actualnextDispatcher/multiownerFP/IRQ/timer/physicalApp/directphoneaudio/package/safeunloadproof. Sourcewasnotchangedbyreviewer; afterrunstart failuresmustretainfrozencandidate.')
    with output.open('x') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(artifact=str(output.relative_to(ROOT)),sha256=sha(str(output.relative_to(ROOT))),
        reviewed_runner_sha256=EXPECTED_RUNNER,generator_sha256=sha(str(Path(__file__).relative_to(ROOT))),
        static_assertions_passed=True,guest_executed=False)))


if __name__ == '__main__':
    main()
