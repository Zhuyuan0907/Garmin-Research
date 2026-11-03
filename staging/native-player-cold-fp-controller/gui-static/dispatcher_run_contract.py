#!/usr/bin/env python3
"""Declarative native-run contract and strict record admission; no emulator."""

PHASES = [
    dict(id='cold_typed_controller', actor='controller', API=None,
        require=['descriptor20_declared_before_first_builder','metadata40_and_name17_exact',
            'native_FF_fill_and_TCB108_observed','TCB_plus28_native_metadata_pointer']),
    dict(id='cold_exit_list',actor='controller',API='0x3cc57d',args=['0x2d226b4'],
        require=['cold_list28_before','original_six_zero_stores','native_list_tag','actual_return_once']),
    dict(id='cold_FP_boot',actor='controller',API='0x20ed68',mode='ARM',args=[],
        require=['owner0_EN1_before','original_registration_return20EDA0_zero','FPnode_once',
            'FPSCR_03000000','boot_CPU_histories_pass','owner0_after']),
    dict(id='timer_start',actor='controller',API='0x2fcf44',mode='ARM',args=['timer',16],
        require=['actual_native_restore_history']),
    dict(id='dispatcher_bootstrap',actor='controller',API='0x5d2f7d',args=[],require=['actual_return']),
    dict(id='dispatcher_singleton',actor='controller',API='0x5d2131',args=[],
        require=['actual_return_D_8800520','five_native_TCBs_and_frames','prior_full_memory_guards']),
    dict(id='background_drain',actor='controller',API='0x2fd035',args=[],
        require=['actual_idle_endpoint','controller_saved_PC2FD0AC']),
    dict(id='idle_resume_controller',actor='idle',API='0x2fcf44',mode='ARM',args=['controller',1],
        require=['actual_restore_current_controller_frame','controller_WAIT_returns','controller_SP9503F90']),
    dict(id='native_heap',actor='controller',API='0x388b6d',args=['EXTENT',1,0,0],
        require=['original_heap_returns','three_native_exit_listeners','cold_heap_guard']),
    dict(id='settings',actor='controller',API='0x2cbd17',args=[],
        require=['actual_return_zero','settings_full_memory_and_native_endpoint_guards']),
    dict(id='native_component',actor='controller',API='0xea1004c',mode='ARM',args=['CONFIG','OUTPUT'],
        require=['actual_return_status1','helper11_returned11','result_mask2FFC','SQL_statement_closure',
            'fonts13_streams8','whole_cache_and_all_inherited_guards','cold_FP_listener_metadata_guards']),
    dict(id='independent_signal_allocate',actor='controller',API='0x3954cc',args=[80],
        require=['live_aligned80_bytes','allocator_fixture_qualified']),
    dict(id='independent_signal_construct',actor='controller',API='0x57458d',args=['S'],
        require=['actual_return','exact_original80_image','original_cleanup_signal_and_Thread_unchanged']),
    dict(id='signal_register',actor='controller',API='0x4b571d',args=['S','0x405341'],
        require=['actual_return','one_C1B584_freefunction_holder_405341','live_vector_holder_backing']),
    dict(id='signal_queue',actor='controller',API='0x5d28ff',args=['D','S'],
        require=['actual_return','native_queue_record_S_zero','native_post_event2']),
    dict(id='controller_yield',actor='controller',API='0x2fd035',args=[],
        require=['native_controller_WAIT_save','actual_Dispatcher_restore','original_callback_chain',
            'actual_callback_entry405340_SP8804F78_LR60935D']),
    dict(id='callback_body',actor='Dispatcher',API=None,
        require=['resume_actual_PC_mode_registers_SP_LR','no_host_direct_callback_invoke',
            'native_manager_init_registry_and_raw_guards','native_cleanup_head_node_guards',
            'declared_fixed_clock_native_reads','actual_FP_fault_exchange_retry_histories',
            'conditional_lookup_creation_root0_branch_recorded','actual_return60935C_SP8804F78']),
    dict(id='dispatcher_release_and_block',actor='Dispatcher',API=None,
        require=['original609366_523566_5D2192_releases','native_next_WAIT','actual_idle_endpoint',
            'new_controller_WAIT_frame_PC2FD0AC']),
    dict(id='final_idle_resume_controller',actor='idle',API='0x2fcf44',mode='ARM',args=['controller',1],
        require=['actual_current_controller_frame_restored','controller_original_WAIT_returns',
            'final_actor_controller_and_SP','all_final_whole_memory_and_native_owned_timed_frame_guards']),
]

def validate_record(record):
    """Admit supplied observations only; this never supplies or executes one."""
    if record.get('static_only') or record.get('simulated_observations'):
        raise ValueError('Static or synthesized observations are not a runtime record')
    observations=record.get('phases',[])
    if len(observations)!=len(PHASES):raise ValueError('Incomplete native phase record')
    for expected,actual in zip(PHASES,observations):
        if actual.get('id')!=expected['id'] or actual.get('actor')!=expected['actor']:
            raise ValueError('Native phase order or actor differs: '+expected['id'])
        witnessed=actual.get('guards',{})
        if any(witnessed.get(name) is not True for name in expected['require']):
            raise ValueError('Required native evidence missing: '+expected['id'])
        if actual.get('host_callback_context_or_owner_patch'):
            raise ValueError('Guest callback context/owner patch is outside this contract')
    return dict(native_phase_record_admitted=True,physical_foreground_or_safe_cleanup_proven=False)

if __name__=='__main__':
    import json
    print(json.dumps(dict(static_only=True,phase_count=len(PHASES),phases=PHASES,
        guest_execution=False,runtime_observations_not_fabricated=True),indent=2))
