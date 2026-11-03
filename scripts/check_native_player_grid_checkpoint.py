#!/usr/bin/env python3
"""Audit automatic Grid/player evidence and explicit initialization limits."""
from datetime import datetime,timezone
from pathlib import Path
import json
import re
from analyze_native_sections import ROOT,EXPECTED
from check_native_music_stream_checkpoint import read,sha,artifacts


def main():
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    public=read('reports/findings.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    findings=state['native_app_music']['static_findings'];item=findings['native_player_grid']
    proof=read(item['evidence']);build=read(proof['build_manifest']);artifacts(build)
    for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    previous=read('staging/native-player-grid/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    for name,value in before['native_app_music']['static_findings'].items():assert findings[name]==value,name
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection',
        'native_voice_outer','native_voice_compatibility','native_music_endpoint','native_music_configuration_gate',
        'native_music_policy','native_music_dispatch','native_l2cap_send','native_music_reply','native_music_loaded',
        'native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for path,expected in old['source_sha256'].items():assert sha(path)==expected,path
        if name in ['native_music_loaded','native_music_stream','native_music_runtime','native_music_ready',
                    'native_music_continuous','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page']:
            assert sha(old['build_manifest'])==old['build_manifest_sha256'];artifacts(read(old['build_manifest']))
        if name=='native_player_menu':
            b=read(old['build_manifest']);assert sha(old['build_manifest'])==old['build_sha256']
            assert sha(b['elf'])==b['elf_sha256'] and sha(b['flat_binary'])==b['flat_binary_sha256']
        counts.append(old['case_count'])
    settings,constructor,event,controls=proof['cases'];load,snapshot=proof['load'],proof['snapshot']
    negative,zero,one=settings['stages'];chosen=constructor['chosen'];widget=chosen['widget']
    source=(ROOT/'scripts/emulate_native_player_grid_integration.py').read_text()
    vm_source=(ROOT/'scripts/emulate_native_player_grid.py').read_text()
    fault=read(proof['geometry_failed_probe']);fault_meta=read('staging/native-player-grid/geometry-boundary-failure-metadata.json')
    context=read('staging/native-player-grid/geometry-context-preflight.json')
    assertion_failure=read('staging/native-player-grid/coordinate-assertion-failure.json')
    runtime=read('staging/native-music-stream/emulator-runtime.json')
    writes=[{'address':hex(a),'word_before':0,'word_after':1,'writer_PC':'0x385450',
        'original_instruction_executed':True,'guest_memory_rewritten_by_test':False}for a in [0x0551c80c,0x0551c7f4,0x0551c7f8]]
    request_rows=[event['actions'][2],controls['restored_visible_enabled']]
    request_match=all(len(r['new_audio_API_requests'])==2 and
        r['new_audio_API_requests'][0]['registers']==[9,22,11] and r['new_audio_API_requests'][0]['stack']==[38,0,0] and
        r['new_audio_API_requests'][1]['arguments']==[9,0]for r in request_rows)
    checks={
        'four_complete_groups_exact_MAIN_unchanged_build_and_all_dependency_hashes':
            proof['all_passed'] and proof['case_count']==len(proof['cases'])==4 and all(c['passed']for c in proof['cases']) and
            proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and sha(item['evidence'])==item['evidence_sha256'] and
            sha(proof['build_manifest'])==proof['build_manifest_sha256'] and
            item['source_artifact_count']==len(proof['source_sha256']) and item['source_artifact_count']>=100,
        'same_original_outer_loader_resident_registration_and40_exports_retained':
            load['native_readback_bytes']==build['combined_file_bytes'] and load['native_readback_sha256']==build['combined_sha256'] and
            load['original_loader_result']==load['original_control_result']==11 and all(load['native_file_callback_entries'].values()) and
            load['entry_events'][0]['from_original_loader'] and load['install_callers'][0]['inside_loaded_component'] and
            load['original40_and_original_runtime_preserved'] and load['native_private12_and_player2_tables_match'] and
            proof['original_voice_RAM_and40_exports_retained_after_Grid_events'],
        'native_setting_read_failure_resets15_positive0_and1_preserve_icons_with_declared_record_fixture':
            negative['supplied_value'] is None and not negative['DB_preserved'] and negative['all15_cleared'] and
            negative['read_trace'][-1]['original_menu_read_return']==-1 and
            len([r for r in negative['native_reset_and_setters']if 'arguments'in r])==15 and
            len([r for r in negative['native_reset_and_setters']if 'reset15_entry'in r])==1 and
            [r['menu_status']for r in [zero,one]]==[0,1] and
            all(r['DB_preserved'] and not r['native_reset_and_setters'] and
                r['read_trace'][-1]['original_menu_read_return']==4 and
                r['lower_record_inventory_requests'][0]['lower_persistent_record_inventory_fixture']for r in [zero,one]) and
            settings['lower_record_search_fixture']=='0x2cab14' and settings['settings_ready_byte_fixture']=='0xf06ef7' and
            not settings['actual_settings_store_boot_initialization_executed'] and
            all(not r['actual_device_setting_value_recovered']for r in settings['stages']) and
            proof['settings_fixture_closed_before_GUI'] and proof['settings_native_ready_byte_restored'],
        'Page_resets_three_times_after_negative_setting_read_explicit_native_reselection':
            constructor['containing_Page']['children']==4 and constructor['containing_Page']['vtable']=='0xc0e5f0' and
            len([r for r in constructor['containing_Page']['native_reset_and_setters']if 'reset15_entry'in r])==3 and
            len([r for r in constructor['containing_Page']['native_reset_and_setters']if 'arguments'in r])==45 and
            all(r['original_menu_read_return']==-1 for r in constructor['containing_Page']['original_settings_read_trace']
                if 'original_menu_read_return'in r) and constructor['explicit_reselection_after_Page_using_original_SQL_setter'],
        'complete_original_Grid_15_records72_stride_19_children_auto_factory_and_parent_not_host':
            constructor['allocation_bytes_from_original_edit_Page_caller']==0x420 and constructor['mode']==0 and
            constructor['vtable']=='0xc0dd9c' and constructor['row_limit']==constructor['row_count']==15 and
            constructor['record_stride_bytes']==72 and constructor['child_count']==19 and constructor['selected_cell']==12 and
            chosen['row']==11 and chosen['ID']=='0x7f135201' and chosen['caption']=='Pi 播放器' and
            chosen['context']=='0x13528000' and chosen['vtable']=='0xc00b38' and chosen['parent']==constructor['grid'] and
            int(chosen['click_signal'],16)!=0 and chosen['initial_state_C8_C9_CA']==[1,4,4] and
            chosen['initial_rectangle']==[0,0,0,0] and constructor['DB_preserved_after_Grid'] and
            constructor['original_automatic_builder_calls'][0]['caller']=='0x546eb2' and
            constructor['original_factory_entries'][0]['original_factory_executed'] and
            constructor['original_factory_entries'][0]['fifth_argument']==0 and
            not constructor['host_called_factory_or_attached_Widget_directly'] and proof['automatic_grid_population_executed'],
        'original_Page_Grid_Widget_dispatch_translates_restores_coordinates_to_resident_player':
            event['Page_children_after_Grid_attach']==5 and event['Grid_parent']==constructor['containing_Page']['object'] and
            event['Widget_parent_remains_automatic_Grid']==constructor['grid'] and event['stock_Grid_event_entry']=='0x5496ba' and
            [r['numeric_action']for r in event['actions']]==[0,1,2] and
            [r['Widget_state_C8_C9_CA']for r in event['actions']]==[[1,2,2],[1,0,0],[1,0,0]] and
            [len(r['new_audio_API_requests'])for r in event['actions']]==[0,0,2] and request_match and
            all(len(r)==1 and r[0]['widget']==widget and r[0]['point']==[20,20]for r in event['player_Widget_inputs']) and
            snapshot['native_menu_state']==[1,1,2,0x13528000,2,2] and
            proof['original_Grid_event_entry_visits']['0x31649a']==2 and
            not event['host_invoked_signal_or_compiled_callback_directly'] and 'vm.invoke(0x27a98' not in source,
        'hidden_disabled_outside_Grid_inside_Page_controls_suppress_then_restore_player':
            all(not controls[k]['new_audio_API_requests']for k in ['hidden_Page','disabled_Widget','outside_Grid_inside_Page']) and
            controls['outside_Grid_inside_Page']['global_point']==[400,240] and
            len(controls['restored_visible_enabled']['new_audio_API_requests'])==2 and
            event['original_visibility_propagated'] and event['Widget_flag112_remains0'],
        'explicit_geometry_input_enable_sound_and_kernel_wake_no_real_touch_layout_root_claim':
            event['test_supplied_geometry']=={'Page':[0,0,480,272],'Grid':[40,40,360,200],'Widget_relative_to_Grid':[120,80,100,40]} and
            event['test_enable0_and_sound_selector36_via_original_APIs'] and not event['actual_physical_touch_classification_executed'] and
            not event['native_layout_or_rendering_executed'] and not proof['actual_page_controller_switch_executed'] and
            not proof['native_geometry_or_font_rendering_completed'] and not proof['rendered_touchable_icon_verified'] and
            proof['original_kernel_wake_boundary_fixture']['result']==0 and
            bool(proof['original_kernel_wake_boundary_fixture']['requests']) and
            not proof['original_kernel_wake_boundary_fixture']['kernel_thread_or_notification_delivery_executed'],
        'failed_original_geometry_null_context_and_assertion_preserved_not_called_full_success':
            not fault['completed'] and fault['phase']=='before_Grid_geometry_API' and
            fault['invalid_accesses'][-1]['PC']=='0x4dddbc' and fault['invalid_accesses'][-1]['address']=='0x218' and
            fault_meta['exit_code']==1 and not fault_meta['full_integration_completed'] and
            sha('staging/native-player-grid/source-at-geometry-boundary.py')==fault_meta['source_sha256'] and
            sha(proof['geometry_failed_probe'])==fault_meta['failure_sha256'] and
            context['global_base']=='0xf071e8' and context['global_context_offset']==8 and context['original_context_pointer']=='0x0' and
            not context['GUI_context_initializer_executed'] and not context['null_region_mapped_or_success_faked'] and
            assertion_failure['terminal_exit']==1 and assertion_failure['groups_reported_before_failure']==2 and
            not assertion_failure['full_suite_complete'] and sha(assertion_failure['source'])==assertion_failure['source_sha256'],
        'three_exact_native_RAM_once_words_full_region_code_canary_checks':
            snapshot['original_GUI_initialized_data_mutations']==writes and
            snapshot['full_conditional_data_region_matches_three_native_word_allowances'] and
            proof['only_three_exact_original_GUI_guard_words_change_conditional_initialized_data'] and
            snapshot['stock_and_loaded_code_unchanged'] and snapshot['all_allocation_guards_intact'] and
            not build['patch_plan'] and build['VM_MAIN_patch_bytes']==0 and
            'SelectionPlayerVM.finish(self)'in vm_source,
        'host_SQL15_rows_restored_finalize_backup_unchanged_separate_heap_no_RAM_claim':
            proof['all15_DB_rows_restored_in_memory'] and proof['original_SQL_statement_finalization'] and proof['database_backup_unchanged'] and
            proof['database_sha256']=='1ae4071e1d93496cac562edf74093f5054f3f72497f4a5c40405a52df2ba2e99' and
            proof['separate_CXX_heap_fixture']['base']=='0x08800000' and proof['separate_CXX_heap_fixture']['bytes']==0x400000 and
            proof['separate_CXX_heap_fixture']['all_guards_intact'] and
            proof['separate_CXX_heap_fixture']['does_not_overlap_inherited_SQL_or_large_canvas_heap'] and
            not proof['separate_CXX_heap_fixture']['actual_free_RAM_claim'],
        'resident_pinned_module_original_reservation_RX_RW_package_emulation_only':
            build['extension_bytes']==54906 and build['combined_file_bytes']==2353926 and build['combined_ram_bytes']==2462860 and
            build['remaining_reservation_bytes']==682868 and load['original_3MiB_reservation_retained'] and not build['unresolved_symbols'] and
            build['code_RX_data_RW_segments'] and build['package_checks']['all_other_members_byte_identical'] and
            build['package_checks']['changed_members']==['DLLIMG.BIN','DLLINFO.TXT'] and 'EMULATION-ONLY'in build['package'] and
            proof['objects_holders_callbacks_resources_and_module_remain_pinned'] and not proof['device_install_candidate'] and
            not proof['actual_package_acceptance_verified'],
        'validated_Unicorn214_library_and_guard_fault_controls':
            proof['emulator_binding_version']=='2.1.4' and proof['emulator_native_version']==[2,1,33621247] and
            sha(runtime['successful_runtime']['native_library'])==runtime['successful_library_sha256'] and
            sha(runtime['successful_runtime']['binding_file'])==runtime['successful_binding_sha256'] and
            len(proof['guard_fault_controls'])==2 and all(c['passed']for c in proof['guard_fault_controls']),
        'frozen21_selected_suites_all79_previous_findings_exact_prior16_scope_snapshot':
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3] and
            len(before['native_app_music']['static_findings'])==79 and prior['all_passed'] and
            len(prior['scope_checks'])==16 and prior['state_sha256']==sha(previous['state']),
        'canonical_task_public31_percent45_details_Taiwan_time_and_privacy':
            public['deep_research']==state and all(task[k]==state[k]for k in
                ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities']) and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==45 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in
                ['report-updated-time','research-updated-time']) and
            all(t in report for t in ['最新離線進展：原廠自動格位建立播放器按鈕','四組完整離線驗證通過',
                '設定儲存區尚未初始化','真正佈局與畫面仍未完成','原機 App 和手機直接藍牙音樂尚未完成',
                '前輪紀錄：原廠菜單頁接上播放器事件']) and
            'REDACTED_PRIVATE_ID'not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report),
        'user_sleeping_no_device_IO_sound_unchanged_physical_evidence_priorities_goal_active':
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not proof['device_io'] and not proof['device_files_modified'] and
            not proof['sounds_emitted'] and not proof['native_App_running_on_device'] and not proof['phone_direct_music_verified'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and state['native_android_auto']['requested'] and
            state['google_maps']['research_deferred_by_user'] and state['goal_status']=='active' and not state['goal_complete'] and
            state['required_work_remaining']}
    assert all(checks.values()),[name for name,value in checks.items()if not value]
    out='evidence/firmware-analysis/native-player-grid-checkpoint-audit.json'
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'scope_checks':checks,
        'state_sha256':sha('evidence/deep-research-state.json'),'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':sha(item['evidence']),'build_manifest_sha256':sha(proof['build_manifest']),
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),'current_turn_device_IO':False,
        'goal_status':'active','full_goal_complete':False}
    (ROOT/out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'audit':out,'scopes':len(checks),'all_passed':True}))


if __name__=='__main__':main()
