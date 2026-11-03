#!/usr/bin/env python3
"""Audit native mutex owner controls and still-incomplete dispatcher research."""
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
import hashlib,json,re
from analyze_native_sections import ROOT,EXPECTED
from check_native_music_stream_checkpoint import artifacts

def read(p): return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p): return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    findings=state['native_app_music']['static_findings']
    metadata_item,ctor_item=findings['native_mainmenu_metadata'],findings['native_mainmenu_constructor']
    metadata,ctor=read(metadata_item['evidence']),read(ctor_item['evidence'])
    build=read(ctor['build_manifest']);artifacts(build)
    for item,proof,count,deps in [(metadata_item,metadata,5,94),(ctor_item,ctor,3,101)]:
        assert sha(item['evidence'])==item['evidence_sha256']
        assert proof['all_passed'] and proof['case_count']==len(proof['cases'])==count
        assert len(proof['source_sha256'])==item['source_artifact_count']==deps
        assert proof['MAIN_sha256']==EXPECTED
        for p,s in proof['source_sha256'].items(): assert sha(p)==s,p
    previous=ctor_item['previous_checkpoint'];before,prior=read(previous['state']),read(previous['audit'])
    for k,v in before['native_app_music']['static_findings'].items(): assert findings[k]==v,k
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer','native_voice_compatibility',
        'native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch','native_l2cap_send',
        'native_music_reply','native_music_loaded','native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page',
        'native_player_grid','native_player_text','native_player_external_fonts','native_player_rendering','native_player_resources',
        'native_mainmenu_dependencies','native_custom_page_root','native_menu_signals','native_heap_callback','native_settings_writer']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for p,s in old['source_sha256'].items(): assert sha(p)==s,p
        counts.append(old['case_count'])
    static=read(metadata_item['static_evidence'])
    for p,s in static['source_sha256'].items(): assert sha(p)==s,p
    indexes=[read(item['preserved_development_evidence']) for item in [metadata_item,ctor_item]]
    for item,index in zip([metadata_item,ctor_item],indexes):
        assert sha(item['preserved_development_evidence'])==item['preserved_development_evidence_sha256']
        for p,s in index['source_artifact_sha256'].items(): assert sha(p)==s,p
        for run in index['runs']:
            assert sha(run['metadata'])==run['metadata_sha256']
            doc=read(run['metadata'])
            for key in ['source','VM_source','probe','proof']:
                if key in doc and key+'_sha256' in doc: assert sha(doc[key])==doc[key+'_sha256']
    m0,m1,m2,m3,m4=metadata['cases'];c0,c1,c2=ctor['cases']
    fullmeta=read('staging/native-player-mainmenu-full/complete-constructor-run-metadata.json')
    failed=read('staging/native-player-mainmenu-full/query-history-assertion-failure-metadata.json')
    failure=read(failed['probe'])
    devmeta=read('staging/native-player-mainmenu-metadata/general-menu-metadata-terminal-metadata.json')
    dev=read(devmeta['probe'])
    progress=public['research_progress'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    returned_path=ROOT/'evidence/user-return-20261004-latest.json'
    returned=read(str(returned_path.relative_to(ROOT))) if returned_path.exists() else None
    presence_matches_instruction=(state['user_resting']and task['user_away']and
        not state['attended_testing']['user_present']and state['attended_testing']['waiting_for_user_return'])or(
        returned is not None and returned['user_explicitly_returned']and not returned['physical_test_requested']and
        not state['user_resting']and not task['user_away']and state['attended_testing']['user_present']and
        not state['attended_testing']['waiting_for_user_return'])
    if returned:
        archive=read(returned['prior_night_checkpoint'])
        for row in archive.values():assert sha(row['snapshot'])==row['sha256']
        nightaudit=read(archive['evidence/firmware-analysis/native-mainmenu-constructor-checkpoint-audit.json']['snapshot'])
        assert nightaudit['all_passed']and len(nightaudit['scope_checks'])==14
        assert nightaudit['state_sha256']==archive['evidence/deep-research-state.json']['sha256']
        assert nightaudit['audit_script_sha256']==archive['scripts/check_native_mainmenu_constructor_checkpoint.py']['sha256']
    controller=state['native_app_music']['development_observations'].get('general_MainMenu_controller_advancing_clock_development')
    if controller:
        cs=read(controller['static_evidence']);ci=read(controller['preserved_development_evidence'])
        for p,s in cs['source_sha256'].items():assert sha(p)==s,p
        for p,s in ci['source_artifact_sha256'].items():assert sha(p)==s,p
        for k in ['static_evidence','preserved_development_evidence','development_evidence','terminal_metadata','clock_argument_evidence']:
            assert sha(controller[k])==controller[k+'_sha256']
        cp=read(controller['development_evidence']);cm=read(controller['terminal_metadata']);cd=read(controller['clock_argument_evidence'])
    writers=[('0x551c7f8','0x1','0x385450'),('0x551c80c','0x1','0x385450'),('0x551c800','0x1','0x385450'),
        ('0x551c804','0xc035f8','0x26de42'),('0x551c808','0x3aaed08','0x26de6c'),
        ('0x551c804','0xc0fd70','0x344e22'),('0x551c7fc','0x1','0x385450')]
    checks={
        'fresh_prior12_scope_snapshot89_findings_preserved':prior['all_passed'] and len(prior['scope_checks'])==12 and
            prior['state_sha256']==sha(previous['state'])==previous['state_sha256'] and sha(previous['audit'])==previous['audit_sha256'] and
            len(before['native_app_music']['static_findings'])==89 and len(findings)==93,
        '31_frozen_selected_suites_exact_sources_and_artifacts_retained':counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5,5,6,5,3,3,5,5],
        'eight_complete_new_controls94_and101_dependencies_same_emulation_only_player':all(c['passed']for p in [metadata,ctor]for c in p['cases']) and
            metadata['build_manifest']==ctor['build_manifest'] and build['extension_bytes']==54976 and build['VM_MAIN_patch_bytes']==0 and
            not build['patch_plan'] and build['code_RX_data_RW_segments'] and 'EMULATION-ONLY'in build['package'],
        'seven_complete_original_metadata_CFGs_native_lookup_missing11_no_fake_read_success':static['complete_bounded_CFG_count']==len(static['functions'])==7 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in static['functions'].values()) and
            sha(metadata_item['static_evidence'])==metadata_item['static_evidence_sha256'] and m0['consumer_buffer_unchanged'] and
            m0['original_generic_read_and_profile_lookup_executed'] and not m0['host_returned_missing_read_status'] and
            len(m0['native_read_requests'])==5 and all(r['native_generic_read_return']==11 and r['original_generic_read_body_executed']and
                not r['output_written']for r in m0['native_read_requests']),
        'original_presence_and_indirect_driver_copies_fictional_inventory_guarded':m1['native_result']==0 and not m1['host_bool_override'] and
            m2['original_presence_getter_result']==1 and m2['whole_guarded_consumer_buffer_matches_native_expected_fields'] and
            m2['supplied_inventory_is_fictional']and len(m2['native_read_requests'])==10 and
            all(r['original_profile_lookup_and_indirect_driver_dispatch']and r['native_generic_read_return']==0 for r in m2['native_read_requests']) and
            metadata['descriptor_and_consumer_object_and_driver_inventory_guards_verified'],
        'native_legacy_signed_length_high_word_and_reused_header_controls_not_device_bug':m3['legacy_header_value']==24 and m3['legacy_body_bytes']==16 and
            m3['unsigned_underflow_request']=='0xfffffffc' and m3['original_generic_driver_normalizes_to4'] and
            m3['lower_unavailable_body_returns1_no_output_native_flag0'] and m3['five_high_word_headers_skip_all_body_reads'] and
            m4['later_native_body_requests']==[140,141,142,143] and m4['native_bank140_read_failure_flag']==0 and
            m4['not_claimed_as_device_firmware_bug'] and metadata['synthetic_profile_table_restored_to_original_zero_BSS'] and
            not metadata['actual_factory_schema_data_driver_boot_or_consumer_default_object_constructor_verified'],
        'compiled_original_loader_player_in_original_general_MainMenu15_row_Grid':c0['original_entry']=='0x40434c' and c0['object']==c0['returned'] and
            c0['vtable']=='0xc03f98' and c0['embedded_Grid_row_count']==15 and c0['loaded_player_caption']=='Pi 播放器' and
            c0['loaded_player_row']['widget']!='0x0' and not c0['host_seeded_player_catalog']and
            not c0['original_controller_or_foreground_executed'] and ctor['load']['native_private12_and_player2_tables_match'],
        'native_default_calculation_setter121E_caller405314_and_reader_match':c1['original_default_entry']=='0x2c7de0' and
            c1['original_write']['key']=='0x121e' and c1['original_write']['native_caller']=='0x405314' and
            not c1['original_write']['host_supplied_default_value'] and not c1['host_supplied_default_or_cursor'] and
            c1['native_read_back_hex']==c1['original_write']['bytes_from_original_default_calculation'] and
            c1['later_121F_branch_and_recreation_unverified'] and len(ctor['original_main_default_writes'])==1,
        'seven_exact_native_GUI_writers_whole_region_not_host_rewritten':ctor['snapshot']['full_general_menu_conditional_region_matches_exact_native_writers'] and
            not ctor['snapshot']['host_rewrote_GUI_initialized_bytes'] and
            [(w['address'],w['value'],w['PC'])for w in ctor['snapshot']['original_native_writer_events']]==writers and
            all(w['size']==4 for w in ctor['snapshot']['original_native_writer_events']),
        'both_full_voice40_code_canary_DB_font_GIR_and_closed_SQL_guards_pass':all(p['original_voice_RAM_and40_exports_unchanged']and
            p['snapshot']['stock_and_loaded_code_unchanged']and p['snapshot']['all_allocation_guards_intact']for p in [metadata,ctor]) and
            metadata['raw_DB_backup_unchanged'] and metadata['no_GUI_conditional_initialized_data_changes'] and
            ctor['raw_font_backups_and_DB_unchanged'] and ctor['all_SQL_statements_closed_by_original_wrappers'] and
            ctor['retained_closed_SQL_history_count']>0 and ctor['full_scoped_general_MainMenu_constructor_final_guards_passed'],
        'hidden_zero_frame_controller_root_recreation_and_accepted_device_App_still_unverified':c2['native_frame']==[0,0,0,0] and
            c2['native_visibility_flags']==[0,0]and not c2['audio_requests'] and
            not ctor['general_MainMenu_controller_root_foreground_and_recreation_verified']and
            not ctor['accepted_modified_VPM_or_device_App_direct_audio_and_safe_lifetime_verified']and
            not ctor['snapshot']['speaker_or_DAC_executed'] and not ctor['snapshot']['UI_thread_timing_proven'],
        'failed_and_partial_runs_distinguished_from7075_and70973_complete_passes':
            [r['session_id']for r in indexes[0]['runs']]==[91360,21207,7075]and
            [r['terminal_exit_code']for r in indexes[0]['runs']]==[1,0,0]and
            [r['full_scoped_final_guards_passed']for r in indexes[0]['runs']]==[False,False,True]and
            [r['session_id']for r in indexes[1]['runs']]==[36971,70973]and
            [r['terminal_exit_code']for r in indexes[1]['runs']]==[1,0]and
            failed['actual_first_run_database_guard_subconditions_not_recorded']and
            len(failure['completed_cases'])==3 and not failure['all_final_guards_passed']and
            devmeta['terminal_exit_code']==0 and dev['completed']and
            fullmeta['terminal_exit_code']==0 and fullmeta['case_count']==3 and fullmeta['source_artifact_count']==101 and
            fullmeta['full_scoped_final_guards_passed'],
        'canonical_task_public32_weighted65_details7_phases_timestamps_and_privacy':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            progress['estimate_percent']==progress['weighted_estimate_percent']==32 and
            sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32 and
            progress['phases'][4]['estimate_percent']==10 and len(progress['completed'])==65 and len(progress['phases'])==7 and
            '<progress id="research-progress" max="100" value="32"'in report and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            '播放器已接入原廠首頁初始化'in report and '頁面目前仍是隱藏、零尺寸'in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report,
        'offline_evidence_current_presence_no_device_sound_install_music_mic_WAV_rerun_or_goal_completion':presence_matches_instruction and
            state['attended_testing']['no_pending_question']and
            all(not p['device_io']and not p['sounds_emitted']for p in [metadata,ctor])and
            not state['last_goal_turn']['device_files_written']and not state['last_goal_turn']['automatic_calls_or_sound']and
            not state['native_app_music']['native_app_running']and not state['native_app_music']['direct_phone_music_verified']and
            state['microphone_amplifier']['status']=='cancelled_by_user'and state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized']and
            state['last_goal_turn']['goal_status']=='active'and not state['last_goal_turn']['full_goal_complete']and
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests']}
    if controller:
        checks['four_controller_CFGs_failed_partial_clock_argument_preserved_no_root_or_success_claim']=(
            cs['complete_bounded_CFG_count']==len(cs['functions'])==4 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in cs['functions'].values())and
            cs['lookup_key_UTF16']=='PageMainMenu'and cs['matching_existing_Page_branch_skips_new_ctor_registration_and_2DA69E']and
            [r['session_id']for r in ci['runs']]==[19309,49765]and all(r['terminal_exit_code']==1 for r in ci['runs'])and
            read(ci['runs'][0]['metadata'])['original_controller_return_or_prior_exception_not_recorded']and
            cm['session_id']==49765 and not cp['completed']and not cp['full_scoped_final_guards_passed']and
            cp['registers']['pc']=='0x3ec6aa'and cp['registers']['r2']=='0x49c'and cp['registers']['lr']=='0x3b4c15'and
            any(e['entry']=='0x40434c'and e['caller']=='0x4053c2'for e in cp['original_main_entries'])and
            not any(e['entry']=='0x38e696'for e in cp['original_main_entries'])and
            cd['observed_virtual_clock_word']+cd['constant_native_125_shift3']==cd['observed_native_wait_argument']==1180 and
            not cd['real_kernel_time_units_owner_or_wait_semantics_verified']and not cp['device_io']and not cp['sounds_emitted'])
    latestprevious=read('staging/native-player-pool-clock/previous-checkpoint.json')
    latestbefore=read(latestprevious['state']['path']);latestprior=read(latestprevious['audit']['path'])
    for kind,row in latestprevious.items():assert sha(row['path'])==row['sha256'],kind
    for key,value in latestbefore['native_app_music']['static_findings'].items():assert findings[key]==value,key
    poolitem=findings['native_pool_clock'];pool=read(poolitem['evidence'])
    assert sha(poolitem['evidence'])==poolitem['evidence_sha256']
    for p,s in pool['source_sha256'].items():assert sha(p)==s,p
    clockindex=read(poolitem['preserved_development_evidence'])
    assert sha(poolitem['preserved_development_evidence'])==poolitem['preserved_development_evidence_sha256']
    newroot=state['native_app_music']['development_observations']['general_MainMenu_root_entry_after_pool_clock_development']
    dispatch=state['native_app_music']['development_observations']['dispatcher_backend_and_owner_development']
    for item in [newroot,dispatch]:
        for key in ['terminal_metadata','development_evidence','preserved_development_evidence','static_evidence']:
            assert sha(item[key])==item[key+'_sha256'],key
    guistatic=read(newroot['static_evidence']);waitstatic=read(dispatch['static_evidence'])
    for proof in [guistatic,waitstatic]:
        for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    guiindex=read(dispatch['prior_GUI_development_evidence']);dispatcherindex=read(dispatch['preserved_development_evidence'])
    assert sha(dispatch['prior_GUI_development_evidence'])==dispatch['prior_GUI_development_evidence_sha256']
    for index in [clockindex,guiindex,dispatcherindex]:
        for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
        for row in index['runs']:
            doc=read(row['metadata']);assert sha(row['metadata'])==row['metadata_sha256']
            for key in ['source','VM_source','probe','proof']:
                if key in doc and key+'_sha256' in doc:assert sha(doc[key])==doc[key+'_sha256']
    rootprobe=read(newroot['development_evidence']);dispatchprobe=read(dispatch['development_evidence'])
    dispatchmeta=read(dispatch['terminal_metadata'])
    native=pool['original_pool_runs'];waits=pool['scoped_lower_wait_failures']
    checks.update({
        'fresh_prior15_scope91_findings33_suites_and_current_user_return_preserved':latestprior['all_passed']and
            len(latestprior['scope_checks'])==15 and latestprior['state_sha256']==latestprevious['state']['sha256']and
            len(latestbefore['native_app_music']['static_findings'])==91 and len(findings)==93 and
            state['attended_testing']['user_present']and not state['user_resting']and not task['user_away'],
        'five_complete_pool_controls98_sources_native_u32_clock_plus1000_no_successful_audio':pool['all_passed']and
            pool['case_count']==len(pool['cases'])==5 and len(pool['source_sha256'])==98 and all(c['passed']for c in pool['cases'])and
            len(native)==len(waits)==6 and [n['clock_result']for n in native]==[0,20,180,4294966784,20,40]and
            [n['native_calculated_argument']for n in native]==[1000,1020,1180,488,1020,1040]and
            all(n['scanned_indices']==list(range(7))and n['original_pool_index']==255 and n['fixture_mutex_count_after']==0 and
                n['native_failure_branch_and_unlock_executed']and not n['host_supplied_final_pool_index']for n in native)and
            all(w['caller']=='0x3b4c14'and w['condition']=='0x35e0308'and w['mutex']=='0x35e02f0'and
                w['native_wait_argument']==((w['original_clock_result']+1000)&0xffffffff)and
                w['fixture_mutex_count_before']==1 and w['explicit_lower_wait_failure']==1 and
                not w['host_changed_wait_argument']and not w['real_kernel_condition_owner_or_wait_schedule_verified']for w in waits)and
            pool['original_voice_RAM_and40_exports_unchanged']and pool['no_GUI_initialized_data_changes']and
            pool['descriptor_guards_and_raw_DB_backup_unchanged']and pool['snapshot']['stock_and_loaded_code_unchanged']and
            pool['snapshot']['all_allocation_guards_intact']and not pool['snapshot']['audio_API_boundary_requests']and
            not pool['controller_root_foreground_device_App_audio_and_kernel_scheduling_verified']and not pool['device_io']and not pool['sounds_emitted'],
        'controller15754_root_entry_missing_native_Cpp_mutex_not_completed_registration':
            [r['session_id']for r in clockindex['runs']]==[31358,15754]and
            [r['terminal_exit_code']for r in clockindex['runs']]==[0,1]and
            [r['full_scoped_final_guards_passed']for r in clockindex['runs']]==[True,False]and
            any(e['entry']=='0x38e696'and e['caller']=='0x4053d6'for e in rootprobe['original_main_entries'])and
            rootprobe['registers']['pc']=='0x351bda'and rootprobe['registers']['r0']=='0x34a59a8'and
            rootprobe['registers']['r2']=='0x0'and not rootprobe['completed']and not rootprobe['full_scoped_final_guards_passed']and
            newroot['missing_object_is_Cpp_mutex_not_tree_or_GUI_data_map']and
            guistatic['complete_bounded_CFG_count']==len(guistatic['functions'])==11 and
            guistatic['original_mutex_vtable']=='0xc1b5dc'and guistatic['original_virtual_lock']=='0x310400'and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in guistatic['functions'].values()),
        'failed_six_dispatcher_controls78_native_initializers_and_six_owner_CFGs_preserved':
            [r['session_id']for r in guiindex['runs']]==[None,43341,63895,80358]and
            all(not r['full_scoped_final_guards_passed']for r in guiindex['runs'])and
            dispatcherindex['runs'][0]['session_id']==73611 and dispatcherindex['runs'][0]['terminal_exit_code']==1 and
            not dispatcherindex['runs'][0]['full_scoped_final_guards_passed']and
            dispatchmeta['planned_case_count']==6 and len(dispatchprobe['completed_cases'])==5 and not dispatchprobe['all_final_guards_passed']and
            len(dispatchprobe['backend_initializations'])==78 and all(n['original_body_executed']and
                len(n['native_zero_writes'])==6 and n['after_hex']=='00'*24 and not n['host_seeded_backend_bytes']
                for n in dispatchprobe['backend_initializations'])and
            dispatchprobe['native_fatal_entries'][-1]['arguments'][0:2]==['0x6e5d8016','0x2']and
            dispatchprobe['native_fatal_entries'][-1]['caller']=='0x3ec5ea'and
            dispatchmeta['condition_constructor_journal_marker_correction']and
            waitstatic['complete_bounded_CFG_count']==len(waitstatic['functions'])==6 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in waitstatic['functions'].values())and
            waitstatic['condition_constructor_thread_pointer_global']=='0xf090a0'and
            waitstatic['condition_constructor_thread_pointer_literal']=='0x3ec6c0'and
            waitstatic['neighbouring_literal_3EC6C4_is_error_code_not_thread_pointer']and
            not state['last_goal_turn']['latest_dispatcher_run_full_scoped_final_guards_passed']and
            state['last_goal_turn']['latest_controller_run_root_registration_reached']and
            not state['last_goal_turn']['latest_controller_run_returned']and
            '原廠首頁控制器與同步流程'in report and '六項控制完成五項'in report
    })
    ownerprevious=read('staging/native-player-mutex-owner/previous-checkpoint.json')
    ownerbefore=read(ownerprevious['state']['path']);ownerprior=read(ownerprevious['audit']['path'])
    for row in ownerprevious.values():assert sha(row['path'])==row['sha256']
    for key,value in ownerbefore['native_app_music']['static_findings'].items():assert findings[key]==value,key
    owneritem=findings['native_mutex_owner'];ownerproof=read(owneritem['evidence']);ownerstatic=read(owneritem['static_evidence'])
    assert sha(owneritem['evidence'])==owneritem['evidence_sha256']and sha(owneritem['static_evidence'])==owneritem['static_evidence_sha256']
    for doc in [ownerproof,ownerstatic]:
        for p,s in doc['source_sha256'].items():assert sha(p)==s,p
    ownerindex=read(owneritem['preserved_development_evidence'])
    assert sha(owneritem['preserved_development_evidence'])==owneritem['preserved_development_evidence_sha256']
    for p,s in ownerindex['source_artifact_sha256'].items():assert sha(p)==s,p
    for row in ownerindex['runs']:
        doc=read(row['metadata']);assert sha(row['metadata'])==row['metadata_sha256']
        for key in ['source','VM_source','proof','probe']:
            if key in doc:assert sha(doc[key])==doc[key+'_sha256']
    ownerdevelopment=state['native_app_music']['development_observations']['dispatcher_with_native_mutex_owner']
    for key in ['terminal_metadata','development_evidence','preserved_development_evidence','reacquisition_evidence']:
        assert sha(ownerdevelopment[key])==ownerdevelopment[key+'_sha256']
    ownerprobe=read(ownerdevelopment['development_evidence']);ownermeta=read(ownerdevelopment['terminal_metadata'])
    reacquire=read(ownerdevelopment['reacquisition_evidence'])
    for p,s in reacquire['source_sha256'].items():assert sha(p)==s,p
    ops=ownerproof['native_mutex_operations'];condition=ownerproof['original_condition_constructor_runs'][0]
    checks.update({
        'fresh_prior19_scope92_findings34_suites_retained_and_five_owner_controls99_dependencies':
            ownerprior['all_passed']and len(ownerprior['scope_checks'])==19 and
            ownerprior['state_sha256']==ownerprevious['state']['sha256']and len(ownerbefore['native_app_music']['static_findings'])==92 and
            ownerproof['all_passed']and ownerproof['case_count']==len(ownerproof['cases'])==5 and all(c['passed']for c in ownerproof['cases'])and
            len(ownerproof['source_sha256'])==99 and ownerstatic['complete_bounded_CFG_count']==len(ownerstatic['functions'])==5 and
            ownerstatic['complete_mixed_ARM_Thumb_function_count']==3 and ownerstatic['explicit_verified_instruction_set_transitions']==12 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in ownerstatic['functions'].values()),
        'original_owner_list_recursive_lock_unlink_condition_IRQ_LR_return_and_all_final_guards':
            len(ops)==8 and [r['operation']for r in ops]==['lock','lock','unlock','lock','unlock','unlock','lock','unlock']and
            [r['native_recursion_count']for r in ops]==[0,1,0,0,0,0,0,0]and
            all(r['native_body_returned']and r['semaphore_fields_written_by_original_only']for r in ops)and
            condition['native_constructor_returned']and condition['original_IRQ_restore_call_completed']and
            condition['original_return_branch_reached']and condition['original_mutex_lock_and_owner_store_executed']and
            ownerproof['condition_tokens'][0]['explicit_retained_bootstrap_token']==0 and
            ownerproof['condition_tokens'][0]['released_by_original_unlock_control']and
            ownerproof['fixture_thread_inventory']['bytes']==96 and
            not ownerproof['fixture_thread_inventory']['host_seeded_semaphore_owner_or_list_links']and
            ownerproof['original_thread_global_words_restored']and not ownerproof['host_seeded_semaphore_owner_fields']and
            ownerproof['original_voice_RAM_and40_exports_unchanged']and ownerproof['descriptor_guards_and_raw_DB_backup_unchanged']and
            ownerproof['no_GUI_initialized_data_changes']and ownerproof['snapshot']['stock_and_loaded_code_unchanged']and
            ownerproof['snapshot']['all_allocation_guards_intact']and not ownerproof['real_condition_wait_scheduler_dispatcher_foreground_or_device_App_verified']and
            not ownerproof['device_io']and not ownerproof['sounds_emitted'],
        'partial45010_owner_gate_passes_wait_returns_reacquire_hook_gap_and_unowned_unlock_preserved':
            [r['session_id']for r in ownerindex['runs']]==[28332,45010]and
            [r['terminal_exit_code']for r in ownerindex['runs']]==[0,1]and
            [r['full_scoped_final_guards_passed']for r in ownerindex['runs']]==[True,False]and
            ownerprobe['native_condition_waits'][0]['native_owner_gate_passed']and '0x6048d2'in ownerprobe['recent']and
            ownerprobe['native_mutex_operations'][-1]['before_words'][2]=='0x0'and
            ownerprobe['native_fatal_entries'][-1]['arguments'][:2]==['0x6e5d800b','0x2']and
            ownerprobe['native_fatal_entries'][-1]['caller']=='0x3008e0'and
            not ownerprobe['completed']and not ownerprobe['original_singleton_returned']and not ownerprobe['full_scoped_final_guards_passed']and
            ownermeta['raw_original_wait_returned_false_is_unupdated_default_not_proof_of_no_return']and
            reacquire['original_reacquire_native_caller']=='0x3ec692'and
            reacquire['current_reacquire_scope_gap_inferred_from_original_CFG_and_harness']and
            reacquire['inherited_counter_only_backend_not_native_owner_reacquisition']and
            reacquire['equal_F09090_F090A0_same_owner_fixture_not_real_wait_or_event_delivery']and
            not reacquire['successful_wait_event_scheduler_dispatcher_foreground_or_device_App_verified']and
            not state['last_goal_turn']['latest_dispatcher_run_full_scoped_final_guards_passed']and
            not ownerprobe['audio_requests']and not ownerprobe['device_io']and not ownerprobe['sounds_emitted']and
            '原廠鎖定與同步初始化已驗證'in report and '解鎖時因擁有者欄位缺失而中止'in report
    })
    failed_checks=[k for k,v in checks.items()if not v]
    if failed_checks: raise ValueError('Checkpoint failed: '+', '.join(failed_checks))
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        metadata_proof_sha256=sha(metadata_item['evidence']),constructor_proof_sha256=sha(ctor_item['evidence']),
        prior_state_snapshot_sha256=sha(previous['state']),prior_audit_snapshot_sha256=sha(previous['audit']),
        audit_script_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),current_turn_device_IO=False,
        pool_clock_proof_sha256=sha(poolitem['evidence']),
        current_prior15_state_snapshot_sha256=latestprevious['state']['sha256'],
        current_prior15_audit_snapshot_sha256=latestprevious['audit']['sha256'],
        latest_controller_development_sha256=sha(newroot['development_evidence']),
        latest_dispatcher_development_sha256=sha(dispatch['development_evidence']),
        mutex_owner_proof_sha256=sha(owneritem['evidence']),
        current_prior19_state_snapshot_sha256=ownerprevious['state']['sha256'],
        current_prior19_audit_snapshot_sha256=ownerprevious['audit']['sha256'],
        latest_native_owner_dispatcher_development_sha256=sha(ownerdevelopment['development_evidence']),
        full_scoped_general_MainMenu_constructor_final_guards_passed=True,
        full_general_MainMenu_controller_or_visible_device_App_verified=False,goal_status='active',full_goal_complete=False)
    (ROOT/'evidence/firmware-analysis/native-mutex-owner-checkpoint-audit.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),frozen_suites=len(counts)+4,metadata_groups=5,constructor_groups=3,pool_groups=5,owner_groups=5)))

if __name__=='__main__': main()
