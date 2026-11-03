#!/usr/bin/env python3
"""Audit original metadata controls and compiled-player general-menu ctor."""
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
    writers=[('0x551c7f8','0x1','0x385450'),('0x551c80c','0x1','0x385450'),('0x551c800','0x1','0x385450'),
        ('0x551c804','0xc035f8','0x26de42'),('0x551c808','0x3aaed08','0x26de6c'),
        ('0x551c804','0xc0fd70','0x344e22'),('0x551c7fc','0x1','0x385450')]
    checks={
        'fresh_prior12_scope_snapshot89_findings_preserved':prior['all_passed'] and len(prior['scope_checks'])==12 and
            prior['state_sha256']==sha(previous['state'])==previous['state_sha256'] and sha(previous['audit'])==previous['audit_sha256'] and
            len(before['native_app_music']['static_findings'])==89 and len(findings)==91,
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
        'canonical_task_public32_weighted61_details7_phases_timestamps_and_privacy':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            progress['estimate_percent']==progress['weighted_estimate_percent']==32 and
            sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32 and
            progress['phases'][4]['estimate_percent']==10 and len(progress['completed'])==61 and len(progress['phases'])==7 and
            '<progress id="research-progress" max="100" value="32"'in report and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            '播放器已接入原廠首頁初始化'in report and '頁面目前仍是隱藏、零尺寸'in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report,
        'asleep_offline_no_device_sound_install_music_mic_WAV_rerun_or_goal_completion':state['user_resting']and task['user_away']and
            not state['attended_testing']['user_present']and state['attended_testing']['waiting_for_user_return']and state['attended_testing']['no_pending_question']and
            all(not p['device_io']and not p['sounds_emitted']for p in [metadata,ctor])and
            not state['last_goal_turn']['device_files_written']and not state['last_goal_turn']['automatic_calls_or_sound']and
            not state['native_app_music']['native_app_running']and not state['native_app_music']['direct_phone_music_verified']and
            state['microphone_amplifier']['status']=='cancelled_by_user'and state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized']and
            state['last_goal_turn']['goal_status']=='active'and not state['last_goal_turn']['full_goal_complete']and
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests']}
    failed_checks=[k for k,v in checks.items()if not v]
    if failed_checks: raise ValueError('Checkpoint failed: '+', '.join(failed_checks))
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        metadata_proof_sha256=sha(metadata_item['evidence']),constructor_proof_sha256=sha(ctor_item['evidence']),
        prior_state_snapshot_sha256=sha(previous['state']),prior_audit_snapshot_sha256=sha(previous['audit']),
        audit_script_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),current_turn_device_IO=False,
        full_scoped_general_MainMenu_constructor_final_guards_passed=True,
        full_general_MainMenu_controller_or_visible_device_App_verified=False,goal_status='active',full_goal_complete=False)
    (ROOT/'evidence/firmware-analysis/native-mainmenu-constructor-checkpoint-audit.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),frozen_suites=len(counts),metadata_groups=5,constructor_groups=3)))

if __name__=='__main__': main()
