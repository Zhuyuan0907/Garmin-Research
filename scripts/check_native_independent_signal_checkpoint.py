#!/usr/bin/env python3
"""Audit native callback entry independently from host control semantics."""
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re,struct
from analyze_native_sections import ROOT,EXPECTED

BASE='staging/native-player-independent-signal/'
def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def hashes(doc):
    for p,s in doc['source_sha256'].items():assert sha(p)==s,p

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    snapshots=read(BASE+'previous-publication-snapshots.json')
    for row in snapshots.values():assert sha(row['snapshot'])==row['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];findings=app['static_findings']
    for k,v in before['native_app_music']['static_findings'].items():assert findings[k]==v,k
    suites=list(prior['selected_frozen_suites']);deps={}
    runtime=findings['native_independent_signal_runtime'];proof=read(runtime['evidence'])
    assert sha(runtime['evidence'])==runtime['evidence_sha256']
    suites.append(dict(path=runtime['evidence'],sha256=runtime['evidence_sha256'],case_count=proof['case_count']))
    for row in suites:
        assert sha(row['path'])==row['sha256'];p=read(row['path']);hashes(p)
        assert p['all_passed'] and p['case_count']==row['case_count']
        for q,s in p['source_sha256'].items():
            assert q not in deps or deps[q]==s,q
            deps[q]=s
    review=read(findings['direct_music_integration_review']['evidence'])['exact_hash_audit'];artifacts=0
    for row in review['manifest_records']:
        assert sha(row['path'])==row['sha256'];hashes(read(row['path']))
        for item in row['artifacts']:
            assert sha(item['path'])==item['sha256']and(ROOT/item['path']).stat().st_size==item['bytes'];artifacts+=1
    for row in review['source_references'].values():assert sha(row['path'])==row['sha256']
    keys=['native_join_cleanup_signal_static','native_mainmenu_foreground_prerequisites_static','native_ui_music_control_actor_prototype']
    for k in keys:
        row=findings[k];assert sha(row['evidence'])==row['evidence_sha256'];hashes(read(row['evidence']))
    join=read(findings[keys[0]]['evidence']);gui=read(findings[keys[1]]['evidence']);control=read(findings[keys[2]]['evidence'])
    peerpath=findings[keys[0]]['peer_evidence'];assert sha(peerpath)==findings[keys[0]]['peer_evidence_sha256'];peer=read(peerpath);hashes(peer)
    narrow=read(runtime['endpoint_scope_review']);assert sha(runtime['endpoint_scope_review'])==runtime['endpoint_scope_review_sha256']
    for p,s in narrow['inputs_sha256'].items():assert sha(p)==s,p
    meta=read(runtime['terminal_metadata']);assert sha(runtime['terminal_metadata'])==runtime['terminal_metadata_sha256']
    for k in ['source','source_snapshot','probe','complete_proof']:assert sha(meta[k])==meta[k+'_sha256']
    terminal=read(meta['probe']);assert terminal['source_sha256_before_run']==meta['source_sha256']
    for p,s in control['unchanged_frozen_source_sha256'].items():assert sha(p)==s,p
    for row in control['compile_artifacts']:assert sha(row['path'])==row['sha256']and(ROOT/row['path']).stat().st_size==row['bytes']
    protected_control=dict(deps)
    for p,s in control['source_sha256'].items():
        assert p not in protected_control or protected_control[p]==s;protected_control[p]=s
    endpoint=proof['cases'][-1]['endpoint'];inventory=endpoint['native_inventory'];timed=endpoint['timed_thread'];memory=proof['cases'][-1]['memory']
    S=int(proof['cases'][-1]['signal']['signal'],16);D=0x8800520;dispatcher=0x8804fb8
    sems={int(p,16):struct.unpack('<6I',bytes.fromhex(raw))for p,raw in endpoint['owned_semaphores'].items()}
    tasks={int(row['TCB'],16):row for row in inventory['tasks']}
    flags_ok=all(struct.unpack_from('<I',bytes.fromhex(row['raw108_hex']),24)[0]==
        ((5 if t in [0x88092b0,dispatcher]else 0)<<28)|0x0ed1a247 for t,row in tasks.items())
    classes_ok=all(bytes.fromhex(raw)[22]==0 for raw in endpoint['owned_semaphores'].values())
    idle=tasks[0x9508f90]['saved_frame13_words'];ctl=tasks[0x9503f90]['saved_frame13_words']
    progress=public['research_progress'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1]for name in ['report-updated-time','research-updated-time']]
    checks={
        'fresh20_scope101_finding_prior_checkpoint_preserved':prior['all_passed']and len(prior['scope_checks'])==20 and prior['state_sha256']==previous['state']['sha256'],
        'all101_finding_values_retained_four_new_findings':len(before['native_app_music']['static_findings'])==101 and len(findings)==105,
        '39_selected_native_suites430_exact_source_dependencies':len(suites)==39 and len(deps)==430,
        'seven_prior_manifests_twenty_artifacts_exact':len(review['manifest_records'])==7 and artifacts==20,
        'terminal66913_four_groups108_dependencies_native_original_code':meta['session_id']==66913 and meta['terminal_exit_code']==0 and
            terminal['completed']and terminal['full_scoped_final_guards_passed']and proof['all_passed']and proof['case_count']==4 and
            len(proof['source_sha256'])==108 and proof['original_MAIN_patch_bytes']==0 and not proof['host_wrote_signal_callback_ready_owner_or_saved_context'],
        'actual_original_Dispatcher_signal_adapter_to405340_before_body':proof['cases'][-1]['signal_chain'][-1]['entry']=='0x405340' and
            proof['cases'][-1]['signal_chain'][-1]['running_task']=='0x8804fb8'and
            all(a in [r['entry']for r in proof['cases'][-1]['signal_chain']]for a in ['0x52353c','0x609338','0x574760'])and
            not proof['cases'][-1]['callback_body_executed']and not proof['original_MainMenu_callback_body_foreground_device_App_direct_music_or_safe_cleanup_verified'],
        'independent80byte_original_constructor_and_typed_freefunction_holder':len(bytes.fromhex(proof['cases'][2]['signal_before']['raw80_hex']))==80 and
            not proof['cases'][2]['signal_before']['vectors'][0]['entries']and
            proof['cases'][2]['signal_registered']['vectors'][0]['entries'][0]['kind']=='free_function'and
            proof['cases'][2]['signal_registered']['vectors'][0]['entries'][0]['bytes']==8 and
            proof['cases'][2]['signal_registered']['vectors'][0]['entries'][0]['function']=='0x405341',
        'original_cleanup_member_holder_and_Thread_retained_unchanged':proof['cases'][-1]['original_cleanup_signal_and_Thread_unchanged']and
            proof['cases'][2]['retained_original_cleanup_signal']['vectors'][0]['entries'][0]['kind']=='member_function'and
            proof['cases'][2]['retained_original_cleanup_signal']['vectors'][0]['entries'][0]['bytes']==16,
        'exact_ALL_ready_state_priority_and_live_original_TCBs':inventory['all_tasks']==['0x88092b0','0x8804fb8','0x2d227c8','0x9503f90','0x9508f90']and
            inventory['ready']==['0x8804fb8','0x9508f90']and
            [tasks[t]['state']for t in [0x88092b0,dispatcher,0x2d227c8,0x9503f90,0x9508f90]]==[8,1,2,2,1],
        'live_owned_recursive_semaphore_chain_depths_and_native_tags':sems[S+56][:5]==(D+0xaec,dispatcher+32,dispatcher,0,0x46c2c8)and
            sems[S+56][5]&0xffff==1 and sems[D+0xaec][:5]==(0,S+56,dispatcher,0,0x31041c)and
            sems[D+0xaec][5]&0xffff==0 and sems[0x8805290][4]==0x6048e8,
        'serialized_native_TCB_magic_flags_and_semaphore_class_bytes_consistent':flags_ok and classes_ok,
        'active_frame_RAII_and_queue_consume_guard_not_stale_Dispatcher_context':endpoint['active_Dispatcher_SP']=='0x8804f78'and
            endpoint['active_Dispatcher_LR']=='0x60935d'and endpoint['actual_queue_record']==[hex(S),0]and
            endpoint['queue_event2_consumed']and endpoint['active_Dispatcher_old_saved_frame_is_consumed_not_resumable'],
        'actual_live_timed_Thread_node_preserved_with_type_BYTE2':timed['node']=='0x8809264'and timed['type_byte']==2 and
            struct.unpack('<5I',bytes.fromhex(timed['raw20_hex']))[:3]==(0,0x88092b0,1)and timed['current_clock']==0 and not timed['physical_timer_IRQ_verified'],
        'suspended_controller_WAIT_and_idle_POST_frames_live_serialized':idle[1]=='0x2fd016'and idle[11:]==['0x9508f88','0x10001']and
            ctl[1]=='0x2fd0ac'and ctl[11:]==['0x9503f88','0x10001']and not endpoint['safe_cleanup_or_task_exit_verified'],
        'full_code_voice_private_API_GUI_DB_storage_descriptor_stack_guards':memory['original_voice_RAM_and40_exports_unchanged']and
            memory['whole_RX_extension_code_unchanged']and memory['all_allocation_storage_descriptor_and_stack_boundaries_intact']and
            memory['backup_and_inmemory_DB_unchanged']and not memory['guest_memory_or_counters_rewritten_by_guard']and
            proof['full_scoped_memory_and_native_callback_endpoint_inventory_guards_passed'],
        'join19_CFG_plus8_peer_CFG_static_original_wait_not_fake_exit':join['assertions_passed']and
            join['complete_bounded_new_local_CFG_count']==len(join['functions'])==19 and peer['static_CFG_count']==8 and
            not join['new_emulation_executed']and not peer['new_runtime_execution'],
        'twenty_bounded_MainMenu_prerequisite_CFGs_static_only':gui['assertions_passed']and
            gui['complete_bounded_new_local_CFG_count']==len(gui['functions'])==20 and not gui['new_emulation_executed']and
            not gui['install_candidate'],
        'ARM_relocatable_component_3805text_zero_undefined_no_loader_image':control['all_passed']and control['ARM_ELF_machine']=='ARM'and
            control['ARM_ELF_type']=='REL'and not control['ARM_unresolved_symbols']and '3805'in control['ARM_ELF_size']and
            not control['ARM_ELF_is_executable_loader_image']and not control['Linux_runtime_or_dynamic_loader_required'],
        '27_host_control_groups_with_ASan_UBSan_and135_old_dependencies_unchanged':control['host_tests']['all_passed']and
            control['host_tests']['case_count']==len(control['host_tests']['cases'])==27 and
            control['unchanged_frozen_dependency_count']==135 and not control['host_test_execution']['stderr']and
            control['host_sanitizers']==['AddressSanitizer','UndefinedBehaviorSanitizer'],
        'host_tests_include_real_restore_preemption_admission_lifetime_stale_completion':all(name in [r['name']for r in control['host_tests']['cases']]for name in
            ['rejected_start_snapshot_survives_restore_preemption','stop_wins_over_synchronous_prepare_return',
            'callback_arriving_during_observation_blocks_done','cancel_zero_is_not_completion','event17_F1_admission_closed_until_explicit_restart',
            'WAV9_requires_native_clear_and_denies_phone_admission','stale_generation_cookie_route_and_token']),
        'host_actor_prototype_never_native_audio_IRQ_GUI_or_integrated_App_claim':not control['old_build_linked']and
            not control['native_firmware_instructions_executed']and not control['native_IRQ_scheduler_mutex_audio_or_GUI_runtime_verified']and
            not control['physical_App_direct_phone_or_stop_mute_verified']and not control['device_install_candidate'],
        '435_exact_native_and_control_source_dependencies_protected':len(protected_control)==435 and len(control['source_sha256'])==5,
        'canonical_task_public_active_goal_and_user_presence_consistent':public['deep_research']==state and all(task[k]==state[k]for k in
            ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'])and
            not state['user_resting']and not task['user_away']and state['attended_testing']['user_present']and
            state['last_goal_turn']['goal_status']=='active'and not state['last_goal_turn']['full_goal_complete'],
        '32_weighted_percent79_details_seven_phases_App10_time_and_bar_consistent':progress['estimate_percent']==progress['weighted_estimate_percent']==32 and
            len(progress['completed'])==79 and len(progress['phases'])==7 and progress['phases'][4]['estimate_percent']==10 and
            sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32 and not progress['goal_completed']and
            times[0]==times[1]and 'value="32"'in report,
        'report_explicit_callback_body_and_host_prototype_limits_no_private_IDs':all(t in report for t in
            ['原廠菜單回呼與播放控制器','停止點在函式主體之前','二十七組主機控制測試通過','目前還沒有能安裝到車機的整合 App'])and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'no_foreground_native_device_App_direct_phone_music_or_safe_cleanup_claim':not app['native_app_running']and
            not app['menu_icon_visible_on_device']and not app['direct_phone_music_verified']and
            not runtime['foreground_device_App_direct_phone_music_or_safe_cleanup_verified']and
            not findings['native_ui_music_control_actor_prototype']['existing_native_source_worker_GUI_radio_or_audio_integrated'],
        'three_branches_user_authorized_round_completed':state['parallel_research']['user_explicitly_authorized']and
            state['parallel_research']['agent_count']==3 and state['parallel_research']['continued_round_completed'],
        'this_turn_no_device_IO_sound_install_or_firmware_mutation':not proof['device_io']and not proof['sounds_emitted']and
            not control['device_service_IO']and not control['sounds_emitted']and not gui['firmware_modified']and
            not state['last_goal_turn']['device_io']and not state['last_goal_turn']['native_firmware_or_research_package_written'],
    }
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),task_sha256=sha('evidence/task-state.json'),
        public_sha256=sha('reports/findings.json'),report_sha256=sha('reports/nuvi2565RT.html'),MAIN_sha256=EXPECTED,
        audit_script_sha256=sha('scripts/check_native_independent_signal_checkpoint.py'),publisher_script_sha256=sha('scripts/publish_native_independent_signal_state.py'),
        prior_checkpoint=previous,selected_frozen_suites=suites,existing_frozen_suites=39,unique_exact_dependencies=430,
        protected_native_and_control_source_dependencies=435,host_control_groups=27,new_complete_full_runtime_proofs=1,
        latest_native_callback_runtime_session=66913,full_scoped_callback_entry_guards_passed=True,callback_body_executed=False,
        physical_foreground_device_App_direct_phone_music_or_safe_cleanup_verified=False,goal_status='active',device_io=False,sounds_emitted=False)
    path='evidence/firmware-analysis/native-independent-signal-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),prior_scopes=20,native_suites=39,native_exact_dependencies=430,
        protected_native_and_control_dependencies=435,host_groups=27,estimate_percent=32,findings=105)))

if __name__=='__main__':main()
