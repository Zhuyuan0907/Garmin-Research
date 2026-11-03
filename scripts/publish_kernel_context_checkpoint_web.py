#!/usr/bin/env python3
"""Verify live LAN report for original kernel context controls and partial GUI worker integration."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-kernel-context/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-kernel-context-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed']and len(audit['scope_checks'])==28
    assert audit['state_sha256']==sha('evidence/deep-research-state.json')and audit['report_sha256']==sha('reports/nuvi2565RT.html')
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode();assert '原廠事件傳送與執行緒切換'in report and '四組完整原廠事件與切換控制通過'in report
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and'REDACTED_PRIVATE_ID'not in report
    key='prior_native_dispatcher_reacquire_user_present_checkpoint';history=latest['historical_offline_checkpoint_audits']
    expected=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],
        state_snapshot=previous['state']['path'],state_snapshot_sha256=previous['state']['sha256'],
        fresh_revalidation_scopes=25,all_passed=True,
        reason='Fresh25-scope memory controls/distinct timer boundary checkpoint retained before four unpatched kernel event-context controls4812 and partial GUI worker entry35440.')
    if key in history:assert history[key]==expected
    else:history[key]=expected
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_dispatcher_reacquire_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_kernel_context_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=True,
        user_explicitly_returned=True,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_scope_count=28,checkpoint_all_scope_checks_passed=True,
        device_io=False,sounds_emitted=False,general_Menu_controller_or_visible_device_App_verified=False,
        complete_native_kernel_controls=dict(session_id=4812,exit_code=0,case_count=4,source_artifact_count=103,all_scoped_final_guards_passed=True,
            original_MAIN_patch_bytes=0,native_saved_resume_destinations_reached=4,zero_event_no_wake_control=True,
            initial_CPU_mode_ready_membership_and_boot_event_are_fixtures=True,
            original_idle_post_continuation_and_tasks_module_remain_resident=True),
        earlier_complete_dispatcher_memory_controls=dict(session_id=6649,exit_code=0,case_count=6,source_artifact_count=102,all_scoped_final_guards_passed=True,
            same_fictional_current_and_constructor_owner=True,lower_wait_recursive_immediate_return=True,resident_condition_recursion=1,real_blocking_wakeup_and_event_delivery_verified=False),
        earlier_complete_mutex_owner_controls=dict(session_id=28332,exit_code=0,case_count=5,source_artifact_count=99,all_scoped_final_guards_passed=True),
        original_mutex_static=dict(complete_CFGs=5,mixed_ARM_Thumb_functions=3,mode_transitions=12),
        latest_dispatcher_development_run=dict(session_id=35440,exit_code=1,original_additional_GUI_TCBs=2,
            native_task_list_insertions=5,native_task_list_writer='0x358cd2',
            original_GUI_worker='0x8804fb8',original_GUI_worker_entry='0x5d215c',native_resume_destination_reached=True,
            rejected_next_lock_entry='0x3009a0',Cpp_mutex='0x34a59ac',old_single_thread_owner='0x9503f90',
            rejection_is_inherited_single_thread_scope_not_native_fatal=True,original_singleton_returned=False,
            full_scoped_final_guards_passed=False),
        original_context_static=dict(complete_bounded_normal_CFGs=5,interworking_transitions=17),
        native_timer_static=dict(complete_CFGs=5,reused_timer_routes=2,reused_exact_dependencies=25),
        earlier_complete_pool_clock_controls=dict(session_id=31358,exit_code=0,case_count=5,source_artifact_count=98,all_scoped_final_guards_passed=True),
        earlier_general_Menu_constructor=dict(session_id=70973,exit_code=0,case_count=3,source_artifact_count=101,all_scoped_final_guards_passed=True),
        scope='Four native normal event/context controls103 dependencies execute unchanged MAIN2FCF44/2FD034/358EC4, including boot timer preemption/return, zero-event no-wake, controller blocking and event1 resume. Native saved destinations reached without Python CPU context restore. Initial CPU mode, ready membership, native-built synthetic controller/idle descriptors/stacks and explicit boot event remain inputs. Idle post continuation/tasks/module stay resident. GUI integration35440 constructs two extra native tasks and enters worker5D215C; inherited single-current-controller C++mutex scope rejects worker request3009A0 before lock body, no singleton return or final guards. Need task-scoped ownership/contention/waiter wake and real GUI producer/boot, no foreground/device App/direct audio/accepted loading or safe lifetime proof.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=69,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        complete_original_kernel_context_and_partial_GUI_task_scope_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=28,kernel_groups=4,served_exact_report=True)))

if __name__=='__main__':main()
