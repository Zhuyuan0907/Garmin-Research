#!/usr/bin/env python3
"""Verify live LAN report for scoped memory controls and partial native timer context work."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-reacquire/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-dispatcher-reacquire-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed']and len(audit['scope_checks'])==25
    assert audit['state_sha256']==sha('evidence/deep-research-state.json')and audit['report_sha256']==sha('reports/nuvi2565RT.html')
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode();assert '事件物件建立與原廠計時器依賴'in report and '六組事件物件記憶體建立控制全數通過'in report
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and'REDACTED_PRIVATE_ID'not in report
    key='prior_native_mutex_owner_user_present_checkpoint';history=latest['historical_offline_checkpoint_audits']
    expected=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],
        state_snapshot=previous['state']['path'],state_snapshot_sha256=previous['state']['sha256'],
        fresh_revalidation_scopes=22,all_passed=True,
        reason='Fresh22-scope owner/partial dispatcher checkpoint retained before six memory-construction controls6649 and distinct native timer context boundary80740.')
    if key in history:assert history[key]==expected
    else:history[key]=expected
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_mutex_owner_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_dispatcher_reacquire_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=True,
        user_explicitly_returned=True,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_scope_count=25,checkpoint_all_scope_checks_passed=True,
        device_io=False,sounds_emitted=False,general_Menu_controller_or_visible_device_App_verified=False,
        complete_dispatcher_memory_controls=dict(session_id=6649,exit_code=0,case_count=6,source_artifact_count=102,all_scoped_final_guards_passed=True,
            same_fictional_current_and_constructor_owner=True,lower_wait_recursive_immediate_return=True,resident_condition_recursion=1,real_blocking_wakeup_and_event_delivery_verified=False),
        earlier_complete_mutex_owner_controls=dict(session_id=28332,exit_code=0,case_count=5,source_artifact_count=99,all_scoped_final_guards_passed=True),
        original_mutex_static=dict(complete_CFGs=5,mixed_ARM_Thumb_functions=3,mode_transitions=12),
        latest_dispatcher_development_run=dict(session_id=80740,exit_code=1,original_timer_builder='0x358bf8',
            original_timer_TCB='0x2d227c8',distinct_from_current_fixture=True,native_condition_transfer_to_timer=True,
            context_restore_boundary='0x358ec4',original_context_restore_executed=False,
            original_wait_returned=False,original_singleton_returned=False,full_scoped_final_guards_passed=False,
            inherited_raw_same_owner_literal_not_authoritative=True,real_event_delivery_verified=False),
        native_timer_static=dict(complete_CFGs=5,reused_timer_routes=2,reused_exact_dependencies=25),
        earlier_complete_pool_clock_controls=dict(session_id=31358,exit_code=0,case_count=5,source_artifact_count=98,all_scoped_final_guards_passed=True),
        earlier_general_Menu_constructor=dict(session_id=70973,exit_code=0,case_count=3,source_artifact_count=101,all_scoped_final_guards_passed=True),
        scope='Six original memory-construction controls102 dependencies execute release300BB8 and reacquire3009A0 caller3EC692, bootstrap and singleton/cached lookup with full guards. Equal fictional current/constructor owner makes lower wait recursive immediate, retaining condition token and native recursion1. New80740 uses original timer descriptor/builder and distinct owner transfer, then reaches358EC4 context boundary before restoration, without wait/singleton return or final guards. Original wake remains fixture; actual events, task schedule, foreground/device App/direct phone audio/accepted loading/safe lifetime remain unverified.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=67,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        complete_memory_controls_and_distinct_native_timer_context_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=25,memory_groups=6,served_exact_report=True)))

if __name__=='__main__':main()
