#!/usr/bin/env python3
"""Verify live LAN report bytes and preserve its prior audit history."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json')
    previous=read('staging/native-player-task-mutex/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-task-mutex-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed'] and len(audit['scope_checks'])==16
    assert audit['state_sha256']==sha('evidence/deep-research-state.json') and audit['report_sha256']==sha('reports/nuvi2565RT.html')
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active' and service['SubState']=='running' and service['UnitFileState']=='enabled' and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes() and 'no-store'in cache
    report=content.decode();assert '多線研究與首頁啟動'in report and '目前還沒有能安裝到車機的整合 App'in report
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report
    history=latest['historical_offline_checkpoint_audits']
    key='prior_native_kernel_context_user_present_checkpoint'
    entry=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],state_snapshot=previous['state']['path'],
        state_snapshot_sha256=previous['state']['sha256'],fresh_revalidation_scopes=28,all_passed=True,
        reason='Fresh28-scope95-finding checkpoint retained before three authorized parallel static reviews and task-scoped mutex development; four original kernel normal-context controls remain complete.')
    if key in history:assert history[key]==entry
    else:history[key]=entry
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_kernel_context_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_task_mutex_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=True,user_explicitly_returned=True,current_physical_test_requested=False)
    prior_run=latest.get('complete_current_offline_run',{})
    latest['complete_current_offline_run']=dict(checkpoint_scope_count=16,prior_checkpoint_scope_count=28,
        checkpoint_all_scope_checks_passed=True,device_io=False,sounds_emitted=False,
        complete_native_kernel_controls=prior_run.get('complete_native_kernel_controls'),
        parallel_static_analyses=dict(task_mutex_CFGs=30,mode_transitions=37,literal_tails=4,GUI_worker_CFGs=25,
            auxiliary_wrapper_CFGs=7,existing_suites_revalidated=37,unique_dependencies_revalidated=425,manifests=7,artifacts=20),
        latest_dispatcher_development_run=dict(session_id=audit['latest_development_runtime_session'],
            original_singleton_returned=audit['original_singleton_returned'],full_scoped_final_guards_passed=False),
        no_combined_UI_direct_music_device_candidate=True,general_Menu_controller_or_visible_device_App_verified=False,
        scope='Original mutex/waiter/priority and GUI notify static bounds are verified. Per-running-TCB runtime is development only; static reachability and observed entries do not prove complete wake, GUI foreground, physical kernel or safe lifecycle. UI/WAV source9 and continuous music channel8 require one-bootstrap composition. Existing four original normal event/context controls remain a separate complete proof; no new hardware test or installed App/direct phone music.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=72,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        parallel_static_partial_runtime_and_UI_music_composition_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=16,prior_scopes=28,served_exact_report=True)))

if __name__=='__main__':main()
