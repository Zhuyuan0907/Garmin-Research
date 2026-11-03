#!/usr/bin/env python3
"""Verify exact live LAN report and preserve prior checkpoint publication."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-task-runtime-full/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-task-runtime-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed'] and all(audit['scope_checks'].values())
    assert audit['state_sha256']==sha('evidence/deep-research-state.json') and audit['report_sha256']==sha('reports/nuvi2565RT.html')
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes() and 'no-store'in cache
    report=content.decode();assert '背景初始化、菜單回呼與播放控制'in report
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report
    history=latest['historical_offline_checkpoint_audits'];key='prior_native_task_mutex_checkpoint'
    entry=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],state_snapshot=previous['state']['path'],
        state_snapshot_sha256=previous['state']['sha256'],fresh_revalidation_scopes=16,all_passed=True,
        reason='Fresh16-scope98-finding checkpoint retained before full native singleton task/memory proof and bounded foreground/source9 lifecycle analyses.')
    if key in history:assert history[key]==entry
    else:history[key]=entry
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_task_mutex_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_task_runtime_checkpoint=path,checkpoint_sha256={path:sha(path)},goal_status='active',full_goal_complete=False,
        no_MAC_in_report=True,user_explicitly_returned=True,current_physical_test_requested=False)
    prior_run=latest.get('complete_current_offline_run',{})
    latest['complete_current_offline_run']=dict(checkpoint_scope_count=len(audit['scope_checks']),prior_checkpoint_scope_count=16,
        checkpoint_all_scope_checks_passed=True,device_io=False,sounds_emitted=False,
        complete_native_kernel_controls=prior_run.get('complete_native_kernel_controls'),
        existing_frozen_suites_revalidated=audit['existing_frozen_suites'],unique_exact_dependencies=audit['unique_exact_dependencies'],
        complete_native_task_return_inventory_memory_groups=3,
        full_scoped_pre_background_guards_passed=True,full_scoped_background_final_guards_passed=False,
        bounded_static_analyses=dict(foreground_signal_CFGs=32,source9_lifecycle_CFGs=29),
        actual_native_signal_callback_entry_before_body_verified=audit['signal_dispatch_before_callback_body_verified'],
        no_combined_UI_direct_music_device_candidate=True,general_Menu_foreground_or_visible_device_App_verified=False,
        scope='Original singleton condition/broadcast/handoff returns and exact task/inventory/whole-memory guards pass in3 complete pre-background groups. Later original controller wait drains worker continuations to idle but is separately development evidence with no final background guards. Bounded32 signal/GUI/foreground and29 source9 lifecycle static flows inform next native callback and async stop completion tests. Signal callback entry, when proved, stops before its body. No safe task cleanup, physical GUI/IRQ, App, accepted package or phone direct music.')
    progress=read('reports/findings.json')['research_progress']
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=len(progress['completed']),
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        full_pre_background_partial_background_and_static_lifecycle_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=len(audit['scope_checks']),prior_scopes=16,served_exact_report=True)))

if __name__=='__main__':main()
